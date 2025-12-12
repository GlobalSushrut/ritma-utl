# Ritma Safety Pack (Minimum CISO Docs)

This pack is the **minimum set of answers** a hard CISO needs before committing to a paid pilot.

---

## 1. Architecture & Data Flows

### 1.1 Where Ritma runs
- **Deployment model (pilot):**
  - Ritma runs as a **sidecar node** alongside your existing services.
  - It does **not** sit inline on critical request paths; it observes and mirrors events.
- **Components used in the demo:**
  - `utld` daemon (node-local Universal Truth Layer).
  - `utl_cli` (CLI client and reporting tools).
  - `dig_index.sqlite` (local dig index database).
  - `decision_events.jsonl` (append-only JSONL decision log).
  - `compliance_index.jsonl` (hash-chained compliance records).

### 1.2 What Ritma sees
- **Inputs (observed):**
  - Policy evaluation metadata (tenant ID, src/dst DIDs, zones, event kind, decision, actions).
  - Transition events and high-level access decisions (allow/deny, actions, rule IDs).
  - Compliance evaluation outputs (which controls passed/failed, at what time).
- **What Ritma does *not* need to see:**
  - Full payload contents (e.g., PII, PHI, transaction bodies) can be **redacted or hashed at the source**.
  - Ritma works on structured metadata and cryptographic digests.

### 1.3 What Ritma stores
- **At rest (default demo config):**
  - `dig_index.sqlite` – metadata about dig files:
    - File IDs, time ranges, Merkle roots, policy decisions, tenant IDs.
    - Paths to dig files (if present) for deeper forensics.
  - `decision_events.jsonl` – hash-chained decision events:
    - One JSON per event, including policy name/version, decision, actions, DIDs.
  - `compliance_index.jsonl` – hash-chained compliance control evaluations.
  - `usage_events.jsonl` (optional) – metering / SLO-like usage events.
  - Evidence packages (JSON manifests, optional ZIPs) exported on demand.

All of these are **node-local** for the pilot; nothing is sent to Ritma SaaS by default.

### 1.4 Multi-tenant story
- **Tenant isolation:**
  - All primary records carry a `tenant_id` field (e.g., `"acme"`).
  - Dig index queries, evidence packages, and compliance reports are **scoped per tenant**.
- **Storage separation options:**
  - Pilot: single `dig_index.sqlite` + per-tenant filters.
  - Production: either per-tenant DBs or strong tenant partitioning (separate files / schemas).
- **Operator access:**
  - Operators see tenants **only through configured roles / CLI queries**.
  - Evidence packages can be generated per tenant and handed to that tenant’s security team only.

### 1.5 Data at rest / in transit & keys
- **In transit (pilot demo):**
  - Node-local connections (Unix socket `/tmp/utld.sock`).
  - For remote node deployments, TLS termination is supported (Rustls-based) and recommended.
- **At rest:**
  - SQLite DBs and JSONL logs are stored on the host’s disk.
  - For pilots, we recommend:
    - OS-level disk encryption (e.g., LUKS, BitLocker).
    - Restricted file permissions / container volumes.
- **Key management basics:**
  - Signing keys for evidence packages are provided via env (`UTLD_PACKAGE_SIG_KEY` / keystore).
  - Verification keys via env (`UTLD_PACKAGE_VERIFY_KEY`) or embedded pubkeys (for ed25519).
  - In production, these would be sourced from a KMS/secret store (e.g., Vault, AWS KMS) rather than plain env.

---

## 2. Threat Model & Trust Boundaries

### 2.1 High-level trust model
- Ritma **assumes**:
  - The host OS and basic platform controls (IAM, disk encryption) are in place.
  - The app that emits events is correctly classifying sensitive fields.
- Ritma **provides**:
  - Immutable, hash-chained logs for policy decisions and compliance.
  - Verifiable evidence packages for auditors.
  - Truth snapshots that capture “state at time T”.

### 2.2 If a Ritma node is compromised
- **What an attacker can see:**
  - Whatever is in the node’s local logs and DBs (decision events, compliance records, dig index metadata, evidence manifests).
- **What an attacker cannot change silently:**
  - Previously issued logs and evidence:
    - JSONL logs and compliance index are hash-chained.
    - Evidence packages contain their own Merkle/chain heads and package hash.
  - Any tampering breaks **hash verification and chain continuity**.
- **Mitigations / blast radius controls:**
  - Rotate signing keys; old packages can be verified independently.
  - Rebuild dig index / compliance index from upstream sources.
  - Use least-privilege on the node (no write access to app data stores).

### 2.3 If the dig index DB is corrupted
- **Failure mode:**
  - Queries for evidence and time ranges may return incomplete or empty results.
- **Detection:**
  - Periodic verification of dig index chain heads (via `truth-snapshot-verify`).
  - Evidence package export will either fail clearly or produce fewer artifacts than expected.
- **Recovery:**
  - Rebuild `dig_index.sqlite` from original log sources / dig files.
  - Compare rebuilt hash heads to truth snapshots / prior evidence packages.

### 2.4 If a signing key leaks
- **What an attacker gains:**
  - Ability to produce **new** evidence packages that appear signed by the node.
- **What they cannot do undetected:**
  - Retroactively change already-published packages without updating their hashes.
  - Change historical JSONL / compliance logs without breaking hash-chains and snapshots.
- **Mitigations:**
  - Key rotation: issue a new signing key, mark old key as compromised.
  - Maintain a registry of trusted signer IDs / key IDs.
  - Use KMS-backed keys with audit logs and short-lived credentials.

### 2.5 Detecting / limiting blast radius
- **Detection:**
  - Hash verification of evidence packages.
  - Chain head verification of decision and compliance logs.
  - Comparison against external ground truth (original app logs, SIEM).
- **Limiting blast radius:**
  - Treat Ritma as an **evidence engine**, not an inline gate, for pilots.
  - Use separate nodes per environment / high-sensitivity tenant.
  - Lock down access to signing keys; enforce HSM/KMS where possible.

---

## 3. Failure Modes & Operational Story

### 3.1 If Ritma is down (pilot mode)
- **Does it break production?**
  - **No.** For pilots, Ritma is configured as a **sidecar / mirror-only component**.
  - Your primary app and auth stack keep running; they do not depend on Ritma for allow/deny.
- **What you lose while it’s down:**
  - Incremental security/compliance evidence:
    - New decision events may not be logged.
    - New truth snapshots / compliance evaluations may not be emitted.
  - Existing logs and evidence packages remain intact and verifiable.
- **What remains working:**
  - Any previously exported evidence packages.
  - Hash-chains in JSONL logs / compliance index.
  - External logs and SIEM data (your existing sources of truth).

### 3.2 If logs are lost vs. Ritma is down
- **Ritma down, logs intact:**
  - You have a **gap in new events**, but prior history is preserved and verifiable.
- **Ritma up, but upstream log source fails:**
  - Ritma will log fewer events or fail clearly when exporting evidence.
  - This is detectable via drift between:
    - App/SIEM logs.
    - Ritma dig index / decision logs.

### 3.3 Summary for a CISO
- Ritma is **non-inline** in pilot: it cannot break production traffic.
- If Ritma fails, you **lose incremental evidence**, not your core logs or availability.
- All historical evidence and logs are **cryptographically protected**:
  - Hash-chains detect tampering.
  - Evidence packages expose mismatches on verification.
- The node can be rebuilt or rotated without losing the ability to verify old evidence.

---

**Next steps (for a strict CISO):**
- Configure signing keys via KMS/secret manager instead of raw env.
- Decide which fields are fully logged vs. hashed/redacted.
- Define operational runbooks for:
  - Node compromise.
  - Key rotation and revocation.
  - Rebuilding dig index from upstream sources.
