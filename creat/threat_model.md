# UTL Threat Model & Security Invariants

This document describes the threat model, trust boundaries, and
security invariants for the Universal Truth Layer (UTL) v1.0.

It is meant to be read together with `creat/hardening_plan.md`.

---

## 1. Scope & Assets

UTL is an append-only truth layer for:

- **State-of-Truth roots (SoT roots)**: identifiers and root hashes that
  represent canonical states (e.g., models, configs, datasets).
- **TATA frames & transitions**: per-event records that tie inputs,
  outputs, and metadata to a specific SoT root.
- **`.dig` files**: append-only, Merkle-backed forensic logs of
  transitions.
- **Entropy bins**: summaries of distributional behaviour over time.
- **Proof artifacts**:
  - Distillium micro-proofs (arkworks-based commitments).
  - zkSNARK proofs (Groth16) where enabled.

The main **attack surface** is:

- Calls into `utld` (Unix socket or via `utl_http`).
- File operations on `.dig` directories.
- Policy definitions (TruthScript JSON).
- SDK entrypoints in Rust, TS/Node, and Python.

---

## 2. Attacker Capabilities (Assumptions)

UTL v1.0 is designed under these assumptions:

- The attacker **may**:
  - Control one or more **applications** using the SDKs.
  - Send arbitrary JSON to the HTTP gateway.
  - Attempt to replay or forge transitions.
  - Read `.dig` files where they have OS-level read access.
- The attacker **does not**:
  - Have root-level control of the host running `utld` (if that is
    compromised, all bets are off).
  - Have arbitrary write access to `.dig` storage outside of UTL itself.
  - Control the HMAC keys used for transition signatures and `.dig`
    signing.

Future v1.1+ work will tighten assumptions around multi-tenancy and
stronger isolation (namespace-per-tenant, mTLS, etc.).

---

## 3. Trust Boundaries

### 3.1 utld daemon

- Trusted to:
  - Validate and record transitions.
  - Compute TATA frames, `.dig` contents, entropy bins, and proofs.
  - Enforce TruthScript policies.
- Exposed via:
  - Unix domain socket (local only, typically root- or service-owned).

### 3.2 HTTP gateway (utl_http)

- Trusted to:
  - Authenticate external clients via `UTLD_API_TOKEN`.
  - Perform basic request validation (JSON shape, hashes, etc.).
- Exposed via TCP (default `127.0.0.1:8080`), suitable for local sidecars
  or API gateways in front.

### 3.3 Storage

- `.dig` directory (`UTLD_DIG_DIR`) is considered **append-only** from
  the perspective of UTL.
- UTL writes `.dig` atomically and can optionally emit `.sig` HMAC
  signatures to detect tampering.

### 3.4 SDKs and Clients

- SDKs are **untrusted** as far as content, but may carry valid
  signatures.
- The UTL core relies on `UTLD_SIG_KEY` for authenticity of
  `RecordTransition` requests.

---

## 4. Security Invariants (v1.0)

UTL aims to uphold the following invariants when configured with HMAC
keys and policies:

1. **No undetected tampering of sealed `.dig` files**
   - Each `.dig` file is written atomically.
   - If `UTLD_DIG_SIGN_KEY` is set, an HMAC-SHA256 signature over its
     JSON content is emitted as `<file>.sig`.
   - Any modification of `.dig` contents can be detected by re-verifying
     signatures.

2. **No acceptance of forged transitions when `UTLD_SIG_KEY` is set**
   - `utld` verifies a `Sig` on `RecordTransition` using HMAC-SHA256
     over `{entity_id, root_id, addr_heap_hash, hook_hash, data}`.
   - If verification fails, the transition is rejected and an
     `invalid_signature_for_root` error is returned.

3. **Policy enforcement is fail-closed for denies**
   - If a TruthScript rule emits `Deny`, the associated transition is
     not recorded.
   - Any policy-engine error returns a clear error to the client and
     does not silently weaken enforcement.

4. **Atomicity of `.dig` sealing**
   - A `.dig` file is either fully written or not present.
   - Crashes during writing only leave behind temporary `.tmp` files,
     which can be safely ignored or cleaned.

5. **No silent failure on critical operations**
   - Errors during `.dig` sealing or transition processing surface as
     structured error messages (`NodeResponse::Error`) to clients and as
     logs to operators.

---

## 5. Out-of-Scope Attacks (v1.0)

The following are explicitly out of scope for v1.0:

- Host-level compromise of the machine running `utld` (root-level
  attacker can bypass all guarantees).
- Physical attacks on disks that are not mitigated by OS-level
  encryption and access control.
- Side-channel attacks against cryptographic primitives
  (arkworks/HMAC/SHA2 are assumed secure).
- Attacks on application code that happens *before* it calls into UTL
  (e.g., bad business logic, prompt injection, data poisoning).

UTL is **not** a full remote attestation or TEEs system; it is designed
as an auditable, append-only truth layer that can be composed with those
systems.

---

## 6. Future Hardening Directions

Planned for v1.1+:

- **Tenant isolation:** explicit tenant IDs and separated storage and
  metrics per tenant.
- **Stronger authN/Z:** mTLS between gateways and utld, per-tenant
  tokens and roles.
- **Advanced SNARK circuits:** proofs for `.dig` inclusion and
  higher-level invariants (e.g., accounting constraints).
- **Better observability:** metrics and dashboards for anomaly detection
  and proof failures.
