# Ritma Transparency Log + Forensics “One‑Minute Page” (Industry-Standard Design)

## Status
Draft.

## Goal
Define an **industry-standard**, **tamper-evident**, **operator-friendly** architecture for Ritma such that for each namespace and each 60s window you can produce a single forensic “page” that:

- **Reflects exactly what the sensor recorded** (the window’s `TraceEvent`s)
- Includes BAR outputs (features, graph, ML, verdict, snapshot manifest)
- Is **sealed** into an append-only transparency ledger (RTSL)
- Can be exported into a **portable proofpack** (human-usable forensic bundle)
- Supports **retention/pruning** of hot storage without losing auditability

## Scope
- Linux runtime capture (`tracer_sidecar`)
- Storage (`index_db.sqlite`) as hot/cold path
- Window processing and sealing (`bar_orchestrator` + `ritma_contract`)
- Ledger format (`RTSL`)
- Export + verification UX (`ritma_cli`)

Not covered here: multi-tenant SaaS control plane, remote transparency gossip network, legal admissibility procedures beyond technical chain-of-custody.

---

## Industry standards to emulate (short list)

### 1) Certificate Transparency (CT): append-only Merkle logs + signed tree heads
CT defines a Merkle tree with **domain separation** for leaf vs node hashing, and uses **Signed Tree Heads (STHs)** and **consistency proofs** to detect equivocation.

- **Merkle tree + domain separation** (leaf uses `HASH(0x00 || leaf)`; node uses `HASH(0x01 || left || right)`) — RFC 9162 §2.1.1
  - https://www.rfc-editor.org/rfc/rfc9162.html
- **Signed Tree Head (STH)** (tree_size, root_hash, timestamp, signature) + consistency proof structure — RFC 9162 §4.9–4.11

Why it matters for Ritma:
- RTSL is effectively a **local transparency log** for window commitments.
- “Hour roots / chain roots” are analogous to CT tree heads.

### 2) Trillian: leaf hashing vs identity hash + store big blobs outside the log
Trillian guidance separates:
- **Merkle hash**: what is committed into the transparency log
- **Identity hash**: optional dedupe semantics

It also recommends storing large/private blobs outside the transparency log and logging only hashes.

- Leaf hashing and separate identity hash — Trillian “Transparent Logging: A Guide”
  - https://raw.githubusercontent.com/google/trillian/master/docs/TransparentLogging.md

Why it matters for Ritma:
- Don’t stuff raw `TraceEvent`s inside RTSL; store them in a **content-addressed evidence store** (or DB) and commit only canonical hashes.

### 3) Sigstore Rekor: operational transparency log + size limits + sharding
Rekor is a transparency log for signed metadata and highlights operational constraints (e.g., entry size limits, sharding).

- Rekor v1 public instance + API endpoints + size limits — Rekor README
  - https://raw.githubusercontent.com/sigstore/rekor/main/README.md

Why it matters for Ritma:
- Proofpacks / “pages” must remain reasonably sized; large artifacts should be referenced by hash.

### 4) CBOR deterministic encoding
Deterministic encodings are a standard technique to ensure canonical hashes are stable across implementations.

- Deterministic CBOR encoding requirements — RFC 8949 §4.2
  - https://www.rfc-editor.org/rfc/rfc8949.html

Why it matters for Ritma:
- `canonical_leaf_hash()` must be based on deterministic encoding.
- Proofpacks should use canonical encoding to keep hashes stable.

### 5) COSE signing
COSE provides standard signed container formats for CBOR payloads.

- COSE signing structures — RFC 9052 §4
  - https://www.rfc-editor.org/rfc/rfc9052.html

Why it matters for Ritma:
- RTSL signatures and proofpack signatures should follow consistent signing semantics.

### 6) SCITT: signed statements + receipts + transparency service model
SCITT defines a general model for signed statements registered with a transparency service, producing receipts that can be audited.

- SCITT architecture overview — draft-ietf-scitt-architecture §5
  - https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture

Why it matters for Ritma:
- A “one-minute page” can be treated as a **signed statement** (about a window) with a **receipt** (RTSL inclusion/consistency material).

### 7) NIST chain-of-custody definition
For forensic credibility, maintain chain-of-custody metadata.

- NIST definition (CSRC glossary)
  - https://csrc.nist.gov/glossary/term/chain_of_custody

Why it matters for Ritma:
- Proofpacks should include who/what produced the page, when, and under what configuration.

---

## Ritma design principles (derived from standards)

### A) Transparency log stores **commitments**, not full data
- RTSL should store:
  - time window boundaries
  - tree_size / counts
  - Merkle root of canonical leaf hashes
  - linkage to previous heads (hour root / chain root)
  - signatures

### B) Evidence/artifacts are **content-addressed** and referenced by hash
- Keep large/private artifacts in:
  - `RITMA_OUT/cases/<case_id>/...` (or another CAS)
  - or a DB/object store
- RTSL commits hashes.

### C) Deterministic canonicalization everywhere
- Leaf hash canonical tuple (already in `bar_orchestrator::canonical_leaf_hash`)
- Canonical CBOR for proofpack files

### D) Simple responder UX
A responder should be able to do:

- **Seal** continuously
- **Export one window** (by time range) into a “page/proofpack” directory
- **Verify** proofpack against RTSL (and optionally against remote witness)

---

## Target “One‑Minute Page” model

### What the page contains
For a window `[start,end]` and namespace `ns`:

1. **Trace excerpt (sensor truth)**
   - list of `TraceEvent`s in the window
   - possibly redacted (hash-only mode)

2. **BAR derived outputs**
   - window features summary
   - attack graph edges + graph hash
   - ML score + explanation
   - verdict + reasons

3. **Evidence pack manifest**
   - list of artifact blobs with `sha256` (or stronger hash)
   - privacy redactions

4. **Ledger receipt**
   - RTSL record reference (segment id / hour root / chain root)
   - signatures
   - (future) inclusion/consistency proofs

5. **Chain-of-custody metadata**
   - node_id, sensor version, config hash, signer id

### Where each part lives
- **Hot path**: `index_db.sqlite` (queryable, pruneable)
- **Transparency ledger**: RTSL (`RITMA_OUT/ledger/v2/...`) commits roots
- **Evidence store**: proofpack/case directory containing files, referenced by hash

This mirrors Trillian guidance: log the hash; store large data separately.

---

## Mapping to current Ritma code

### Capture
- `crates/tracer_sidecar` produces `common_models::TraceEvent`
- Inserts into `IndexDb::insert_trace_event_from_model()`

### Window processing + sealing
- `crates/bar_orchestrator::Orchestrator::run_window()`
  - Correlate window (features + attack graph)
  - Run ML
  - Judge
  - Snapshot (optional)
  - Seal (proof metadata + receipts)
  - Write `RITMA_OUT` via `StorageContract::write_window_output()`

### Ledger output format
- `crates/ritma_contract::StorageContract::write_window_output()`
  - `RITMA_OUT_FORMAT=legacy|rtsl|dual`
  - `RITMA_OUT_ENFORCE_RTSL=1` forces RTSL

### Proofpack export
- `crates/ritma_cli` has export functions that read IndexDB (events/features/ml/etc.) and write canonical CBOR files.

---

## Known gaps (what must change)

### 1) Snapshot must include the real trace excerpt
**Bug fixed**: `bar_orchestrator` previously called snapshotter with `&[]`. It must pass the actual `trace_events` excerpt for `[start,end]`.

### 2) Snapshotter returns only hashes/metadata, not persisted artifacts
Today snapshotter computes artifact hashes but does not write the artifact payloads into an evidence store. Industry standard practice is:
- write artifacts to a content-addressed store
- log the hashes + metadata in the manifest

### 3) Export should not require ML id
UX should allow:
- `ritma export-window --namespace ... --start ... --end ...` producing one proofpack

### 4) RTSL-only should be the default for production
If RTSL is the standard, deployments should enforce it (and optionally disallow legacy output).

### 5) Retention should be explicit and safe
Pruning `trace_events` must happen only after:
- RTSL record exists
- proofpack/evidence is exported or copied to long-term storage

---

## Recommended implementation plan (in repo)

### Phase 1 (correctness)
- Ensure `bar_orchestrator` passes real per-window `trace_excerpt` to snapshotter.
- Enforce RTSL-only in production configurations.

### Phase 2 (forensic usability)
- Add a **window export** command that generates the “one-minute page” proofpack directly from `(namespace,start,end)`.
- Include the **trace excerpt** file in the proofpack (canonical CBOR).

### Phase 3 (evidence store)
- Implement snapshot artifact persistence to an evidence store (e.g., `RITMA_OUT/cases/<case_id>/...`).
- Proofpack references should be hash-addressed.

### Phase 4 (transparency hardening)
- Add verifiable inclusion/consistency proof material for RTSL (CT-like proofs).
- Add witness/gossip support (future).

---

## Environment recommendations
For production-grade “RTSL standard” deployments:

- `RITMA_OUT_ENABLE=1`
- `RITMA_OUT_FORMAT=rtsl`
- `RITMA_OUT_ENFORCE_RTSL=1`

---

## Success criteria
- Given a window `[start,end]`, exported proofpack contains:
  - `trace_events.cbor` (what sidecar recorded)
  - `attack_graph.cbor`, `coverage.cbor`, `ml_score`, `verdict`
  - `manifest.cbor`
- Verification confirms:
  - proofpack hashes match IndexDB records
  - merkle root matches RTSL record for that window

---

## Chain-of-Custody (CoC) — Industry-Standard Requirements

This section defines Ritma's chain-of-custody architecture for **military**, **critical infrastructure**, **financial**, and **court-admissible** forensic contexts. It draws from:

- **ACPO/NPCC Good Practice Guide** (UK digital evidence principles)
- **ISO/IEC 27037:2012** — identification, collection, acquisition, preservation of digital evidence
- **ISO/IEC 27041:2015** — assuring suitability of investigative methods
- **ISO/IEC 27042:2015** — analysis and interpretation of digital evidence
- **ISO/IEC 27043:2015** — incident investigation principles and processes
- **NIST SP 800-86** — integrating forensic techniques into incident response
- **NISTIR 8387** — digital evidence preservation for evidence handlers
- **NIST SP 800-88 Rev.1** — media sanitization (secure deletion)
- **RFC 3161** — Time-Stamp Protocol (TSP) for evidence timestamping
- **IETF COSE Merkle Tree Proofs** (draft-ietf-cose-merkle-tree-proofs) — receipts for transparency logs

### CoC Principle 1: No action should change evidence

**Standard**: ACPO Principle 1 / ISO 27037 §7.1.1

**Ritma implementation**:
- `tracer_sidecar` captures events in **append-only** mode; no modification of raw events after insertion.
- `index_db` uses **hash chaining** (`event_hash`, `prev_hash`) so any tampering breaks the chain.
- RTSL commits **Merkle roots** of sealed windows; once sealed, the window's hash is immutable.

### CoC Principle 2: Competent persons access evidence with audit trail

**Standard**: ACPO Principle 2 / ISO 27037 §7.1.2 / UK MoJ POL.POP.009–011

**Ritma implementation**:
- Every custody-relevant action is logged to a **custody_log** table:
  - `CAPTURE` — sidecar inserted events
  - `SEAL` — bar_orchestrator sealed window into RTSL
  - `EXPORT` — proofpack exported
  - `PRUNE` — hot data deleted after seal
  - `VERIFY` — proofpack verified
- Each log entry includes:
  - `timestamp` (RFC 3339, ideally RFC 3161 TSA-signed)
  - `actor_id` (node_id / user / service principal)
  - `action`
  - `target` (namespace, window_id, artifact hash)
  - `prev_log_hash` (hash chain for tamper detection)
  - `signature` (optional, for high-assurance deployments)

### CoC Principle 3: Audit trail enables third-party replication

**Standard**: ACPO Principle 3 / ISO 27043 §6.3 / UK MoJ POL.POP.009

**Ritma implementation**:
- Proofpacks include:
  - `custody_log.cbor` — excerpt of custody events for that window
  - `manifest.cbor` — artifact hashes + metadata
  - `rtsl_receipt.cbor` — RTSL inclusion proof (Merkle path + signed tree head)
- A third party can:
  1. Verify `trace_events.cbor` hash matches manifest
  2. Verify manifest hash matches RTSL leaf
  3. Verify RTSL inclusion proof against signed tree head
  4. Verify custody_log hash chain is unbroken

### CoC Principle 4: Investigation leader ensures legal compliance

**Standard**: ACPO Principle 4 / ISO 27041 / UK MoJ POL.POP.014

**Ritma implementation**:
- Ritma provides **technical controls**; legal/procedural compliance is the operator's responsibility.
- Configuration options:
  - `RITMA_COC_REQUIRE_SIGNATURE=1` — require cryptographic signature on custody log entries
  - `RITMA_COC_TSA_URL=...` — RFC 3161 Time-Stamp Authority for external timestamping
  - `RITMA_COC_RETENTION_DAYS=...` — minimum retention before pruning allowed

---

## Secure Deletion After Sealing — Tamper-Evident Pruning

### Problem

Storing all raw `TraceEvent`s indefinitely is impractical for high-volume deployments. However, deleting evidence without proper controls could:
1. **Destroy forensic value** before it's needed
2. **Enable cover-ups** by malicious insiders
3. **Violate retention regulations** (PIPEDA 2yr, Québec Law 25 5yr, etc.)

### Industry guidance

- **NIST SP 800-88 Rev.1**: Sanitization must be **verified** and **documented**. Cryptographic erasure (deleting keys) is acceptable if keys are irreversibly destroyed.
- **ISO 27037 §7.4**: Preservation includes documenting any changes to evidence, including destruction.
- **UK MoJ POL.POP.013**: Forensic Readiness Plan must include secure disposal procedures.

### Ritma secure deletion policy

**Rule**: Raw data in `index_db` may be pruned **only after**:
1. The window is **sealed** into RTSL (Merkle root committed)
2. A **custody_log entry** of type `PRUNE` is recorded with:
   - window boundaries
   - count of events deleted
   - hash of deleted data (for audit)
   - reference to RTSL seal record
3. (Optional) Proofpack has been **exported** to long-term storage

**Implementation**:
```
index_db.prune_sealed_window(namespace, window_id) -> PruneResult
  1. Verify window_id exists in RTSL (sealed)
  2. Compute hash of events to be deleted
  3. Insert custody_log entry (action=PRUNE, target=window_id, data_hash=...)
  4. DELETE FROM trace_events WHERE namespace=? AND ts >= start AND ts <= end
  5. Return PruneResult { events_deleted, custody_log_id }
```

**Guardrails**:
- `RITMA_PRUNE_REQUIRE_SEAL=1` (default) — prune fails if window not sealed
- `RITMA_PRUNE_REQUIRE_EXPORT=1` — prune fails if proofpack not exported
- `RITMA_PRUNE_MIN_AGE_HOURS=24` — minimum age before pruning allowed

### Exploitation prevention

| Attack vector | Mitigation |
|---------------|------------|
| Attacker deletes events before seal | `prune_sealed_window` checks RTSL seal exists; fails otherwise |
| Attacker modifies custody_log | custody_log uses hash chaining; any gap/modification detectable |
| Attacker replays old seal to justify deletion | RTSL seal includes timestamp; prune checks seal_ts < prune_ts |
| Attacker with DB access deletes directly | custody_log is append-only; missing entries detectable by hash chain gaps |
| Attacker deletes custody_log | custody_log can be replicated to external witness / SIEM; gaps detectable |

### Cryptographic erasure (future)

For deployments requiring NIST 800-88 "Purge" level:
- Encrypt `trace_events` with per-window key
- Store key in HSM or secure enclave
- Pruning = delete key (cryptographic erasure)
- Custody_log records key deletion event

---

## Custody Log Schema

```sql
CREATE TABLE IF NOT EXISTS custody_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                    -- RFC 3339 timestamp
    actor_id TEXT NOT NULL,              -- node_id / user / service
    action TEXT NOT NULL,                -- CAPTURE|SEAL|EXPORT|PRUNE|VERIFY|ACCESS
    namespace_id TEXT,
    window_id TEXT,
    target_hash TEXT,                    -- hash of affected data
    details TEXT,                        -- JSON metadata
    prev_log_hash TEXT,                  -- hash chain
    log_hash TEXT NOT NULL,              -- hash of this entry
    signature TEXT,                      -- optional cryptographic signature
    tsa_token BLOB                       -- optional RFC 3161 timestamp token
);
CREATE INDEX IF NOT EXISTS idx_custody_log_ns_ts ON custody_log(namespace_id, ts);
CREATE INDEX IF NOT EXISTS idx_custody_log_action ON custody_log(action);
```

---

## RFC 3161 Timestamping (Optional)

For court-admissible evidence, external timestamping proves evidence existed at a specific time:

1. Compute hash of sealed window (or custody_log entry)
2. Send `TimeStampReq` to TSA (e.g., FreeTSA, DigiCert, Entrust)
3. Receive `TimeStampResp` containing signed timestamp token
4. Store token in `custody_log.tsa_token` or proofpack

**Configuration**:
- `RITMA_TSA_URL=https://freetsa.org/tsr` (example)
- `RITMA_TSA_HASH_ALG=SHA-256`

---

## COSE Receipts for RTSL (Future)

IETF draft-ietf-cose-merkle-tree-proofs defines CBOR-encoded receipts for transparency logs:

- **Inclusion proof**: proves a leaf is in the Merkle tree
- **Consistency proof**: proves tree grew append-only

Ritma can adopt this format for `rtsl_receipt.cbor`:
```cbor
{
  "vds": 1,                    // RFC9162_SHA256
  "tree_size": 12345,
  "root": h'...',              // 32-byte root hash
  "leaf_index": 42,
  "inclusion_path": [h'...', h'...', ...],
  "signature": h'...'          // COSE_Sign1
}
```

---

## Summary: Ritma CoC Compliance Matrix

| Requirement | Standard | Ritma Feature |
|-------------|----------|---------------|
| Append-only evidence capture | ISO 27037, ACPO P1 | hash-chained trace_events |
| Tamper-evident ledger | CT, SCITT | RTSL Merkle tree + signed roots |
| Audit trail for all actions | ACPO P2-3, ISO 27043 | custody_log table |
| Secure deletion with proof | NIST 800-88, ISO 27037 | prune_sealed_window + custody_log |
| External timestamping | RFC 3161 | TSA integration (optional) |
| Portable evidence bundle | ISO 27042 | proofpack export |
| Third-party verification | ACPO P3 | inclusion proofs + hash verification |

---
---

# Ritma v2 Forensic Page Standard (Normative Specification)

**Status**: Draft Normative  
**Version**: 2.0  
**Applies to**: RTSL, Proofpack, CAS, Custody Log

This section defines the **exact bytes-on-disk**, **exact hashes/signatures**, and **exact file names** for Ritma forensic evidence. Implementations MUST NOT deviate from this specification.

---

## 1. Window Page: The Canonical Signed Statement

### 1.1 `window_page.cbor` — The SCITT-like Statement

The **window page** is the single canonical object that everything else references. It is a **signed statement** (SCITT-shaped) that commits to all evidence for a one-minute window.

**Encoding**: Deterministic CBOR (RFC 8949 §4.2)  
**Map key ordering**: Lexicographic by UTF-8 bytes  
**Integer encoding**: Minimal bytes  
**Float encoding**: Shortest form preserving value

#### 1.1.1 Canonical CBOR Map Structure

```cbor
{
  "v": 2,                                    ; page format version (integer)
  "ns": "<namespace_id>",                    ; namespace URI (tstr)
  "win": {                                   ; window boundaries
    "id": "<window_id>",                     ; UUID (tstr)
    "start": "<RFC3339>",                    ; window start (tstr)
    "end": "<RFC3339>"                       ; window end (tstr)
  },
  "sensor": {                                ; sensor identity
    "node_id": "<RITMA_NODE_ID>",            ; node identifier (tstr)
    "tracer_ver": "<semver>",                ; tracer_sidecar version (tstr)
    "bar_ver": "<semver>"                    ; bar_orchestrator version (tstr)
  },
  "cfg": {                                   ; configuration hashes
    "config_hash": "<sha256>",               ; effective config hash (tstr)
    "policy_hash": "<sha256>"                ; policy pack hash (tstr)
  },
  "counts": {                                ; event counts (for quick triage)
    "events": <uint>,                        ; trace_events count
    "edges": <uint>,                         ; attack_graph edges count
    "artifacts": <uint>                      ; evidence artifacts count
  },
  "trace": {                                 ; trace evidence commitment
    "mode": "full" | "hash_only",            ; privacy mode (tstr)
    "trace_cbor_hash": "<sha256>",           ; SHA-256 of trace_events.cbor (tstr)
    "trace_chain_head": "<sha256>"           ; last event_hash in window (tstr, optional)
  },
  "bar": {                                   ; BAR outputs commitment
    "features_hash": "<sha256>",             ; SHA-256 of features.cbor (tstr)
    "graph_hash": "<sha256>",                ; SHA-256 of attack_graph.cbor (tstr)
    "ml_hash": "<sha256>",                   ; SHA-256 of ml_result.cbor (tstr)
    "verdict_hash": "<sha256>"               ; SHA-256 of verdict.cbor (tstr)
  },
  "manifest_hash": "<sha256>",               ; SHA-256 of manifest.cbor (tstr)
  "custody_log_hash": "<sha256>",            ; SHA-256 of custody_log.cbor (tstr)
  "rtsl": {                                  ; RTSL commitment
    "leaf_hash": "<sha256>",                 ; CT-style leaf hash (tstr)
    "leaf_index": <uint>,                    ; position in log (uint, optional)
    "sth_ref": "<sha256>"                    ; STH hash reference (tstr)
  },
  "time": {                                  ; timestamps
    "sealed_ts": "<RFC3339>",                ; seal timestamp (tstr)
    "tsa_token_hash": "<sha256>"             ; RFC 3161 token hash (tstr, optional)
  }
}
```

#### 1.1.2 Hash Computation

All hashes in this spec are **SHA-256** unless otherwise noted.

```
hash(x) = SHA-256(x)
```

For files:
```
file_hash = SHA-256(file_bytes)
```

### 1.2 `window_page.sig.cose` — COSE_Sign1 Signature

The page MUST be signed using **COSE_Sign1** (RFC 9052 §4.2).

**Algorithm**: ES256 (ECDSA w/ SHA-256 on P-256) or EdDSA (Ed25519)  
**Protected header**:
```cbor
{
  1: -7,                    ; alg: ES256 (or -8 for EdDSA)
  3: "application/ritma-page+cbor"  ; content type
}
```

**Payload**: The exact bytes of `window_page.cbor`  
**External AAD**: Empty

```
COSE_Sign1 = [
  protected: << { 1: -7, 3: "application/ritma-page+cbor" } >>,
  unprotected: {},
  payload: << window_page.cbor bytes >>,
  signature: << 64 bytes for ES256 >>
]
```

---

## 2. RTSL Leaf Definition (Hard Rule)

### 2.1 Leaf Payload

RTSL commits to the **page hash**, not raw events. The leaf payload is a minimal routing envelope:

```cbor
{
  "v": 2,                       ; RTSL version
  "ns": "<namespace_id>",       ; namespace
  "win_id": "<window_id>",      ; window UUID
  "start": <unix_ts>,           ; window start (integer seconds)
  "end": <unix_ts>,             ; window end (integer seconds)
  "page_hash": "<sha256>"       ; SHA-256 of window_page.cbor
}
```

**Canonical encoding**: Deterministic CBOR, keys sorted lexicographically.

### 2.2 Leaf Hash (CT-style Domain Separation)

```
leaf_payload_bytes = canonical_cbor(leaf_payload)
leaf_hash = SHA-256(0x00 || leaf_payload_bytes)
```

The `0x00` prefix is the **leaf domain separator** per RFC 9162 §2.1.

### 2.3 Node Hash (Merkle Tree Interior)

```
node_hash = SHA-256(0x01 || left_hash || right_hash)
```

The `0x01` prefix is the **node domain separator**.

### 2.4 Signed Tree Head (STH)

```cbor
{
  "v": 2,                       ; STH version
  "log_id": "<sha256>",         ; log identity (hash of log public key)
  "tree_size": <uint>,          ; number of leaves
  "root_hash": "<sha256>",      ; Merkle root
  "timestamp": "<RFC3339>",     ; STH timestamp
  "signature": "<base64>"       ; COSE_Sign1 detached signature
}
```

The STH MUST be signed with the log's signing key (same algorithm as page signatures).

---

## 3. Proofpack Directory Layout (Exact, Boring, Predictable)

When exporting a window:

```
ritma export-window --ns <ns> --start <RFC3339> --end <RFC3339>
```

Output directory structure:

```
proofpack_<ns_safe>_<start_ts>_<end_ts>/
├── README.txt                    # Human one-screen summary
├── window_page.cbor              # The canonical signed statement
├── window_page.sig.cose          # COSE_Sign1 signature
│
├── trace_events.cbor             # Optional (omit if hash_only mode)
├── attack_graph.cbor             # Attack graph edges
├── features.cbor                 # Window features
├── ml_result.cbor                # ML score + explanation
├── verdict.cbor                  # Verdict + reasons
│
├── manifest.cbor                 # Artifact manifest with hashes
├── custody_log.cbor              # Custody log excerpt for this window
│
├── rtsl_receipt.cbor             # STH + inclusion proof
├── keyring/
│   └── signer_pub.cosekey        # Public key for signature verification
│
└── hashes.txt                    # Human-friendly digest list (optional)
```

### 3.1 File Naming Convention

- `<ns_safe>`: namespace with `/` replaced by `_`, max 64 chars
- `<start_ts>`, `<end_ts>`: Unix timestamp (integer seconds)

Example:
```
proofpack_ns___test_prod_app_svc_1737331200_1737331260/
```

### 3.2 `README.txt` Format

```
Ritma Forensic Proofpack v2
===========================
Namespace:    ns://test/prod/app/svc
Window:       2025-01-19T12:00:00Z to 2025-01-19T12:01:00Z
Window ID:    a1b2c3d4-e5f6-7890-abcd-ef1234567890
Node:         demo-node
Sealed:       2025-01-19T12:01:05Z

Counts:
  Events:     142
  Edges:      23
  Artifacts:  5

Verification:
  ritma verify-proofpack .

Page Hash:    sha256:abc123...
RTSL Leaf:    #42 in log
STH Root:     sha256:def456...
```

### 3.3 `manifest.cbor` Structure

```cbor
{
  "v": 2,
  "artifacts": [
    {
      "name": "trace_events.cbor",
      "sha256": "<hash>",
      "size": <bytes>,
      "cas_ref": "sha256/<aa>/<bb>/<hash>"  ; optional CAS path
    },
    ...
  ],
  "privacy": {
    "mode": "full" | "hash_only",
    "redactions": ["pii", "secrets"]
  }
}
```

### 3.4 `rtsl_receipt.cbor` Structure

```cbor
{
  "v": 2,
  "leaf_index": <uint>,
  "leaf_hash": "<sha256>",
  "inclusion_path": [
    { "side": "L" | "R", "hash": "<sha256>" },
    ...
  ],
  "sth": {
    "tree_size": <uint>,
    "root_hash": "<sha256>",
    "timestamp": "<RFC3339>",
    "log_id": "<sha256>",
    "signature": "<base64>"
  }
}
```

---

## 4. Content-Addressed Store (CAS)

### 4.1 Filesystem CAS Layout

```
RITMA_OUT/cas/sha256/<aa>/<bb>/<full_hash>
```

Where:
- `<aa>` = first 2 hex chars of hash
- `<bb>` = next 2 hex chars
- `<full_hash>` = full 64-char hex SHA-256

Example:
```
RITMA_OUT/cas/sha256/ab/cd/abcd1234567890...
```

### 4.2 CAS Operations

**Store**:
```rust
fn cas_store(data: &[u8]) -> String {
    let hash = sha256(data);
    let path = format!("cas/sha256/{}/{}/{}", &hash[0..2], &hash[2..4], hash);
    write_if_not_exists(path, data);
    hash
}
```

**Retrieve**:
```rust
fn cas_get(hash: &str) -> Option<Vec<u8>> {
    let path = format!("cas/sha256/{}/{}/{}", &hash[0..2], &hash[2..4], hash);
    read_file(path).ok()
}
```

### 4.3 Proofpack Export Modes

| Mode | Behavior |
|------|----------|
| `full` | Include all artifact payloads in proofpack |
| `hash_only` | Include only hashes; payloads stay in CAS |
| `hybrid` | Include small artifacts (<1MB); hash large ones |

---

## 5. Custody Log v2 (Court/Audit Friendly)

### 5.1 Enhanced Schema

```sql
CREATE TABLE IF NOT EXISTS custody_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                    -- RFC 3339 timestamp
    actor_id TEXT NOT NULL,              -- node_id / user / service
    session_id TEXT,                     -- ties actions within process lifetime
    tool TEXT NOT NULL,                  -- tracer_sidecar | bar_orchestrator | ritma_cli
    action TEXT NOT NULL,                -- CAPTURE|SEAL|EXPORT|PRUNE|VERIFY|ACCESS
    namespace_id TEXT,
    window_id TEXT,
    target_hash TEXT,                    -- hash of affected data
    details BLOB,                        -- CBOR (not JSON) for canonicalization
    prev_log_hash TEXT,                  -- hash chain
    log_hash TEXT NOT NULL,              -- hash of this entry
    signature TEXT,                      -- optional cryptographic signature
    tsa_token BLOB,                      -- optional RFC 3161 timestamp token
    host_attestation TEXT                -- optional TPM/IMA hash
);
```

### 5.2 Custody Log Entry Hash

```
entry_bytes = canonical_cbor({
  ts, actor_id, session_id, tool, action,
  namespace_id, window_id, target_hash,
  details_hash, prev_log_hash
})
log_hash = SHA-256(entry_bytes)
```

### 5.3 `custody_log.cbor` Export Format

```cbor
{
  "v": 2,
  "entries": [
    {
      "ts": "<RFC3339>",
      "actor_id": "<id>",
      "session_id": "<uuid>",
      "tool": "bar_orchestrator",
      "action": "SEAL",
      "namespace_id": "<ns>",
      "window_id": "<win_id>",
      "target_hash": "<sha256>",
      "details": { ... },
      "prev_log_hash": "<sha256>",
      "log_hash": "<sha256>"
    },
    ...
  ],
  "chain_valid": true
}
```

---

## 6. Prune Tombstone Commitment

### 6.1 Prune Custody Entry (Enhanced)

When pruning, the custody log entry MUST include:

```cbor
{
  "action": "PRUNE",
  "details": {
    "deleted_range": {
      "ns": "<namespace_id>",
      "start": <unix_ts>,
      "end": <unix_ts>,
      "count": <uint>
    },
    "deleted_events_hash": "<sha256>",    ; hash of deleted data
    "sealed_leaf_hash": "<sha256>",       ; RTSL leaf that sealed this window
    "sth_hash": "<sha256>",               ; STH at time of seal
    "tombstone_hash": "<sha256>"          ; hash of deleted_range CBOR
  }
}
```

### 6.2 Tombstone Hash Computation

```
tombstone_cbor = canonical_cbor({
  "ns": namespace_id,
  "start": start_ts,
  "end": end_ts,
  "count": events_count,
  "deleted_events_hash": deleted_hash
})
tombstone_hash = SHA-256(tombstone_cbor)
```

This makes deletion itself **auditable evidence**.

---

## 7. CLI Verification UX

### 7.1 `ritma verify-proofpack <dir>`

**Steps**:
1. Load `window_page.cbor` and `window_page.sig.cose`
2. Verify COSE_Sign1 signature using `keyring/signer_pub.cosekey`
3. Recompute hashes of all included payloads
4. Compare against `manifest.cbor` hashes
5. Verify `window_page` hash matches `rtsl_receipt.cbor` leaf
6. Verify inclusion proof against STH root
7. Verify custody_log hash chain

**Output**:
```
Ritma Proofpack Verification
============================
Page signature:     ✅ valid (ES256, signer: demo-node)
Manifest hashes:    ✅ 5/5 artifacts verified
RTSL inclusion:     ✅ leaf #42 in tree of 1000
Custody chain:      ✅ 3 entries, chain intact

Overall:            ✅ VALID
```

**Exit codes**:
- `0`: Valid
- `1`: Tampered (signature or hash mismatch)
- `2`: Incomplete (missing files, hash-only mode)
- `3`: Error (IO, parse failure)

---

## 8. Environment Variables (Policy Knobs)

| Variable | Default | Description |
|----------|---------|-------------|
| `RITMA_OUT_ENABLE` | `0` | Enable RTSL output |
| `RITMA_OUT_FORMAT` | `rtsl` | Output format: `legacy`, `rtsl`, `dual` |
| `RITMA_OUT_ENFORCE_RTSL` | `0` | Hard-fail if RTSL write fails |
| `RITMA_PRUNE_REQUIRE_SEAL` | `1` | Prune only sealed windows |
| `RITMA_PRUNE_REQUIRE_EXPORT` | `0` | Prune only exported windows |
| `RITMA_PRUNE_MIN_AGE_SECS` | `86400` | Minimum age before prune (24h) |
| `RITMA_EXPORT_MODE` | `full` | Export mode: `full`, `hash_only`, `hybrid` |
| `RITMA_CAS_ENABLE` | `1` | Enable content-addressed store |
| `RITMA_TSA_URL` | (none) | RFC 3161 TSA endpoint |
| `RITMA_SIGN_ALG` | `ES256` | Signing algorithm: `ES256`, `EdDSA` |

---

## 9. Implementation Checklist

### Phase 1: Core (Correctness)
- [x] `window_page.cbor` canonical structure in `common_models` (WindowPageV2, RtslLeafPayloadV2)
- [x] COSE_Sign1 signing (`ritma_contract/src/cose.rs`, `window_page.sig.cose`)
- [x] RTSL leaf = `page_hash` (`write_window_v2_as_rtsl_record` in rtsl.rs)
- [x] Snapshotter wired to CAS (`serialize_and_store` helper in snapshotter)

### Phase 2: Export (Usability)
- [x] `ritma export-window --ns --start --end` command (cmd_export_window)
- [x] Proofpack directory with exact layout
- [x] `manifest.cbor` generation (ManifestV2)
- [x] `rtsl_receipt.cbor` with inclusion proof (generate_rtsl_receipt)

### Phase 3: Verification (Trust)
- [x] `ritma verify-proofpack` command (cmd_verify_proofpack)
- [x] Ed25519 signature verification (verify_page_signature)
- [x] Hash verification against manifest
- [x] Inclusion proof verification (verify_rtsl_inclusion_proof)

### Phase 4: Hardening
- [x] Custody log v2 (session_id, tool, CBOR details) in index_db
- [x] Prune tombstone commitment (prune_sealed_window)
- [x] Prune guardrails (RITMA_PRUNE_REQUIRE_EXPORT, RITMA_PRUNE_MIN_AGE_SECS)
- [x] CAS wired to snapshotter (store_to_cas, serialize_and_store helpers)
- [x] RFC 3161 TSA integration (`ritma_contract/src/tsa.rs`, `RITMA_TSA_URL`)

---

## 10. Compatibility Notes

- **RTSL v1** (legacy): Leaf was raw event hashes. **Deprecated**.
- **RTSL v2** (this spec): Leaf is `page_hash`. **Current**.
- **Proofpack v1**: Ad-hoc structure. **Deprecated**.
- **Proofpack v2** (this spec): Exact layout. **Current**.

Migration: v1 data remains readable but new seals MUST use v2.

