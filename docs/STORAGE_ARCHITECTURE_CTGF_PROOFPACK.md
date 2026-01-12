# Ritma Storage Architecture (Final Target): CTGF + ProofPack (Local-first / Non-custodial)

This document defines the **final target storage system** for Ritma that is:

- **Sustainable** (storage + compute remain bounded)
- **Forensics-feasible** (you can reconstruct timelines + causality)
- **Auditable** (tamper-evident, chain-of-custody, retention)

It is designed to remain **non-custodial by default**:

- Local disk is authoritative.
- Remote backends (S3/MinIO, ClickHouse, WORM) are **explicit opt-in replication**, not required for integrity.

## Philosophy (one-line)

Store **meaning** in thin atoms + CTGF, store **bytes** in CAS, store **trust** in per-window ProofPacks.

---

## The 5 pillars

1. **Canonical Event Atoms (thin)**
2. **CTGF (Conical Tree Graph Format) compression layer**
3. **Graph-lite lineage index (fast tracing)**
4. **CAS (content addressed store) for heavy bytes**
5. **ProofPack per window (heap tree roots + signatures)**

---

## 1) Canonical Event Atoms (thin, always-on)

### Goal
Persist the minimum “meaning” necessary to:

- reconstruct a timeline,
- trace causality,
- verify integrity offline,
- reference heavy bytes only when required.

### Encoding rules (hard requirements)

- **CBOR tuples/arrays only** (not maps)
- **All strings are dictionary IDs** (no raw strings in the hot stream)
- Schema is **versioned** (`schema_version`), and any hashing includes the schema version

### Atom tuple (v0)

Recommended minimal tuple (positional fields):

- `tΔ`: delta time inside the block/window
- `etype`: small enum (exec/open/write/connect/...)
- `actor`: proc_id (or actor_id)
- `object`: file_id / flow_id / proc_id
- `flags_class`: small enum/bitset class (not raw flags)
- `arg_hash`: optional hash (not raw argv/args)
- `payload_ref`: optional CAS ref hash

Notes:

- IDs are integers (varint-friendly).
- Anything large/PII goes to CAS (or is redacted) and is referenced by `payload_ref`.

---

## 2) CTGF (Conical Tree Graph Format)

### Goal
Achieve 100×–1000× compression by converting repeated runtime micro-graphs into:

- **Cone patterns** (stored once)
- **Cone instantiations** (tiny references)

### 2.1 Cone patterns

A cone pattern is a reusable, placeholder graph like:

`exec → open → mmap → connect → send`

Stored once with placeholders instead of concrete IDs.

### 2.2 Cone instantiations

Each instantiation records:

- `cone_id`
- `t_start`
- placeholder→id mapping
- counters / exceptions

### Storage format

- `ctgf/cones/v0001/cones.cbor.zst` — versioned cone library
- `windows/YYYY/MM/DD/HH/blocks/inst_0000.cbor.zst` — instantiation blocks (storage partition = hour)

---

## 3) Graph-lite index (fast forensics tracing)

### Goal
Provide fast “who caused what?” tracing without a heavy graph database.

### Minimum adjacency indices

- **Exec lineage:** parent_proc → child_proc
- **Proc → File:** proc → inode (read/write/exec)
- **Proc → Flow:** proc → flow_id (connect/send/recv)

### Storage approach

- LMDB (or RocksDB) with varint-packed adjacency lists
- key: `(node_id, edge_type, time_bucket)` → packed edges

---

## 4) CAS (Content Addressed Store) for heavy bytes

### What belongs in CAS
Only store heavy evidence when needed:

- file chunks
- snapshot manifests
- packet segments
- memory pages (rare, trigger-only)

### CAS rules

- chunk size: 1–4MB
- key: `BLAKE3(chunk)`
- local-first filesystem layout; optional S3/MinIO replication + lifecycle

---

## 5) ProofPack per window (heap tree roots + signatures)

### Goal
Make the system tamper-evident and audit/court-grade without storing raw logs everywhere.

### Per micro-window output (logical windows inside the hour)

- `micro/w000.cbor` (scope, `t1/t2`, counts, algorithm IDs, schema version)
- `micro/w000.sig` (signature over the micro-window root)

### Per hour output (storage partition roots)

- `hour_header.cbor` (hour-level metadata)
- `proofs/hour_root.cbor` (Merkle roots for the hour)
- `proofs/hour_root.sig` (signature)
- `proofs/chain.cbor` (`prev_root` link)

### Proof structure

- leaf: `hash(canonical instantiation record)`
- micro-window root: Merkle over leaves
- hour root: Merkle over micro-window roots (heap-array style)
- signature: sign micro-window root and hour root (software key v0; TPM/HSM v1)

### Chain-of-custody

- Local disk is enough to be tamper-evident.
- Optional replication to WORM/Object Lock storage creates stronger custody guarantees.

---

## Output Container v2 (ROC v2): enterprise-grade forensic vault

This is the operator-facing container format that makes the system:

1. **Human-navigable** (daily catalog + time-jump indexes)
2. **Precise** (micro-windows inside hourly partitions)
3. **Auditable** (case freezing + access logs + optional anchors)
4. **Operationally measurable** (accounting ledger)
5. **Scalable long-term** (cone library versioning + hot/cold cones)

## Final on-disk layout (Output Container v2: `RITMA_OUT/`)

```
RITMA_OUT/
  _meta/
    store.cbor
    keys/
      pubkeys.cbor
      key_rotation_log.cbor.zst
    schema/
      event_schema_v1.cbor
      cone_schema_v1.cbor
      proof_schema_v1.cbor
    health/
      last_compaction.cbor
      stats_rolling_7d.cbor.zst

  catalog/
    YYYY/MM/DD/
      day.cbor.zst

  windows/
    YYYY/MM/DD/HH/
      hour_header.cbor
      proofs/
        hour_root.cbor
        hour_root.sig
        chain.cbor
      micro/
        w000.cbor
        w000.sig
        w001.cbor
        w001.sig
      blocks/
        inst_0000.cbor.zst
        inst_0001.cbor.zst
      index/
        t_1s.cbor
        t_10s.cbor
        t_60s.cbor
        edge_refs.cbor
        cone_refs.cbor
      report/
        print.txt

  graph/
    edges/
      YYYY/MM/DD/
        HH.edges.lmdb
    dict/
      dict.lmdb

  ctgf/
    cones/
      v0001/
        cones.cbor.zst
        cone_index.cbor
      v0002/

  cas/
    b3/
      ab/cd/<hash>

  accounting/
    YYYY/MM/DD/
      account.cbor.zst

  cases/
    CASE_000042/
      case_header.cbor
      frozen_windows.cbor
      manifest.cbor
      manifest.sig
      access_log.cbor.zst

  exports/
    CASE_000042/
      evidence_bundle.tar.zst
      manifest.cbor
      manifest.sig
```

---

## Capture modes (policy engine)

To keep storage sustainable, implement capture modes:

- **Thin always-on** (atoms + CTGF + graph-lite)
- **Thick on trigger** (60–300 sec): write CAS payloads for context
- **Full only on case** (manual/approved)

Trigger examples:

- exec from tmp/memfd
- ptrace/injection indicators
- privilege escalation
- unusual outbound egress spikes
- secrets-path access
- new binary hash not seen before

---

## How this aligns with Ritma’s Truth Layer requirements

- **Evidence-first**: artifacts are written to disk (atoms, ctgf blocks, proofs, exports)
- **Tamper-evident**: per-window signed roots + chaining
- **Portable verification**: export bundles include manifests + hashes + signatures
- **Non-custodial**: raw bytes are opt-in (CAS trigger-only)
- **Diffable continuity**: windows are the unit of sealing and diffing

---

## Mapping to current repo components (integration plan)

- `crates/index_db`:
  - remains the current hot store (SQLite) for canonical events and windows
  - can act as a source-of-truth stream feeding CTGF/edges/proofpack writers
- `crates/bar_orchestrator`:
  - already has a window pipeline; extend it to emit CTGF inst blocks + proof roots
- `crates/evidence_package`:
  - owns export bundle layout, manifest hashing, signature files
- `crates/node_keystore`:
  - provides local signing keys (v0); later TPM/HSM integration

---

## Implementation modules (crate plan)

- `ctgf_encoder` (atoms → cone instantiations)
- `cone_library` (pattern discovery + storage)
- `inst_block_writer` (hourly partition block writer)
- `edges_indexer` (graph-lite LMDB updates)
- `proofpack_window` (heap tree roots + signatures + chaining)
- `cas_writer` (chunking + BLAKE3 addressing + manifests)
- `catalog_builder` (daily `catalog/YYYY/MM/DD/day.cbor.zst`)
- `time_jump_indexer` (`t_1s.cbor`, `t_10s.cbor`, `t_60s.cbor`)
- `case_manager` (case freezing, manifests, access logs, retention locks)
- `accounting_ledger` (bytes/compression/dedupe accounting)
- `anchor_points` (optional daily anchors to WORM/TSA/UTLD)

Acceptance targets:

- Offline verify fails on any mutation/removal
- Window sealing is deterministic (same inputs → same roots)
- Thick capture is bounded by time and policy
- Human-time navigation works without scanning folders (catalog + time-jump indexes)
- Case freezing prevents retention deletion of included windows

---

## Rotation + retention v0 spec (IndexDB + RITMA_OUT)

This section defines the **v0 operational retention policy** for local-first CCTV deployments.

### Goals

- Keep disk usage bounded without losing evidentiary integrity.
- Ensure deletion/expiry never breaks offline verification for sealed artifacts.
- Ensure any future “case freeze” prevents retention deletion.

### Definitions

- **Hot store:** `INDEX_DB_PATH` (SQLite). Operational query/index store.
- **Evidence store:** `RITMA_OUT_DIR` (Output Container v2). Append-only evidence artifacts.
- **Sealed window:** a closed time range whose roots/manifests are committed to `RITMA_OUT_DIR`.
- **Case freeze:** a retention lock for selected sealed windows (future feature; retention must respect it).

### IndexDB rotation (v0)

Rotate the SQLite DB by either size or time:

- **Rotate by size:** when the active DB exceeds a configured threshold.
- **Rotate by time:** daily rotation boundary (UTC) for long-running agents.

Rotation outputs must be stored in the same parent directory as `INDEX_DB_PATH`.

Proposed filename scheme (example):

- Active: `index_db.sqlite`
- Rotated: `index_db.sqlite.2026-01-06T00-00-00Z.0001`

### Seal-before-deletion rule

Before any rotated unit is eligible for deletion:

- A sealing step must run for the covered time range.
- The sealing step must emit the corresponding evidence artifacts to `RITMA_OUT_DIR` (ProofPack roots + catalog/index entries).
- If sealing fails, retention deletion must not proceed.

### Retention policy (v0)

Retention acts on two classes of data:

- **IndexDB rotated units:** keep the most recent **N** rotated units (or **N days**) plus the active DB.
- **RITMA_OUT artifacts:** sealed artifacts are retained according to policy; unsealed/in-progress artifacts may be pruned only if doing so cannot break verification for any sealed range.

### CAS expiry policy (v0)

Raw/high-volume payloads (CAS) may be expired more aggressively than thin atoms/proofs, but only if:

- The payload is not referenced by any sealed manifest.
- The payload is not part of a frozen case.

### Case freeze (hard constraint)

When case freezing is implemented, retention must treat frozen windows as immutable and non-expirable:

- Deletion/GC must not remove any file referenced by a frozen case manifest.
- Any background cleanup must be aware of case-freeze metadata.
