# Ritma Security Stack — Layers L1–L5 (Current State)

This document describes the current state of Ritma’s security stack from **Layer 1 (Immutable Evidence)** to **Layer 5 (Business/API)**: what each layer is, its **maturity/stage**, and **what it can do right now**.

---

## L1 — Immutable Evidence & Compliance Layer

**Role**  
Ground-truth layer for **immutable evidence**, **compliance records**, and **virtual CCTV** of system behavior. This is where you prove *what actually happened*.

**Stage**  
**Hardened / Production-ready core** (with some signing logic still as stubs that can later be backed by HSM/KMS).

**Key Capabilities (Current)**

- **Immutable decision & control logs**
  - `security_events::DecisionEvent`:
    - Logs decisions with timestamps and rich metadata.
    - Consensus metadata: decision kind, thresholds met, quorum, validator count, consensus hash.
    - New SVC fields provide version binding:
      - `svc_policy_id`: SVC commit for the policy in effect.
      - `svc_infra_id`: SVC infra snapshot ID at decision time.
  - `compliance_index::ControlEvalRecord`:
    - Hash-chained records: `prev_hash`, `record_hash` for tamper-evident append-only history.
    - Policy snapshot metadata (rulepack id/version/hash).
    - New SVC fields:
      - `svc_control_id`: SVC commit for the control/rulepack.
      - `svc_infra_id`: infra version at evaluation time.

- **Compliance burns with Merkle trees**
  - `compliance_index::burn` module:
    - `ComplianceBurn` represents a **sealed burn** of many control evaluations:
      - `merkle_root`: Merkle tree over record hashes.
      - `prev_burn_hash` / `burn_hash`: hash-chained burns for tamper-evident history.
      - `summary`: total/passed/failed controls, pass rate, time span, frameworks.
      - `leaves`: leaf hashes (record hashes) used to build the Merkle tree.
      - `svc_commit_id`: SVC commit for the burn itself.
      - `infra_version_id`: infra snapshot ID when the burn was taken.
      - Optional `signature` for non-repudiation.
    - Merkle operations:
      - `generate_merkle_proof` + `verify_merkle_proof` for per-record inclusion proofs.
      - `verify_burn_chain` to verify the entire burn chain (hashes + linkage).
  - `burn_process` orchestrator:
    - `BurnProcess` and `BurnConfig`:
      - Reads previous burn hash to maintain a **burn chain** per tenant/framework.
      - Builds and persists burns as JSON files.
      - Maintains a chain index file listing all burn IDs.
      - Optional auto-signing of burns (stubbed, ready to be replaced with real crypto).

- **DigFiles (evidence bundles)**
  - `dig_mem::DigRecord`:
    - Records low-level evidence with:
      - `addr_heap_hash`, `hook_hash`, `timeclock`, `data_container` (TataFrame), and `p_container` (param bag).
      - New metadata:
        - `svc_commit_id`: SVC commit active for this record.
        - `infra_version_id`: infra snapshot at record time.
        - `camera_frame_id`: ID of the CCTV frame this record is associated with.
        - `actor_did`: DID of the actor responsible.
    - `leaf_hash()` computes a deterministic leaf hash for Merkle trees.
  - `dig_mem::DigFile`:
    - Bundles many `DigRecord`s:
      - `merkle_root`: Merkle tree of all leaf hashes.
      - `schema_version`: current DigFile format version.
      - `svc_commits`: deduplicated list of SVC commits referenced by records.
      - `camera_frames`: deduplicated frame IDs from CCTV.
      - `tenant_id`, `compression`, `encryption`, `signature`.
      - `prev_file_hash` / `file_hash`: hash-chained DigFiles for file-level immutability.
    - Integrity & inclusion:
      - `verify()` recomputes Merkle root and file hash.
      - `generate_proof(record_index)` + `verify_proof(record, proof)` for Merkle inclusion.
      - `verify_digfile_chain(files)` checks per-file integrity and chain linkage.
    - Targeted retrieval:
      - `records_by_svc(svc_commit_id)`.
      - `records_by_frame(frame_id)`.
      - `records_by_actor(actor_did)`.

- **Virtual CCTV — LogCamera**
  - `dig_mem::log_camera`:
    - `LogFrame`:
      - `frame_id`, `frame_number`, `timestamp` (`TimeTick`).
      - `state_snapshot`: system view at that point (active DIDs, active policies, resource states, metrics, pending decisions).
      - `transition`: optional `Transition` object describing what changed (type, actor DID, before/after state hashes, events, duration).
      - `prev_frame_hash` / `frame_hash`: hash-chained frames.
      - `events_merkle_root`: Merkle root of transition events.
    - `LogCamera`:
      - Captures `LogFrame`s at a configured frame rate.
      - Maintains in-memory buffer and `last_frame_hash`.
      - `capture_frame()` computes events Merkle root + frame hash and chains frames.
      - `verify_frames(frames)` validates hashes + linkage.
    - `LogCameraRecorder`:
      - Manages multiple cameras by name (“main”, “audit”, etc.).
      - `capture()` on a specific camera.
      - `flush_all()` persists frames as JSONL files, one line per frame.

**Net effect (L1)**  
You now have **cryptographically verifiable, time-ordered, cross-linked evidence** of:
- Policy decisions
- Control evaluations
- Compliance burns
- Low-level records (DigFiles)
- System state snapshots and transitions (CCTV)

---

## L2 — Evidence Indexing & Secure Search Layer

**Role**  
Indexes all evidence from L1, persists it in an efficient DB, and provides **secure, audited** search and retrieval.

**Stage**  
**Production-ready indexing + secure search logging** (search backend itself still stubbed).

**Key Capabilities (Current)**

- **dig_index — SQLite + JSONL index**
  - `DigIndexEntry` (JSONL + DB schema) now includes:
    - Core fields: `file_id`, `root_id`, `tenant_id`, `time_start`, `time_end`, `record_count`, `merkle_root`.
    - Policy linkage: `policy_name`, `policy_version`, `policy_decision`, `policy_commit_id` (legacy), `storage_path`.
    - SVC & infra:
      - `svc_commits`: list of SVC commit IDs.
      - `infra_version_id`: infra snapshot ID.
    - CCTV & actors:
      - `camera_frames`: frame IDs.
      - `actor_dids`: DIDs of actors in this file.
    - Compliance:
      - `compliance_framework`, `compliance_burn_id`.
    - File security:
      - `file_hash`, `compression`, `encryption`, `signature`.
    - `schema_version`: index format version.
  - JSONL index:
    - `append_index_entry()` writes hash-chained JSON lines with `prev_index_hash` and a `.head` file storing the running index hash.
  - SQLite DB schema:
    - Main table `digs` with indices:
      - `idx_digs_tenant_time (tenant_id, time_start, time_end)`.
      - `idx_digs_root_time (root_id, time_start, time_end)`.
      - `idx_digs_policy_decision (policy_decision)`.
      - `idx_digs_infra_version (infra_version_id)`.
      - `idx_digs_compliance (compliance_framework, compliance_burn_id)`.
      - `idx_digs_file_hash (file_hash)`.
    - Relationship tables:
      - `dig_svc_commits (file_id, svc_commit_id)` with `idx_svc_commits`.
      - `dig_camera_frames (file_id, frame_id)` with `idx_camera_frames`.
      - `dig_actors (file_id, actor_did)` with `idx_actors`.

- **Query API (`query` module)**
  - `DigIndexQuery` builder:
    - Filters: tenant, time range, svc_commit, infra_version, frame, actor, compliance framework, burn ID, decision, limit.
    - `execute(db_path) -> Vec<DigIndexEntry>` joins against the relational tables as needed.
  - Convenience functions:
    - `files_by_svc_commit(db_path, svc_commit_id)`.
    - `files_by_camera_frame(db_path, frame_id)`.
    - `files_by_actor(db_path, actor_did)`.
    - `files_by_compliance_burn(db_path, burn_id)`.
    - `tenant_statistics(db_path, tenant_id) -> TenantStats` (file count, total records, earliest/latest timestamps).

- **Hyper-secure search logging (`svc_ledger::search_events`)**
  - `SecureSearchGateway`:
    - DID-based queries (`caller_did`).
    - Mandatory `purpose` per search.
    - Tenant filter enforcement.
    - Per-DID rate limiting (queries per time window).
  - `SearchEvent`:
    - `query_id`, `caller_did`, `query`, `filters`, `timestamp`, `results_count`.
    - Optional `svc_policy_id` linking the search to an authorizing policy.
    - `prev_hash`, `event_hash`, `signature`.
    - `verify_chain()` to validate the entire search audit log.

**Net effect (L2)**  
You can **search and slice** the immutable evidence from L1 by tenant, time, SVC commit, infra version, CCTV frame, actor, or compliance burn, with all searches themselves **secured and auditable**.

---

## L3 — TruthScript Policy & Compliance Pipeline Layer

**Role**  
The **universal policy and compliance engine**: TruthScript language (v1/v2), proof validation, consensus, and a configurable compliance pipeline.

**Stage**  
**Advanced prototype / stable core**: logic is implemented and tested; wiring to all infra and external runtimes is the next step.

**Key Capabilities (Current)**

- **TruthScript v1 & v2 models**
  - v1: original event + conditions + actions.
  - v2 (`truthscript::v2`): infra-aware:
    - `InfraContext` (required capabilities, execution mode, identity requirements, resource limits).
    - `RuleV2` with `WhenV2` (conditions & logical operator), `ActionV2` (eBPF, cgroups, network, DIDs, mTLS, consensus, proofs, evidence, service lifecycle).
    - `PolicyV2::validate()` for structural sanity.

- **v2 Execution (`v2_executor`)**
  - `PolicyExecutorV2`:
    - Evaluates conditions against `ExecutionContext` (stubbed infra state today).
    - Executes actions (logged / simulated in `dry_run` mode).
    - Sorts rules by priority, respects scopes.

- **Consensus (`policy_engine::consensus`)**
  - Weighted validators with thresholds and quorum.
  - Domain-filtered evaluation and staleness checks.
  - Pluggable `SignatureVerifier` for vote signatures.
  - Consensus result exported into `DecisionEvent` (L1) for full audit.

- **Proof validation (`policy_engine::proof_validator`)**
  - Infrastructure to check cryptographic proofs before entering consensus.

- **Compliance pipeline (`policy_engine::compliance_pipeline`)**
  - Multi-stage pipeline:
    - `PolicyEvaluation` → `ProofValidation` → `Consensus` → `ControlEvaluation` → `EvidenceEmission`.
  - CUE-driven config via `cue_integration` (stub ready for real CUE runtime).
  - Fail-fast semantics and integration points for external engines.

**Net effect (L3)**  
You can express **rich policies** over infra and security events, push them through **proof/consensus-aware pipelines**, and emit **self-verifying evidence** that flows into L1/L2.

---

## L4 — Infrastructure Control & Runtime Enforcement Layer

**Role**  
The layer that actually **enforces** policy decisions on infrastructure: eBPF, cgroups, network controls, services, etc.

**Stage**  
**Designed + partially implemented (stub actions)**: API and schema are in place; real integrations with OS/network runtime are the next step.

**Key Capabilities (Current)**

- **Infra-aware policy actions (TruthScript v2)**
  - Actions model:
    - eBPF program load/unload or packet drops.
    - cgroup resource profile application.
    - network quarantine/allow.
    - DID/mTLS credential revocation.
    - evidence emission and service lifecycle operations.

- **Executor skeleton**
  - `PolicyExecutorV2` knows how to interpret v2 actions and conditions.
  - In `dry_run` mode, it logs what would be done — a safe way to test policies.

**Net effect (L4)**  
L4 provides the **language and control hooks** needed to turn decisions into infra changes; the heavy lifting now is binding these to your host/kernel/network implementations.

---

## L5 — Business / API & External Consumption Layer

**Role**  
The layer where **external systems** (console, auditors, partner tools) consume everything built by L1–L4: APIs, dashboards, reports.

**Stage**  
**Foundational / baseline**: crates and integration tests exist; more product/API shaping remains.

**Key Capabilities (Current)**

- Foundation crates (lightly touched in this hardening pass):
  - `biz_api` — business-facing APIs (entry point for external services).
  - `policy_store`, `tenant_policy` — policy storage and per-tenant configuration.
  - `tests/integration` — scaffolding for end-to-end scenarios.

- With current layers, L5 can:
  - Serve **auditor and SRE views**:
    - Show DigFiles, burns, decisions, CCTV frames for a tenant or incident.
    - Expose query results from `dig_index` and secure search logs.
  - Generate **compliance reports**:
    - Per framework (e.g., SOC2) and per burn.
    - With verifiable evidence (Merkle proofs/chain checks) attached.

**Net effect (L5)**  
L5 now has strong primitives from below (L1–L4) to build **auditor-grade interfaces**, external APIs, and reporting — the main work left is UX/API design, not core security plumbing.
