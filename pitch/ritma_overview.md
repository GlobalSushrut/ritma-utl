# Ritma / Universal Truth Layer (UTL) – Pitch Overview

## 1. What Ritma Is

Ritma is an experimental **Universal Truth Layer (UTL)** for security.

From the real code and architecture:

- It is a **policy-driven middleware** that sits **between applications and the operating system**.
- Every important action (a **transition**) is evaluated against a **TruthScript policy**.
- The system both **enforces decisions** (allow / deny / allow with actions) and **creates verifiable forensics** about what actually happened.

At runtime, Ritma is composed of:

- **`utld`** – the main daemon (policy firewall + dig sealing + decision events).
- **`utl_cli`** – CLI used to register roots, record transitions, and inspect forensics.
- **`utl_forensics`** – HTTP API over indexed forensic data (DigFiles & forensics store).
- **`security_host`** – host agent stub that consumes decision events and calls `security_os` traits.
- **`security_os`** – abstract interfaces for firewall / isolation controllers.

This is not just a library or policy engine; it is a **full runtime fabric** aimed at security, forensics, and governance.

---

## 2. What Ritma Actually Does (Based on Code)

From the core crates and binaries, Ritma provides three concrete capabilities:

### 2.1 Enforce – Live Policy Firewall

- **Daemon**: `crates/utld` (not shown here but described in README) listens on a Unix socket.
- **Requests**: It processes `NodeRequest` messages, including:
  - `RegisterRoot` — register a new **StateOfTruthRoot** (defined in `crates/sot_root`).
  - `RecordTransition` — apply a policy to an event (entity, root, hashes, payload, parameters).
- **Policies**: Uses `truthscript` + `policy_engine` crates to evaluate each event.
- **Decisions**:
  - `allow` – event accepted.
  - `deny` – event blocked with a reason.
  - `allow_with_actions` – event accepted but triggers additional actions (e.g., seal a DigFile).

The **`utl_cli`** binary (see `crates/utl_cli/src/main.rs`) wires into this daemon and exposes commands such as:

- `roots-list` – list registered roots.
- `root-register` – register a new StateOfTruth root (ID, hash, parameters, hooks).
- `tx-record` – record a transition with signature, hashes, logic refs, parameters, etc.

These commands map directly to strongly typed Rust requests (`NodeRequest`) over the Unix socket.

### 2.2 Record – Cryptographically Sealed Forensics (DigFiles)

- For selected transitions, `utld` creates **DigFiles** via the `dig_mem`, `forensics_store`, and `dig_index` crates.
- Each **DigFile**:
  - Contains a sequence of **DigRecords** with timestamps and a parameter bag.
  - Has a **Merkle root** committing to all records.
  - Is written under `UTLD_DIG_DIR` (default `./dig`).
- The **`forensics_store`** crate mirrors DigFiles into an S3-style directory layout under `UTLD_FORENSICS_DIR` (default `./forensics`):

  - `forensics/<tenant>/<YYYY>/<MM>/<DD>/root-<root_id>_file-<file_id>_<ts>.dig.json`

- The **`dig_index`** crate writes a compact `DigIndexEntry` for each sealed DigFile into:
  - `UTLD_DIG_INDEX` JSONL (default `./dig_index.jsonl`).
  - Optionally `UTLD_DIG_INDEX_DB` (e.g. `./dig_index.sqlite`).

The `utl_cli` code uses this index to:

- List DigFiles and filter by tenant, root, time, etc. (`digs-list`).
- Resolve a DigFile path from an index entry and inspect it (`dig-inspect-id`).
- Inspect DigFiles from disk and print human-readable summaries (`dig-inspect`).

### 2.3 Explain – Decision Events and Host Agent

- For every policy evaluation that has actions, the daemon emits a **`DecisionEvent`** (crate `security_events`) into a JSONL log at `UTLD_DECISION_EVENTS` (default `./decision_events.jsonl`).
- Events include:
  - `tenant_id`, `root_id`, `entity_id`, `event_kind`.
  - `policy_name`, `policy_version`, `policy_decision`.
  - `policy_rules`, `policy_actions`.
  - Optional identity context (DIDs, zones, actors).
- The `security_host` binary reads this stream:
  - Prints human-readable summaries (decisions, rules, actions).
  - Invokes `security_os` trait implementations like `FirewallController` and `CgroupController`.
  - Current implementations mostly log intended actions but are the anchor for a real host agent.

Together, these pieces create a chain:

`App / Agent → utld (policy+dig) → DigFiles + Index + Forensics API → DecisionEvents → security_host / OS Controls`

---

## 3. Potential & Strategic Value

Based on the code and architecture, Ritma’s potential is in **high-assurance security and compliance** contexts where you need both **real-time enforcement** and **strong evidence**.

### 3.1 Potential

- **Universal truth fabric for security**:
  - A shared layer of record and decision across many systems, not just logs.
  - Cryptographically committed history (Merkle-rooted DigFiles) that can be audited.
- **Policy as product surface**:
  - TruthScript policies and tenant lawbooks (`tenant_policy`) allow rich, tenant-specific behavior.
  - The engine can evolve without changing application code.
- **Forensics that are queryable and explainable**:
  - Indexed forensic artifacts via JSONL/SQLite and HTTP (`utl_forensics`).
  - Evidence bundles (`/evidence/:file_id`) can be used directly in audits or investigations.
- **Integration-friendly**:
  - CLI (`utl_cli`) for ops workflows.
  - Unix socket API (`utld`) for agents and SDKs.
  - HTTP API (`utl_forensics`) for dashboards, SIEMs, and external tools.

### 3.2 Example Use Cases

These are all directly supported or clearly enabled by the current architecture:

1. **Zero-trust host firewall with explainable decisions**
   - Every host-level transition (connection, process, file access) is turned into a `RecordTransition`.
   - `utld` enforces allow/deny decisions via `security_host` + `security_os` traits.
   - Each decision is logged as a `DecisionEvent` and, when needed, sealed in DigFiles.
   - Security teams can query `utl_forensics` for “why was this denied / allowed?” with exact policy rules.

2. **Tenant-level governance for multi-tenant SaaS**
   - Each tenant gets a **root of truth** and a **lawbook** (crate `tenant_policy`).
   - Transitions from that tenant are evaluated under their lawbook and global platform invariants.
   - DigFiles, indices, and forensics store provide tenant-scoped evidence for audits and breach investigations.

3. **Regulatory and compliance evidence (PCI, HIPAA, SOC2, etc.)**
   - DigFiles serve as an immutable audit trail of security-relevant decisions.
   - Forensics API can power compliance dashboards, auto-generated evidence bundles, and audit exports.

4. **Security research / advanced telemetry**
   - Researchers can run custom policies (TruthScript) and see how they fire on synthetic or live data.
   - The CLI’s `policy-test` and `policy-validate` commands already support this.

---

## 4. Current Stage & Maturity (Product)

Based on the project structure, README, and extent of code wiring:

- **Stage**: Early **production slice / advanced prototype**.
  - The README explicitly calls this the first production slice of **Pravyom**.
  - The core scenario (policy firewall + DigFiles + forensics API + host agent stub) is implemented.
- **What works today** (per the README and code):
  - Live policy enforcement on transitions via `utld`.
  - Sealed DigFiles and an indexed forensic vault (`dig`, `forensics`, `dig_index.*`).
  - Time- and policy-based dig queries via `utl_forensics`.
  - Structured decision events driving a host-agent stub (`security_host`).
- **What’s not fully productized yet**:
  - Host agent is still a **stub** (trait calls, logging-only controllers).
  - No full-blown deployment tooling, scaling strategy, or high-availability story in this repo.
  - Lawbook governance and cryptographic proof story (`zk_snark`, `trust_container`) are present at primitive level but not yet presented as a full product offering.

A reasonable product-stage summary:

> Ritma is **beyond toy** and **into early production slice**: you can run the daemon, apply real policies, generate real forensic artifacts, and query them via CLI and HTTP. The host agent and some of the advanced cryptographic / governance features are at an early, foundation stage.

---

## 5. Technical Maturity

From the Rust workspace and actual code:

- **Language & tooling**:
  - Rust 2021 workspace with multiple focused crates.
  - Clap-based CLI, serde for serialization, JSONL and SQLite indexing.
  - Clear use of types (e.g., `UID`, `Hash`, `ZkArcCommitment`, `StateOfTruthRoot`).
- **Architecture**:
  - Modular crate design:
    - Runtime components (`utld`, `utl_cli`, `utl_forensics`, `security_host`).
    - Core primitives (`core_types`, `sot_root`, `entropy_tree`, `tracer`, `zk_snark`, `trust_container`).
    - Forensics infrastructure (`dig_mem`, `dig_index`, `forensics_store`).
    - Policy system (`truthscript`, `policy_engine`, `tenant_policy`).
  - The CLI (`utl_cli`) shows mature wiring: multiple subcommands, robust argument parsing, and detailed error messages.
- **Data integrity**:
  - Merkle-rooted DigFiles.
  - Indexed metadata for time windows, tenant, root, and decision info.
  - Clear directory and file naming conventions.
- **Extensibility**:
  - `security_os` traits allow swapping in real firewall/cgroup controllers later.
  - Policy engine is decoupled from storage and transport.

Technical maturity summary:

> The codebase is **technically mature at the platform-core level** (daemon, CLI, indexing, APIs) and **deliberately early** at integration edges (host agent, external OS controls, full lawbook governance UI). It is engineered as a real platform, not a demo script.

---

## 6. How to Use This File in a Pitch

This Markdown file is designed to be a direct bridge from **code → narrative**.

You can:

- Lift sections directly into pitch slides:
  - “What Ritma Is” → elevator slide.
  - “What it Actually Does” → architecture and demo slides.
  - “Potential & Use Cases” → market/problem/solution fit section.
  - “Current Stage & Technical Maturity” → roadmap and risk slide.
- Adapt terminology for different audiences:
  - For security leaders: emphasize policy control, explainable enforcement, and forensics.
  - For investors: emphasize unique position as a universal truth layer and the depth of implemented primitives.

This description is intentionally grounded in the **real code and repository layout**, so it stays honest while still being pitch-ready.

## 7. Deep Technical Architecture and Guarantees

### 7.1 End-to-End Request Pipeline

- **Transport & protocol**
  - `utld` (see `crates/utld/src/main.rs`) binds a Unix socket from `UTLD_SOCKET` (default `/tmp/utld.sock`).
  - Each client connection is handled in `handle_client`, which reads **newline-delimited JSON** and deserializes into `NodeRequest`.
- **Request types** (`NodeRequest` in `crates/utld/src/lib.rs`):
  - `RegisterRoot { root_id, root_hash, root_params, tx_hook, zk_arc_commit }`.
  - `RecordTransition { entity_id, root_id, signature, data, addr_heap_hash, p_container, logic_ref, wall, hook_hash }`.
  - `BuildDigFile { root_id, file_id, time_start, time_end }`.
  - `BuildEntropyBin { root_id, bin_id }`.
  - `ListRoots`.
- **Policy enforcement hook**
  - If a policy is configured via `UTLD_POLICY`, `utld` loads it as a `truthscript::Policy` and wraps it with `PolicyEngine`.
  - Every `RecordTransition` request first passes through `enforce_policy`:
    - Builds an `EngineEvent` (kind + typed fields) from `p_container`, `entity_id`, `root_id`, `logic_ref`.
    - Evaluates it with `PolicyEngine::evaluate`, producing a list of `EngineAction`s.
    - Emits a `DecisionEvent` and injects policy metadata (`policy_name`, `policy_version`, `policy_decision`, `policy_rules`, `policy_actions`) back into `p_container`.
    - Applies side effects via `apply_engine_actions` (e.g., deny, seal dig, require proofs).
  - If `enforce_policy` returns a `NodeResponse` (e.g., deny), that is sent immediately; otherwise the request falls through to `handle_request` which mutates the `UtlNode` state.

### 7.2 Core Data Model and State of Truth

- **Primitive types** (`core_types`):
  - `UID(u128)` – globally unique IDs (UUID v4) used for roots, entities, files, bins, circuits.
  - `Hash([u8; 32])` – SHA‑256 hashes via `hash_bytes`.
  - `Sig(Vec<u8>)` – opaque signature bytes (used with HMAC in `verify_signature`).
  - `ParamBag(BTreeMap<String, String>)` – generic parameter bag for events and records.
  - `LogicRef`, `BoundaryTag`, `LogicDescriptor`, `TracerRef` – strongly-typed wrappers around strings for logic identity and boundaries.
- **State of Truth root** (`sot_root`):
  - `StateOfTruthRoot { root_id: UID, root_hash: Hash, root_params: ParamBag, tx_hook: UID, zk_arc_commit: ZkArcCommitment }`.
  - Roots are:
    - Registered via `NodeRequest::RegisterRoot` → `UtlNode::register_root`.
    - Persisted atomically to JSON (`UTLD_STATE_FILE`, default `./utld_roots.json`).
- **In‑memory node state** (`UtlNode`):
  - `roots: HashMap<UID, StateOfTruthRoot>` – registered roots.
  - `records: HashMap<UID, Vec<DigRecord>>` – pending records per root.
  - `entropy_bins: HashMap<UID, Vec<EntropyBin>>` – derived entropy summaries.
  - `capsules: HashMap<UID, Vec<UnknownLogicCapsule>>` – unknown logic traces.
  - `sealed_files: HashMap<UID, Vec<DigFile>>` – sealed DigFiles per root (in‑memory cache).
  - `micro_proofs: HashMap<UID, Vec<DistilliumMicroProof>>` – experimental micro‑proofs.

### 7.3 Recording a Transition and Building a DigFile

When a `RecordTransition` passes policy checks:

1. **Signature verification** (`verify_signature` in `utld`):
   - If `UTLD_SIG_KEY` is set, `utld` interprets it as hex HMAC‑SHA256 key.
   - Computes HMAC over:
     - `entity_id` (little‑endian bytes).
     - `root_id` (little‑endian bytes).
     - `addr_heap_hash` bytes.
     - `hook_hash` bytes.
     - Raw `data` bytes.
   - Compares the result to `Sig(signature)` and returns `InvalidSignature` on mismatch.
   - If any problem with the key (unset or invalid), verification is **skipped but logged**.
2. **Framing** (`TataFrame` + `DigRecord`):
   - `TimeTick::now()` captures the logical time.
   - A `TataFrame` is built from `(data, tick, root_hash, p_container, logic_ref, wall)`.
   - A `DigRecord` stores:
     - `addr_heap_hash`.
     - `p_container` cloned from the frame.
     - `timeclock` (same tick).
     - An embedded `TataFrame` as `data_container`.
     - `hook_hash`.
   - Record is appended to `UtlNode.records[root_id]`.
3. **Sealing and indexing** (`seal_and_index_current_dig`):
   - Called by policy actions like `SealCurrentDig` or `Deny`.
   - Steps:
     - Allocate `file_id = UID::new()` and `time_range = (now, now)`.
     - `UtlNode::seal_dig_for_root` builds a `DigFile` from all pending records for the root, resets `records[root_id]`, and stores the sealed file in memory.
     - `persist_dig_file` writes the DigFile JSON to `UTLD_DIG_DIR` (`./dig` by default) with atomic write + optional HMAC signature via `UTLD_DIG_SIGN_KEY`.
     - Derives tenant/policy metadata from the first `DigRecord`’s `p_container` (`tenant_id`, `policy_*`).
     - Calls `forensics_store::persist_dig_to_fs` to mirror into S3‑style layout under `UTLD_FORENSICS_DIR`.
     - Constructs a `DigIndexEntry` (file_id, root_id, tenant_id, time range, record_count, Merkle root, policy metadata, storage_path) and appends it via `dig_index::append_index_entry`:
       - Always to JSONL `UTLD_DIG_INDEX` (`./dig_index.jsonl`).
       - Optionally to SQLite `UTLD_DIG_INDEX_DB` with indexed columns for tenant/time, root/time, and policy_decision.

### 7.4 Policy Language and Engine

- **TruthScript (`truthscript`)** defines the high‑level policy language:
  - `Policy { name, version, rules }`.
  - Each `Rule` has optional `when` and a list of `Action`s.
  - `When { event: Option<String>, conditions: Vec<Condition> }` with conditions such as:
    - `EventEquals { value }`.
    - `FieldEquals { field, value }`.
    - `FieldGreaterThan { field, threshold }`.
    - `EntropyGreaterThan { threshold }`.
    - `CountGreaterThan { counter, threshold }`.
  - `Action` variants line up with enforcement features:
    - `SealCurrentDig`, `FlagForInvestigation`, `RequireDistilliumProof`, `RequireUnknownLogicCapsule`, `CaptureInput`, `CaptureOutput`, `RecordField`, `RequireSnarkProof`, `Deny`.
- **Policy engine (`policy_engine`)**:
  - Wraps a `truthscript::Policy` and exposes `evaluate(EngineEvent)` → `Vec<EngineAction>`.
  - Internally tracks counters to implement `CountGreaterThan`.
  - Unit tests demonstrate scenarios like high‑threat HTTP requests leading to `Deny`, or AI calls requiring micro‑proofs.
- **Tenant lawbooks (`tenant_policy`)**:
  - Separate `Lawbook` format with `rules` expressed in terms of `event_kind`, conditions and `RuleAction` (Allow/Deny/Rewrite/Escalate) plus required `EvidenceKind`s (`SealDigfile`, `MustLog`).
  - `validate_lawbook` enforces invariants:
    - Non‑empty `tenant_id`, `policy_id`, `version > 0`, at least one rule.
    - For high‑risk event kinds (`record_access`, `payment_tx`, `ai_call`), rules **must** request some evidence.
  - `utl_cli` offers `lawbook-validate` to check tenant lawbooks against these platform rules.

Combined, TruthScript + `policy_engine` + tenant lawbooks give a layered **governance model**: global policies, per‑tenant lawbooks, and explicit evidence requirements.

### 7.5 Entropy, Unknown Logic, and zkSNARKs

- **Entropy analysis (`entropy_tree`)**:
  - `EntropyBin::from_records` takes DigRecords and computes `frame_hashes` from their `data_container.content_hash()`.
  - `compute_entropy` uses the distribution of the first byte across hashes to compute Shannon‑like entropy.
  - `EntropyHeapNode::from_bins` aggregates bins into a Merkle‑like root via `hash_bytes`.
  - Policies can react to entropy via `Condition::EntropyGreaterThan` on an `entropy` field.
- **Unknown logic tracing (`tracer`)**:
  - `UnknownLogicCapsule` captures:
    - Input snapshot (a `TataFrame<Vec<u8>>`).
    - `LogicDescriptor` describing the external logic.
    - `BridgeInfo { trusted, location }`.
    - Output snapshot and output address.
  - `UtlNode::record_unknown_logic_capsule` attaches capsules to a root; `PolicyAction::RequireUnknownLogicCapsule` is wired in `apply_engine_actions` for logging today and can evolve into richer tracing.
- **zkSNARK integration (`zk_snark`)**:
  - Implements an **equality circuit** over BN254 using Groth16:
    - `EqualityCircuit` enforces `a == b`.
    - `setup_equality` creates `SnarkKeys { proving_key, verifying_key }` for a `circuit_id`.
    - `prove_equality` and `verify_equality` provide a full proof/verify loop.
  - `apply_engine_actions` handles `PolicyAction::RequireSnarkProof` by:
    - Setting up keys for a new `circuit_id` (random `UID`).
    - Mapping `root_id` into the field as `a` and `b` and verifying equality.
    - Logging success/failure; currently used as a **demonstration hook** but structurally ready for real circuits.
- **Distillium micro‑proofs (`distillium`)**:
  - `UtlNode::generate_micro_proof_for_root` uses `DistilliumMicroProof::new` with `(root_id, state_hash, true, None)` and stores the proof.
  - Triggered by `PolicyAction::RequireDistilliumProof` in `apply_engine_actions`.

These features show a **cryptographically aware design** where entropy, unknown logic, and proofs are first‑class concepts around each StateOfTruth root.

### 7.6 Decision Events, DIDs, and OS‑Level Hooks

- **Decision events (`security_events`)**:
  - `DecisionEvent` struct contains:
    - `ts`, `tenant_id`, `root_id`, `entity_id`, `event_kind`.
    - `policy_name`, `policy_version`, `policy_decision`.
    - `policy_rules`, `policy_actions`.
    - Optional `src_did`, `dst_did`, `actor_did`, `src_zone`, `dst_zone`.
  - `append_decision_event` writes to `UTLD_DECISION_EVENTS` (default `./decision_events.jsonl`) and fills `ts` if zero.
- **Identity and isolation model (`security_os`)**:
  - `Did` type with strict parsing (`did:ritma:...`) and `DidKind` classification (Tenant, Service, Zone, Identity).
  - `IsolationScope` (Service/Zone/Tenant) and `IsolationProfile` (CPU, memory, egress/ingress flags).
  - `FlowDecision` (Allow/Deny/Throttle/Isolate) representing high‑level network/RPC decisions.
  - `FirewallController` and `CgroupController` traits define **host‑level enforcement hooks**.
- **Host agent stub (`security_host`)**:
  - Reads the decision stream from `SECURITY_EVENTS_PATH` (`./decision_events.jsonl`).
  - Logs each decision with key metadata.
  - When `src_did` and `dst_did` are present and parseable:
    - Derives `FlowDecision` (deny vs allow) from `policy_decision`.
    - Calls `FirewallController::enforce_flow` on a logging implementation.
  - Contains a placeholder for calling `CgroupController::apply_profile` once isolation profiles are encoded into events.

This gives a clear upgrade path from **log‑only** to **real OS enforcement** without changing the upstream policy language.

### 7.7 Guarantees, Limitations, and Open Risks (Code-Level)

- **What the code already guarantees**:
  - **Deterministic hashing and IDs** via `core_types::hash_bytes` and `UID::new`.
  - **Atomic writes** for:
    - Root state (`utld_roots.json` via temp file + fsync + rename).
    - DigFiles under `UTLD_DIG_DIR`.
  - **Optional authenticity** for:
    - Transition signatures (HMAC with `UTLD_SIG_KEY`).
    - DigFile contents (HMAC with `UTLD_DIG_SIGN_KEY`, `.sig` sidecar file).
  - **Queryable forensics** via JSONL + SQLite index, with indexes on tenant/time, root/time, and policy_decision.
  - **Structured, machine‑readable events** for SOCs/agents via `DecisionEvent`.
- **Current limitations in the code**:
  - `utld` is **single‑process, single‑threaded**, handling connections sequentially on one `UtlNode` (no sharding or concurrency control yet).
  - Signature and dig signing are **best‑effort** (skipped if keys misconfigured, with logs but no hard failure).
  - `security_host` only logs and invokes logging controllers; there is no real firewall/cgroup integration in‑repo.
  - zkSNARK and Distillium integration are **demonstrative**: equality circuit, simple micro‑proofs, no production proof circuits yet.
  - Entropy and unknown‑logic features are present but not yet wired into a full operator workflow or dashboard.
- **Risks and future hardening** (implied by the code):
  - Need for **multi‑process / distributed** UTL nodes for scale and HA.
  - Stronger guarantees around **key management** (HSM/KMS instead of env vars).
  - Hardening of **on‑disk stores** (permissions, rotation, encryption at rest).
  - Formalization of how **tenant lawbooks** map into TruthScript policies in a multi‑tenant control plane.

From an investor or technical due‑diligence perspective, this section shows that Ritma already encodes a **coherent security and evidence model in code**: roots of truth, framed transitions, sealed and indexed DigFiles, entropy and unknown‑logic awareness, pluggable policies, and explicit hooks for host enforcement and cryptographic proofs.
