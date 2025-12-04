# Universal Trust Layer – Architecture

This document describes the concrete architecture for the Universal Trust Layer
(UTL) based on the primitives defined in `preplanning.md`.

It is written to be directly translatable into a Rust crate (or workspace)
without redesigning the concepts.

---

## 1. High‑Level Architecture

At a high level, UTL provides a **State of Truth pipeline** for any entity
(process, AI model, device, container):

1. **Rooting** – establish a `StateOfTruthRoot` that commits to initial
   memory, environment, binary, and configuration.
2. **Clocked transitions** – every meaningful transition performs a
   `TransitionHandshake` bound to a universal, non‑linear `TimeTick`.
3. **Event framing** – each step emits a `TataFrame<D>`: a compact, hashed
   polar container for data and logic context.
4. **Entropy structuring** – frames are ingested into `EntropyBin`s and an
   `EntropyHeapNode` tree with Merkle commitments.
5. **Merkle memory** – windows of activity are written into `.dig` files:
   Merkle‑committed, time‑sliced forensic memory.
6. **Micro‑proofs and agreements** – important states become
   `DistilliumMicroProof`s, which chain into `TrustAgreementContainer`s.
7. **Unknown logic tracing** – black‑box or unsolved logic is wrapped in an
   `UnknownLogicCapsule` so its behavior is still fully traceable.

The entire pipeline is designed to be **hash‑first** and **zk‑friendly**.

---

## 2. Core Data Structures (Rust‑oriented Sketch)

> These are conceptual; exact Rust signatures will live in code. Types like
> `UID`, `Hash`, `Sig`, `ZkArcCommitment`, and `ZkProof` are shared in
> `core_types`.

### 2.1 State of Truth Root

- **StateOfTruthRoot**
  - `root_id: UID`
  - `root_hash: Hash`  – hash(memory + env + binary + config)
  - `root_params: RootParams`
  - `tx_hook: TransitionHookId`
  - `zk_arc_commit: ZkArcCommitment`

Responsibilities:

- Provide a stable root of reality for an entity.
- Act as anchor for all later transitions, proofs, and `.dig` files.

### 2.2 Universal Clock and Handshake

- **TimeTick**
  - `raw_time: u64` – unix/monotonic time.
  - `mock_time: f64` – non‑linear mapped time (your formula), normalized.

- **TransitionHandshake**
  - `entity_id: UID`
  - `sot_root: StateOfTruthRoot`
  - `clock_tick: TimeTick`
  - `signature: Sig`

Responsibilities:

- Bind an entity + SoT + universal clock tick to a specific transition.
- Make replay/fabrication of transitions detectable.

### 2.3 Distillium Micro‑Proof

- **DistilliumMicroProof**
  - `micro_id: UID`
  - `parent_root: UID`
  - `state_hash: Hash`
  - `timestamp: u64`
  - `lock_flag: bool`
  - `zk_snip: Option<ZkProof>`

Responsibilities:

- Provide small, atomic proof capsules for important states.
- Serve as building blocks for larger proof chains and agreements.

### 2.4 TataFrame (Hashed Polar Container)

- **TataFrame<D>**
  - `data: D`
  - `timeclock: TimeTick`
  - `hash_root: Hash`
  - `params: ParamBag`
  - `logic_ref: LogicRef`
  - `wall: BoundaryTag`

Responsibilities:

- Be the primary record/log/event unit across the system.
- Carry both data content and logic/security context.
- Support compact binary encoding and compression.

### 2.5 Entropy Bin and Heap Tree

- **EntropyBin**
  - `bin_id: UID`
  - `tata_frames: Vec<Hash>`
  - `local_entropy: f64`

- **EntropyHeapNode**
  - `node_id: UID`
  - `children: Vec<EntropyHeapNodeId>`
  - `bin_ref: Option<EntropyBinId>`
  - `merkle_root: Hash`

Responsibilities:

- Group TATA frames by entropy and structure them hierarchically.
- Enable proofs and analysis over subtrees or bins.

### 2.6 Merkle Memory and .dig Files

- **DigRecord**
  - `addr_heap_hash: Hash`
  - `p_container: ParamBag`
  - `timeclock: TimeTick`
  - `data_container: TataFrame<Vec<u8>>`
  - `hook_hash: Hash`

- **DigFile**
  - `file_id: UID`
  - `time_range: (u64, u64)`
  - `dig_records: Vec<DigRecord>`
  - `merkle_root: Hash`

Responsibilities:

- Provide append‑only, Merkle‑committed forensic memory snapshots.
- Support later replay, debugging, and verification.

### 2.7 Trust Agreement Container

- **TrustAgreementContainer**
  - `agreement_id: UID`
  - `party_a: UID`
  - `party_b: UID`
  - `terms_hash: Hash`
  - `proof_chain: Vec<DistilliumMicroProof>`
  - `tracer: TracerRef`

Responsibilities:

- Bind real‑world or logical agreements to actual execution traces.
- Provide a compact object to export to legal, policy, or SLA systems.

### 2.8 Unknown Logic Capsule

- **BridgeInfo**
  - `trusted: bool`
  - `location: String`  – namespace / cgroup / pod identifier.

- **UnknownLogicCapsule**
  - `capsule_id: UID`
  - `input_snapshot: TataFrame<Vec<u8>>`
  - `logic_descriptor: LogicDescriptor`
  - `bridge: BridgeInfo`
  - `output_snapshot: TataFrame<Vec<u8>>`
  - `output_address: String`  – e.g. `namespace:cgroup:addr`.

Responsibilities:

- Wrap black‑box logic (AI models, binaries, plugins) with full traceability.
- Allow blame, audit, and rollback without requiring interpretability.

---

## 3. Module / Crate Structure

Planned Rust workspace (names are indicative; actual layout may evolve):

- **`core_types`**
  - `UID`, `Hash`, `Sig`, `ZkArcCommitment`, `ZkProof`.
  - `ParamBag`, `LogicRef`, `BoundaryTag`, `LogicDescriptor`, `TracerRef`.

- **`sot_root`**
  - `StateOfTruthRoot`, `RootParams`, `TransitionHookId`.
  - Root creation, hashing, and validation helpers.

- **`clock`**
  - `TimeTick` and universal non‑linear clock implementation.
  - Conversions from system time and mock time formula.

- **`handshake`**
  - `TransitionHandshake` construction and verification.
  - Signature verification/abstraction for different key schemes.

- **`tata`**
  - `TataFrame<D>` definition.
  - Encoding, hashing, and compression plug‑points.

- **`entropy_tree`**
  - `EntropyBin`, `EntropyHeapNode`.
  - Entropy metrics and Merkle tree builder.

- **`dig_mem`**
  - `DigRecord`, `DigFile`.
  - File writer/reader, Merkle root calculation.

- **`distillium`**
  - `DistilliumMicroProof` creation and verification traits.
  - Hooks for real zk systems.

- **`trust_container`**
  - `TrustAgreementContainer` and proof‑chain utilities.

- **`tracer`**
  - `UnknownLogicCapsule`, `BridgeInfo`.
  - APIs to wrap external calls and emit capsules.

- **`policy_engine`**
  - Core evaluation engine for programmable compliance rules.
  - Consumes events from `utld` (frames, `.dig` metadata, entropy, capsules).

- **`truthscript`**
  - Parser and compiler for the compliance DSL.
  - Emits policy configurations/bytecode for `policy_engine`.

All of these can initially be organized under a single crate with modules and
split into multiple crates once the API stabilizes.

---

## 4. Lifecycle and Data Flow

### 4.1 Process / Entity Startup

1. Collect initial `memory`, `env`, `binary`, and `config` descriptors.
2. Compute `root_hash = hash(memory + env + binary + config)`.
3. Instantiate `StateOfTruthRoot` with `root_params`, `tx_hook`, and
   `zk_arc_commit`.

### 4.2 Transition Execution

For each significant transition:

1. Obtain a `TimeTick` from `clock` (raw + mock time).
2. Construct a `TransitionHandshake` for `(entity, SoT, tick)` and sign it.
3. Execute logic (known or unknown).
4. Emit one or more `TataFrame`s describing inputs, outputs, and context.

### 4.3 Entropy and Binning

1. Ingest `TataFrame`s into `EntropyBin`s based on time, type, or other rules.
2. Compute `local_entropy` for each bin.
3. Link bins into an `EntropyHeapNode` tree.
4. Derive Merkle roots for nodes and subtrees.

### 4.4 Merkle Memory and .dig

1. Over fixed time or transition windows, serialize relevant `DigRecord`s:
   - Heap/address mapping hash.
   - Params and TATA snapshots.
   - Hook hash for transitions.
2. Append to `.dig` files.
3. Periodically seal files with a `merkle_root` and optional external anchor
   (e.g. SoT zk arc, blockchain, or other ledger).

### 4.5 Micro‑Proofs and Agreements

1. For checkpoints, generate `DistilliumMicroProof`s from state and history.
2. For agreements (SLAs, policies, tasks), build `TrustAgreementContainer`s
   referencing the relevant micro‑proofs and tracer.
3. Export or verify these containers in higher‑level systems.

### 4.6 Unknown Logic Capsules

1. Before calling black‑box logic:
   - Capture inputs in a `TataFrame<Vec<u8>>`.
2. Wrap the call with `UnknownLogicCapsule` construction:
   - Set `logic_descriptor` and `BridgeInfo` (trusted, location).
3. After execution, capture outputs in another `TataFrame<Vec<u8>>`.
4. Store or emit the capsule into the same entropy/dig pipeline.

---

## 5. Invariants and Security Properties

Key invariants we want every implementation to maintain:

- **Root immutability** – once a `StateOfTruthRoot` is created, its
  `root_hash` and `root_params` must never change.
- **Monotone clock** – while the clock may be non‑linear, observable
  `TimeTick` values must not go backwards for the same entity.
- **Handshake binding** – every accepted transition must have a valid
  `TransitionHandshake` that binds it to a specific SoT root and tick.
- **Frame integrity** – `TataFrame` hashes must be reproducible from their
  encoded representation.
- **Merkle consistency** – Merkle roots in entropy trees and `.dig` files
  must match recomputation from their children.
- **Proof chain soundness** – `TrustAgreementContainer.proof_chain` must
  reference valid `DistilliumMicroProof`s that themselves tie back to the
  correct `StateOfTruthRoot`.

These will be enforced with unit tests and, where possible, type/trait design.

---

## 6. Storage and File Formats

### 6.1 .dig Files

- Append‑only, versioned format.
- Contains:
  - Header with `file_id`, version, `time_range`.
  - Ordered `DigRecord`s.
  - Footer with `merkle_root` and optional external anchors.
- Encoding:
  - Start with a simple, uncompressed binary encoding.
  - Later versions can add compression and delta encoding while preserving
    deterministic hashing.

### 6.2 Indexing and Retrieval

- Index `.dig` files by `StateOfTruthRoot`, `entity_id`, and time.
- Optionally index by entropy ranges and agreement ids.

---

## 7. Extensibility

The architecture is designed so that:

- New proof systems can be plugged into `DistilliumMicroProof` via traits.
- New clock mappings can be implemented behind `TimeTick`.
- New entropy metrics can be added without breaking existing data.
 - Additional agreement types can build on `TrustAgreementContainer`.

---

## 8. Next Implementation Steps

1. **Phase 0 – Spec and Threat Model**
   - Freeze core structs and naming (SoT, TimeTick, TATA, .dig).
   - Choose concrete hash/signature schemes and write a minimal threat model.
2. **Phase 1 – Node Daemon and Core Crates**
   - Create the Rust workspace with `core_types`, `sot_root`, `clock`,
     `tata`, and `dig_mem`.
   - Implement a node‑local daemon (`utld`) exposing a stable socket/gRPC API
     for emitting handshakes, TATA frames, `.dig` records, and capsules.
3. **Phase 2 – OS and Container Integration**
   - Run `utld` as a system service (e.g. systemd) with clear directories for
     `.dig` files and entropy trees.
   - Add cgroup/namespace awareness so each service/container gets its own
     StateOfTruthRoot and trace pipeline.
4. **Phase 3 – SDKs and Application Integration**
   - Provide a production‑ready Rust SDK that applications can link against
     to emit `TransitionHandshake`, `TataFrame`, `DistilliumMicroProof`, and
     `UnknownLogicCapsule` events to `utld`.
   - Document integration patterns for servers, batch jobs, and container
     workloads.
5. **Phase 4 – Enterprise Hardening**
   - Define performance budgets (CPU, memory, IO) and benchmark under real
   - workloads.
   - Add observability (metrics, logs), upgrade/versioning strategy, and
   - security review for deployment in regulated or multi‑tenant environments.

---

## 9. Programmable Compliance Layer (TruthScript)

On top of the Universal Trust Layer, we add a **programmable compliance and
policy layer**. This turns the system from a passive truth recorder into an
active, configurable compliance engine.

### 9.1 Goals

- Allow enterprises to **express compliance and security rules as code**.
- Make rules **bind directly to cryptographic truth** (SoT, TATA, `.dig`,
  entropy, capsules).
- Support **domain-specific rulepacks** (AI, banking, healthcare, government).
- Provide a path from **policy → enforcement → proof** using the same data.

### 9.2 TruthScript DSL (Conceptual Shape)

TruthScript is a small domain-specific language for writing rules over:

- Events: transitions, entropy spikes, `.dig` seals, unknown logic executions.
- Entities: roots, entities, containers, models.
- Fields: frame fields, params, agreement fields.

Illustrative syntax (conceptual):

```text
rule HIPAA_001 {
    when frame.stream == "patient_record" {
        require field(patient.id) not_exposed;
        require dig.seal_on_write;
        require frame.hash_integrity == true;
    }
}

rule AI_FAIRNESS {
    when event == "ai_call" {
        capture input;
        capture output;
        record model_version;
        require no_black_box_skip;
    }
}

on event GPU_JOB_START {
    create_distillium_proof();
    enforce_truth_root();
}

on entropy_spike > 0.8 {
    flag_for_investigation();
    seal_current_dig();
}
```

The actual implementation will likely compile TruthScript into a structured
policy IR rather than interpret arbitrary text at runtime.

### 9.3 Enforcement Points

The compliance layer attaches to several points in the existing architecture:

- **At TATA emission**: decide which frames must be captured, enriched,
  or locked.
- **At `.dig` sealing time**: decide when to force sealing, how often, and
  under which conditions (entropy spikes, policy boundaries).
- **At micro‑proof generation**: decide when `DistilliumMicroProof`s are
  required and what they must cover.
- **At unknown logic execution**: decide when an `UnknownLogicCapsule` is
  mandatory and how it must be parameterized.
- **At TrustAgreementContainer creation**: enforce that agreements link to
  appropriate micro‑proof chains.

### 9.4 Policy Engine Architecture

- **truthscript crate**
  - Parser + checker for TruthScript files.
  - Emits a policy configuration / bytecode (policy IR).

- **policy_engine crate**
  - Loads policy IR at startup or reload time.
  - Evaluates rules on events streamed from `utld`:
    - TATA frames
    - Distillium micro‑proofs
    - `.dig` seals
    - Entropy events
    - UnknownLogicCapsule records
  - Produces enforcement actions:
    - allow / deny / require more data
    - trigger `.dig` seals
    - trigger proof generation
    - generate alerts / logs

The engine can be embedded inside `utld` or run as a sibling service that reads
events from `utld` and sends back enforcement commands.

### 9.5 Example Enforcement Flows

- **AI safety**

  - Rule: after N model calls or on suspicious output, require a
    DistilliumMicroProof and capture an UnknownLogicCapsule.
  - Effect: UTL emits the required proofs and capsules, compliance engine logs
    and optionally blocks further calls until satisfied.

- **GPU job governance**

  - Rule: on `GPU_JOB_START`, create a SoT‑anchored checkpoint, start a `.dig`
    window, and enable high‑frequency frame capture.
  - Rule: on high entropy or anomaly, seal the current `.dig` and raise an
    incident.

- **Healthcare workflow**

  - Rule: for certain data streams (EMR, lab results), ensure no patient
    identifiers appear in exported frames, and that every export is bound to a
    TrustAgreementContainer with explicit consent.

### 9.6 Compatibility and Safety

- Policies should be **versioned** and **auditable** just like `.dig` files.
- The engine should support **dry‑run** and **report‑only** modes for
  introduction in production.
- Rules must never be able to retroactively change past truth; they can only
  influence **what is recorded, sealed, or blocked** going forward.
