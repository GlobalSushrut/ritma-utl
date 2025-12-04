# Universal Trust Layer – Pre‑Planning

## 1. Intent and Scope

This document captures the early design intent for the Universal Trust Layer (UTL).
It crystallizes the raw concepts into implementable primitives and a crate layout
that we can turn into real Rust code later.

Focus of this pre‑planning:

- **Define the core primitives and language** you already invented.
- **Clarify goals vs non‑goals** for the first iterations.
- **Sketch the initial Rust workspace layout** (modules / crates).
- **Set an MVP cut** so we can build something small but real.

## 2. Problem Statement

Modern compute (AI, cloud, devices, containers) lacks a portable, verifiable
"state of truth" layer across:

- Processes, AIs, devices, and containers.
- Time (non‑linear / mocked clocks, replays).
- Memory and execution (heap, GPU, unknown logic).
- Agreements (humans, services, policies).

We want a **Universal Trust Layer** that gives:

- A root state of truth for any process or entity.
- Verifiable transitions over a universal clock.
- Compact proofs for important states and transitions.
- Merkle/zk‑anchored memory and execution history.
- Traceability for both transparent and black‑box logic.

## 3. Core Primitives (Conceptual)

These are the eight main primitives (plus supporting clock / entropy / memory)
we will design around:

- **StateOfTruthRoot (SoT)**  
  Root of reality for a given process/entity. Binds initial state, params,
  and a zk arc commitment for the full life of the process.

- **TransitionHandshake + TimeTick (Universal Clock)**  
  Handshake that binds entity id + SoT root + universal non‑linear time to
  each transition.

- **DistilliumMicroProof**  
  "Aadhaar‑style" micro‑proof capsule for important states, combining
  state hash, timestamp, lock flag, and optional zk snippet.

- **TataFrame (TATA Data Type)**  
  Universal hashed polar container for events/records:
  data + time on one pole, logic + boundary on the other.

- **EntropyBin + EntropyHeapNode**  
  Group TATA frames by entropy and arrange them into a heap/tree with Merkle
  commitments for anomaly detection, replay, and analysis.

- **Merkle Memory & .dig Files**  
  Time‑sliced, Merkle‑committed forensic memory / execution dumps emitted as
  `.dig` files.

- **TrustAgreementContainer**  
  Binds agreements (terms) to proof chains derived from actual execution.

- **UnknownLogicCapsule**  
  Perfect tracing wrapper for black‑box or unsolved logic: we may not know
  the math, but we fully know inputs, location, and outputs.

These map 1:1 to your original points; here we are only stabilizing names
and relationships.

## 4. Design Principles

- **Verifiability‑first**  
  Everything important must be hashable, commit‑able, and provable later
  (Merkle and zk‑friendly).

- **Small, composable units**  
  The primitives should be usable independently (e.g., just TATA + entropy,
  or just SoT + handshake) and still make sense.

- **Format‑agnostic data**  
  Work with opaque bytes / generic types at the core. Higher layers can know
  about JSON, Protobuf, etc., but the trust core does not depend on them.

- **Deterministic wire formats**  
  Clear, deterministic encoding (for hashes, Merkle trees, proofs).

- **Rust‑first, polyglot‑ready**  
  Implemented in Rust with clear FFI‑friendly types so other languages can
  consume proofs and files.

## 5. Domain Language and Naming

Canonical names we will use across code and docs:

- **StateOfTruthRoot**: `root_id`, `root_hash`, `root_params`, `tx_hook`, `zk_arc_commit`.
- **TransitionHandshake**: `entity_id`, `sot_root`, `clock_tick`, `signature`.
- **TimeTick**: `raw_time`, `mock_time` based on your non‑linear formula.
- **DistilliumMicroProof**: `micro_id`, `parent_root`, `state_hash`, `timestamp`,
  `lock_flag`, `zk_snip`.
- **TataFrame<D>**: `data`, `timeclock`, `hash_root`, `params`, `logic_ref`, `wall`.
- **EntropyBin**: `bin_id`, `tata_frames`, `local_entropy`.
- **EntropyHeapNode**: `node_id`, `children`, `bin_ref`, `merkle_root`.
- **DigRecord / DigFile**: `addr_heap_hash`, `p_container`, `timeclock`,
  `data_container`, `hook_hash`, plus `file_id`, `time_range`, `dig_records`,
  `merkle_root`.
- **TrustAgreementContainer**: `agreement_id`, `party_a`, `party_b`, `terms_hash`,
  `proof_chain`, `tracer`.
- **UnknownLogicCapsule**: `capsule_id`, `input_snapshot`, `logic_descriptor`,
  `bridge`, `output_snapshot`, `output_address`.

We will keep these names stable in `arch.md` and in Rust types later so the
mental model never drifts.

## 6. Planned Rust Workspace Layout (Future)

Target layout for the Rust implementation (to be created after this planning
step, not yet in the repo):

- **`crates/sot_root/`**  
  StateOfTruthRoot type, root parameters, initialization and hashing.

- **`crates/clock/`**  
  TimeTick implementation and the universal non‑linear clock mapping.

- **`crates/handshake/`**  
  TransitionHandshake, signature abstraction, binding clock + SoT.

- **`crates/tata/`**  
  TataFrame and related helpers (encoding, compression hooks, hashing).

- **`crates/entropy_tree/`**  
  EntropyBin and EntropyHeapNode, entropy calculations, Merkle commitments.

- **`crates/dig_mem/`**  
  Merkle memory structures, `.dig` file format, writers/readers.

- **`crates/distillium/`**  
  DistilliumMicroProof construction and verification hooks.

- **`crates/trust_container/`**  
  TrustAgreementContainer and integration with micro‑proofs and tracers.

- **`crates/tracer/`**  
  UnknownLogicCapsule and bridge/location abstractions.

- **`crates/core_types/`**  
  Shared definitions: `UID`, `Hash`, `Sig`, `ZkArcCommitment`, `ZkProof`,
  `ParamBag`, `LogicRef`, `BoundaryTag`, `LogicDescriptor`, etc.

Initially these may live in a single crate; we can split into multiple crates
when boundaries and dependencies are clearer.

## 7. MVP Cut (Version 0.1)

For the first concrete implementation we will:

- **Implement core types**
  - `UID`, `Hash`, `TimeTick`, `StateOfTruthRoot`, `TransitionHandshake`.
- **Implement basic TATA frame**
  - Generic `TataFrame<D>` with hashing and simple param bag.
- **Add a minimal entropy bin/tree**
  - Group frames into bins, compute a basic entropy score and a Merkle root.
- **Add a simple .dig recorder**
  - Append `DigRecord` to a `.dig` file and compute a file‑level Merkle root.
- **Add stub Distillium micro‑proofs**
  - Deterministic, non‑zk proof objects (hash‑based) with room for zk later.
- **Add a minimal TrustAgreementContainer**
  - Link a `terms_hash` with a list of micro‑proofs.
- **Add UnknownLogicCapsule skeleton**
  - Capture inputs/outputs/locations without deep integration yet.

Out of scope for MVP:

- Real zk proof systems (we only reserve types and hooks).
- Optimized compression or 1000x shrink encodings.
- Complex key management or PKI.
- Multi‑tenant storage backends.

## 8. Roadmap Sketch

- **Phase 0 – Docs & Types**  
  `preplanning.md`, `arch.md`, core type definitions, basic hashing.

- **Phase 1 – Single‑process demo**  
  Create a demo binary that:
  - Creates a `StateOfTruthRoot`.
  - Performs a few transitions with `TransitionHandshake`.
  - Emits `TataFrame`s and `EntropyBin`s.
  - Writes a `.dig` file.

- **Phase 2 – Proofs & Agreements**  
  - DistilliumMicroProofs over selected frames.
  - TrustAgreementContainer for simple SLAs / tasks.

- **Phase 3 – Unknown Logic & Multi‑entity**  
  - Wrap a black‑box AI call into an UnknownLogicCapsule.
  - Cross‑entity handshakes and shared entropy trees.

## 9. Open Questions

- How strong / formal must the non‑linear clock be for v0.1?  
  (Exact formula vs just a monotone but weird mapping.)

- Do we target a specific hash function (e.g. BLAKE3) from day one,
  or abstract it behind a trait?

- How much of the `.dig` format is fixed vs versioned / extensible?

- Where do we first deploy this?  
  Single‑machine AI workloads, cloud services, or device firmware?

These will be refined in `arch.md` and in the first Rust prototypes.
