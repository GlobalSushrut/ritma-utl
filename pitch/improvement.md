# Ritma / TruthScript – Next-Gen Architecture Improvements

> Goal: Evolve Ritma into a **Universal Truth Layer** whose assurances rival or exceed a blockchain, *without* becoming a blockchain – by combining CUE-based policy, immutable policy "burns", cryptographically verifiable forensics, and zero-knowledge circuits.

---

## 1. Design Goals

1. **CUE-native TruthScript**  
   TruthScript policies, tenant lawbooks, and event shapes are authored and validated in **CUE**, then compiled into the existing Rust `truthscript` + `policy_engine` model.

2. **Immutable policy burn box**  
   Policy deployments become **one-way burns**: you can only add new versions, never mutate or delete prior ones. Every change leaves a **forever-auditable snapshot**.

3. **Blockchain-grade assurance without a chain**  
   Use **hash-chained logs, Merkle commitments, multi-party witnessing, and zk proofs** to achieve immutability, non-equivocation, and verifiable history without a global blockchain.

4. **ZK-first primitives**  
   Move from demo equality proofs to **task-specific zk circuits** for policy evaluation and dig inclusion, so that policy compliance and forensics can be proven without full disclosure.

5. **Operator practicality**  
   All of the above must integrate with the existing Rust workspace: `utld`, `utl_cli`, `utl_forensics`, `security_host`, `truthscript`, `policy_engine`, `tenant_policy`, `zk_snark`, and `distillium`.

---

## 2. CUE as Canonical Policy Language for TruthScript

### 2.1 Motivation

Today:

- Policies and lawbooks are JSON (`truthscript::Policy`, `tenant_policy::Lawbook`).
- Validation is done via Rust types and some CLI commands (`policy-validate`, `lawbook-validate`).

We want:

- **Single canonical source of truth** for:
  - TruthScript policy schema.
  - Tenant lawbook schema.
  - Event schemas (fields in `EngineEvent.fields` / `ParamBag`).
- **Declarative constraints** that are more expressive than JSON Schema.
- A way to **generate and validate policy artifacts** before they ever touch `utld`.

CUE is a good fit: it’s a configuration+constraints language with type-checking and unification, ideal for declaratively specifying allowed structures and invariants.

### 2.2 Proposed CUE Layering

Introduce a new CUE-focused toolchain and crates:

- **New crate**: `crates/utl_cue` (Rust CLI + small library).
- **CUE modules (in repo)**:
  - `cue/truthscript.cue` – schema for `Policy`, `Rule`, `When`, `Condition`, `Action`.
  - `cue/tenant_lawbook.cue` – schema for `Lawbook`, `RuleAction`, `EvidenceKind`.
  - `cue/events.cue` – common event kinds and field shapes (e.g. `ai_call`, `record_access`, `payment_tx`).

Workflow:

1. **Author CUE policy**  
   Developers and tenants write policies as CUE files referencing these schemas:
   - `policy_hipaa.cue`, `policy_ai.cue`, `tenant_acme_lawbook.cue`, etc.

2. **Validate & compile locally**  
   `utl_cue` provides commands:
   - `utl_cue policy build <file.cue>` → JSON `truthscript::Policy`.
   - `utl_cue policy validate <file.cue>` → check against `truthscript.cue`.
   - `utl_cue lawbook build <file.cue>` → JSON `tenant_policy::Lawbook`.
   - `utl_cue lawbook validate <file.cue>` → check tenant invariants (already encoded in CUE).

3. **Attach content hashes**  
   During build, `utl_cue` computes:
   - `policy_hash = SHA-256(compiled_json)`.
   - Optionally `cue_hash = SHA-256(normalized_cue_source)`.
   These hashes are embedded into metadata fields, e.g. `policy.meta.policy_hash`.

4. **Load into `utld`**  
   - `UTLD_POLICY` points to compiled JSON, but `utld` can also check optional metadata:
     - Enforce that `policy_hash` matches the file contents.
     - Optionally require that the policy was signed by a valid issuer (see §4).

Results:

- All live policies are guaranteed to **pass CUE validation**.
- Policy structure and invariants are centrally defined and shared (`cue/*.cue`).
- You can build higher-level tooling (UIs, SaaS control planes) directly on CUE.

### 2.3 CUE for Event Shapes

Extend CUE usage beyond policies:

- Define event schemas in `events.cue`, e.g.:
  - `RecordTransitionEvent`, `AICallEvent`, `PaymentTxEvent`, etc.
- Generate **typed client libraries** from these schemas (out of scope for now, but enabled by CUE).
- Enforce in CI that any event-producing service matches the declared shape.

This improves **end-to-end type safety**: events → policy matching → forensics all share a common schema vocabulary.

---

## 3. Immutable Policy Deploy/Burn Box ("Burn CUE")

### 3.1 Concept

We introduce a **TruthScript Deploy Box**: a minimal service + data model for policy and lawbook deployments, with **burn semantics**:

- You can only **append** new deployments.
- You cannot mutate or delete prior deployments.
- Every deployment produces a **Policy Burn Record** that is itself recorded under Ritma’s forensics model.

Think of this as a **write-once policy ledger**, backed by CUE + DigFiles.

### 3.2 Data Model: Policy Burn Record

New logical type (conceptually, stored as JSON/CUE + DigRecords):

- `PolicyBurnRecord`:
  - `burn_id: UID` – unique ID of this burn.
  - `kind: enum { TruthScriptPolicy, TenantLawbook }`.
  - `policy_id: String` – logical policy identifier (`"hipaa"`, `"ai_guardrail"`, etc.).
  - `version: String` – semantic version (`"1.2.0"`).
  - `cue_source_ref: String` – path or content hash of the CUE file.
  - `compiled_json_ref: String` – path or content hash of the compiled JSON.
  - `policy_hash: Hash` – SHA-256 of compiled JSON.
  - `cue_hash: Hash` – SHA-256 of normalized CUE source.
  - `issuer_did: Did` – DID of the entity who burned this policy.
  - `signature: Sig` – signature by issuer over the above fields.
  - `prev_burn_id: Option<UID>` – link to previous version of same `policy_id` (if any).
  - `ts: TimeTick` – timestamp.

Each `PolicyBurnRecord` is:

- Written as a `RecordTransition` event on a dedicated **policy root** (e.g. `policy_root_id`).
- Evaluated under a **meta-policy** that enforces burn semantics (e.g. denies attempts to mutate historical burns).
- Sealed into DigFiles that form the **policy ledger**.

### 3.3 Burn Semantics

Enforce via code and policy:

- **Append-only per `policy_id`**:
  - New burns can be created with higher `version` numbers.
  - On-chain/in-ledger invariants:
    - For a given `policy_id`, `version`s must be strictly increasing.
    - Historical `PolicyBurnRecord`s remain accessible and immutable.

- **Runtime selection**:
  - `utld` consults the policy ledger (or a cached view) to determine the **effective policy version** for a tenant or root.
  - It loads the corresponding compiled JSON and checks `policy_hash`.

- **Change tracking**:
  - Comparing two burns (`prev_burn_id`, `burn_id`) gives a precise snapshot of **what changed**:
    - CUE diff.
    - Policy JSON diff.
  - These diffs can be computed offline and stored as additional DigRecords or metadata.

### 3.4 CLI and Operator Flow

Extend `utl_cli` (or new `utl_cue` commands) with:

- `policy-burn`:
  - Inputs: CUE file, policy ID, version, issuer key/did.
  - Steps:
    - Validate + compile CUE.
    - Construct `PolicyBurnRecord`.
    - Sign it.
    - Send a `RecordTransition` to `utld` on the policy root.

- `policy-history <policy_id>`:
  - List all burns for that ID, with versions, hashes, issuers.

- `policy-compare <policy_id> <v1> <v2>`:
  - Show semantic diffs (CUE and/or JSON) between burns.

This makes policy governance **operationally real** while remaining fully traceable.

---

## 4. Blockchain-Grade Trust Without Blockchain

We want the **security properties** of a blockchain (immutability, non-equivocation, verifiable history) by combining features Ritma already has (Merkle DigFiles, HMAC, Distillium, zkSnark) with new structures.

### 4.1 Hash-Chained Dig Index

Extend `DigIndexEntry` with a new field:

- `prev_index_hash: Option<Hash>` – SHA-256 of the previous index entry (or a chain root for the first entry).

Whenever `dig_index::append_index_entry` writes a new index entry:

1. It reads the last index hash (from memory or a small metadata file).
2. Sets `prev_index_hash`.
3. Computes `current_index_hash = SHA-256(prev_index_hash || serialized_entry)`.
4. Writes the entry and updates a **head file** containing `current_index_hash`.

This yields a **hash chain over all indexed DigFiles**, akin to a minimal blockchain:

- Any deletion or modification in the index breaks the hash chain.
- External observers can store the head hash periodically for **tamper detection**.

### 4.2 Periodic Truth Snapshots

Introduce a new internal process (or CLI command) `utl_snapshot`:

- Periodically computes a **truth snapshot** containing:
  - Head of the dig index chain.
  - Head of the policy burn ledger chain.
  - Optionally, summary stats (counts of roots, DigFiles, denies, etc.).
- Computes `snapshot_hash = SHA-256(snapshot_bytes)`.
- Seals this snapshot as a DigFile under a dedicated root (e.g. `snapshot_root_id`).

These snapshots form a **coarse-grained chain of evidence**:

- To prove that the system hasn’t been rolled back or tampered, you show:
  - A sequence of snapshots, each hash-chained.
  - And that operational data (DigFiles, burns) are consistent with those snapshots.

### 4.3 Multi-Party Witnessing

To approximate blockchain consensus without a chain:

- Allow external **witnesses** (auditors, customers, regulators) to subscribe to:
  - Decision event stream.
  - Snapshot stream.
  - Optional minimal index updates.

Witness behavior:

- Each witness stores snapshot hashes and/or index heads independently.
- Optionally signs those snapshots with its own keys.

Security property:

- For Ritma to undetectably rewrite history, **all or many witnesses must collude** or be compromised – similar to needing a majority of validators in a blockchain, but implemented with simpler infra.

### 4.4 Optional External Anchoring (Future)

To further harden without making blockchain a dependency:

- Implement an optional module that periodically **anchors snapshot hashes** into:
  - Public timestamping services.
  - Existing blockchains (Bitcoin, Ethereum, etc.).

This becomes a **defense-in-depth** layer, not a core requirement.

---

## 5. ZK Circuits Beyond Equality

Today, the `zk_snark` crate implements an **equality circuit** (`a == b`) over BN254 with Groth16. We can evolve this into **application-specific ZK proofs**.

### 5.1 Design Principle

Circuits should prove **properties about policy evaluation and evidence** without revealing full internal data. Example properties:

- "This deny decision is consistent with policy P and event commitment E."  
- "This frame is included in DigFile with Merkle root R."  
- "This summary statistic (e.g., number of denies for rule X) is accurate for all events in a period."  

### 5.2 Circuit 1: Policy Evaluation Circuit (Selective Disclosure)

**Goal**: Prove that an event `E` satisfied (or did not satisfy) a policy `P` and that a given decision bit `d` matches TruthScript semantics, without revealing sensitive fields.

Sketch:

- Public inputs:
  - `policy_commitment` – hash of compiled policy JSON.
  - `event_commitment` – hash/commitment to event fields.
  - `decision_bit` – 0 or 1.

- Private inputs (witness):
  - Concrete policy rule parameters (simplified subset sufficient for circuit).
  - Concrete field values of `E`.

- Circuit constraints:
  - Re-implements a **restricted subset** of TruthScript semantics in arithmetic form:
    - `FieldEquals`, `FieldGreaterThan`, `CountGreaterThan` (possible using accumulators), etc.
  - Ensures that `decision_bit` is consistent with applying those rules to `E`.

Integration:

- New `Action` variant, e.g. `RequirePolicyEvalProof`.
- New crate `zk_truth` that uses `bellman` or similar to define the circuit.
- `utld` (or a sidecar) generates proofs on-demand for selected transitions.
- `DecisionEvent` gains an optional `zk_proof_ref` and `policy_commitment`.

### 5.3 Circuit 2: Dig Inclusion Circuit

**Goal**: Prove that a particular frame hash `h` is included in a DigFile with Merkle root `R`.

Sketch:

- Public inputs:
  - `R` – Merkle root of the DigFile.
  - `h` – leaf hash.

- Private inputs:
  - Merkle path (siblings) from leaf to root.

- Circuit constraints:
  - Recompute root from `h` and siblings.

Integration:

- `utl_forensics` can issue **inclusion proofs** for DigFile entries.
- A verifier (customer, regulator) can check that a reported event trace is really part of the committed DigFile.

### 5.4 Circuit 3: Aggregate Compliance Circuit (Later Phase)

**Goal**: Prove aggregate statements like: "Over this week, all `payment_tx` events from tenant T were either allowed with evidence E or denied as per policy P", without revealing each event.

Sketch:

- Public inputs:
  - Commitments to batches of events.
  - Aggregate counters.

- Private inputs:
  - Per-event fields.
  - More complex constraints.

This is more complex and belongs in a **later phase** once basic circuits are stable.

---

## 6. Additional Architectural Improvements

### 6.1 Concurrency and High Availability

Current state (from code/README):

- Single-process `utld` with one `UtlNode` handling sequential connections.

Improvements:

- **Multi-threaded UtlNode** with per-root locking or sharding.
- Optionally **multi-process nodes** that share Dig index and forensics store via a transactional layer (SQLite + file locks).
- Separation of roles:
  - Policy enforcement node(s).
  - Forensics writer node(s).
  - Snapshot/witness nodes.

This sets the stage for HA clusters without overhauling the data model.

### 6.2 Key Management & Cryptographic Hardening

Current:

- HMAC keys via env vars (`UTLD_SIG_KEY`, `UTLD_DIG_SIGN_KEY`).
- Best-effort verification (skip on misconfig, with logs).

Improvements:

- Integrate with **KMS/HSM** for key storage.
- Introduce **key IDs** and rotation policies in configuration.
- Allow operators to choose **fail-open vs fail-closed** on signature verification.
- Make Distillium and zkSnark keys managed via the same key infrastructure.

### 6.3 Formal Semantics of TruthScript

To support CUE and ZK circuits, TruthScript needs a **clear, written semantics**:

- Precise definition of condition evaluation (ordering, short-circuiting, numeric edge cases).
- Semantics of missing fields and type coercion (`Number` vs `String`).
- Treatment of counters and state.

Deliverables:

- A small **spec document** (could be CUE+Markdown) describing these semantics.
- Property-based tests ensuring Rust implementation matches the spec.

### 6.4 Hardening Entropy & Unknown Logic Features

Current:

- `entropy_tree` and `tracer` provide primitives.

Improvements:

- Make **entropy metrics** first-class fields in `DecisionEvent` and Dig index entries.
- Provide **standard policies** and **CUE templates** for treating entropy as a risk signal.
- For Unknown Logic Capsules:
  - Add richer metadata (e.g., source code commit, deployment id).
  - Provide CLI and HTTP queries for “show all capsules touching service X”.

---

## 7. Phased Implementation Plan

### Phase 0 – Semantics & Schemas

- Write a **TruthScript semantics doc**.
- Define CUE schemas: `truthscript.cue`, `tenant_lawbook.cue`, `events.cue`.

### Phase 1 – CUE Tooling & Policy Burn MVP

- Implement `utl_cue` with build/validate commands.
- Allow `utld` to load compiled JSON with optional hash checks.
- Implement `PolicyBurnRecord` type and CLI command `policy-burn`.
- Record burns as DigRecords on a dedicated policy root.

### Phase 2 – Immutable Ledger & Hash-Chained Index

- Extend `DigIndexEntry` with `prev_index_hash` and maintain chain head.
- Snapshot the policy burn ledger and dig index heads into dedicated roots.
- Add CLI/HTTP endpoints to fetch and verify snapshot chains.

### Phase 3 – ZK Circuits Integration

- Implement `zk_truth` crate with **policy eval** and **dig inclusion** circuits.
- Extend `Action` enum with `RequirePolicyEvalProof` and `RequireDigInclusionProof`.
- Record proofs in `DecisionEvent` and optionally in DigFiles.

### Phase 4 – HA, Witnesses, and Optional External Anchors

- Add multi-threading / sharding to `utld`.
- Implement witness support (streams and signatures).
- Optionally integrate snapshot anchoring into external timestamping/blockchain services.

---

## 8. Summary

These improvements turn Ritma from a powerful **single-node UTL prototype** into a platform with:

- **CUE-native, formally constrained policy authoring** for TruthScript and tenant lawbooks.
- An **immutable policy burn box** that preserves every policy change as forensically verifiable evidence.
- **Hash-chained indices and multi-party witnessing** that approximate blockchain security properties without the weight of a chain.
- **Zero-knowledge circuits** that prove policy correctness and evidence inclusion without over-exposing sensitive data.

Combined, this gives Ritma a plausible path to being a **trust anchor** for security, compliance, and AI governance, while remaining implementable within the existing Rust workspace and concepts.
