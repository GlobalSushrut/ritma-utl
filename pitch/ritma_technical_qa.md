# Ritma / TruthScript – Deep Technical Q&A (Investor Due Diligence)

> This document enumerates 50 technical questions an investor or technical diligence team might ask about Ritma (Universal Truth Layer) and TruthScript, with concise but deep answers grounded in the current codebase.

---

## 1. What is Ritma at the systems level?

Ritma is a **policy-driven middleware fabric** that sits between applications/agents and the operating system. Concretely, it:

- Accepts **`NodeRequest`** messages over a Unix socket (`utld`).
- For each `RecordTransition`, runs a **policy evaluation** using TruthScript + `policy_engine`.
- **Mutates state of truth** and appends framed records (`DigRecord`) into in-memory buffers.
- Periodically and/or via policy actions, **seals DigFiles**, mirrors them into an S3-like forensics store, and appends compact index entries (JSONL/SQLite).
- Emits **DecisionEvents** to a host-agent stub (`security_host`) that is wired to OS-control traits in `security_os`.

So Ritma is effectively a single-process UTL node implementing: enforcement, recording, and explanation.

---

## 2. How does TruthScript relate to the policy engine?

- `truthscript` defines the **policy schema and primitives**:
  - `Policy { name, version, rules }`.
  - `Rule { name, when: Option<When>, actions: Vec<Action> }`.
  - `When { event: Option<String>, conditions: Vec<Condition> }`.
  - `Condition` and `Action` enums define matching and side effects.
- `policy_engine` wraps a `truthscript::Policy` and exposes `PolicyEngine::evaluate(event)`.
- Ritma’s daemon `utld` constructs an `EngineEvent` from the incoming transition and calls `PolicyEngine::evaluate`.
- The `EngineAction`s returned are then interpreted to:
  - Enforce Deny/Allow.
  - Request Dig sealing, micro-proofs, zk proofs, additional logging, etc.

TruthScript is the **language/format**, `policy_engine` is the **runtime evaluator**, and `utld` is the **integrator**.

---

## 3. What is a `RecordTransition` technically?

A `RecordTransition` is a `NodeRequest` variant that carries:

- Identity and scoping: `entity_id`, `root_id`.
- Integrity inputs: `addr_heap_hash`, `hook_hash`, `signature`.
- Payload: raw `data` bytes, `p_container` (parameter bag), `logic_ref`, `wall`.

In `utld`:

1. The request is deserialized from newline-delimited JSON.
2. Policy enforcement (`enforce_policy`) builds an `EngineEvent` from `p_container` plus `entity_id`, `root_id`, `logic_ref`.
3. If policy allows, signature is optionally validated (`verify_signature`).
4. A `TataFrame` and `DigRecord` are created and appended to `UtlNode.records[root_id]`.
5. Later, a policy action or explicit request seals these records into a DigFile.

---

## 4. How are policies represented on disk and in code?

- **On disk**: JSON documents compatible with `truthscript::Policy`, e.g. `security_policy.json` pointed at by `UTLD_POLICY`.
- **In code**:
  - Loaded via `Policy::from_json_str`.
  - Serialized via `Policy::to_json_string` for roundtrips.
  - The CLI offers `policy-validate` and `policy-test` commands (`utl_cli`) to load, validate, and exercise policies against synthetic events.

This design ensures policies are **human-editable JSON** and **strongly typed** in Rust at runtime.

---

## 5. What kinds of conditions can TruthScript express?

TruthScript’s `Condition` enum supports primitives like:

- `EventEquals { value: String }` – match on event kind.
- `FieldEquals { field, value }` – string equality on a named field.
- `FieldGreaterThan { field, threshold: f64 }` – numeric comparison.
- `EntropyGreaterThan { threshold: f64 }` – reacts to entropy metrics.
- `CountGreaterThan { counter, threshold: u64 }` – stateful counter condition.

These are intentionally **minimal but composable**; more complex logic is built as combinations of conditions and multiple rules.

---

## 6. How does the `CountGreaterThan` condition work internally?

- `PolicyEngine` holds a `counters: BTreeMap<String, u64>`.
- When evaluating an `EngineEvent`, for each `Condition::CountGreaterThan { counter, threshold }`:
  - It increments `counters[counter]`.
  - Returns true only if the updated value is greater than `threshold`.

This provides a **stateful view** of activity across events without external storage, suitable for simple “rate/volume” guards.

---

## 7. What actions can TruthScript trigger and how are they enforced?

Key `Action` variants include:

- `SealCurrentDig` – trigger sealing of pending DigRecords into a DigFile.
- `FlagForInvestigation { reason }` – mark the event for human review.
- `RequireDistilliumProof` – request generation of a Distillium micro-proof.
- `RequireUnknownLogicCapsule` – require tracing of unknown external logic.
- `CaptureInput` / `CaptureOutput` – persist full input/output payloads.
- `RecordField { field }` – record an extra logical field.
- `RequireSnarkProof` – request a zkSNARK equality proof.
- `Deny { reason }` – block the transition.

`utld::apply_engine_actions` interprets these into **node-level side effects**, e.g. sealing DigFiles, generating micro-proofs, or short-circuiting with a `Deny` response.

---

## 8. How does the policy decision feed into forensic evidence?

When a policy evaluation returns `EngineAction`s, `utld`:

- Constructs a `DecisionEvent` with:
  - `policy_name`, `policy_version`.
  - `policy_decision` (allow/deny).
  - `policy_rules`, `policy_actions`.
- Injects this metadata back into `p_container` before recording the `DigRecord`.
- As a result:
  - DigFiles carry the **policy context** for each frame.
  - The index (`DigIndexEntry`) includes policy decision metadata.

This ensures that **“what happened” and “why the engine decided so”** are bound together cryptographically.

---

## 9. How does Ritma store forensic evidence on disk?

The pipeline:

1. **DigRecords in memory** per root in `UtlNode.records`.
2. On seal (`seal_and_index_current_dig`):
   - Build a `DigFile` with records and Merkle root.
   - Persist JSON to `UTLD_DIG_DIR` (`./dig` by default) with atomic write and optional HMAC signature.
3. Mirror the DigFile into an **S3-style layout** via `forensics_store` under `UTLD_FORENSICS_DIR` (`./forensics`).
4. Append a `DigIndexEntry` to `UTLD_DIG_INDEX` (JSONL) and optional SQLite DB (`UTLD_DIG_INDEX_DB`).

This gives **immutable log files**, a **forensics tree**, and **queryable indices**.

---

## 10. What are DigFiles and how are they integrity-protected?

- A **DigFile** is a JSON structure containing:
  - `file_id`, `root_id`.
  - A list of `DigRecord`s, each with a framed payload (`TataFrame`), parameter bag, hashes, and timestamps.
  - A **Merkle root** over its records.
- Integrity mechanisms:
  - Merkle root commits to the full record set.
  - On-disk writes use a temp file + fsync + atomic rename.
  - Optional HMAC signature over the file contents using `UTLD_DIG_SIGN_KEY` creates a `.sig` sidecar.

This design provides **tamper-evidence** and **atomic visibility** of new forensic artifacts.

---

## 11. How does the index file (`dig_index.jsonl` / SQLite) work?

For each sealed DigFile, `dig_index` writes a `DigIndexEntry` containing:

- `file_id`, `root_id`, optional `tenant_id`.
- Time window (`time_start`, `time_end`).
- Record count, Merkle root.
- Policy decision summary and storage path.

Index backends:

- **JSONL** (`UTLD_DIG_INDEX`) – append-only, human-readable, easy to pipe.
- **SQLite** (`UTLD_DIG_INDEX_DB`) – optional, with indexes on tenant/time, root/time, and policy_decision.

The CLI and `utl_forensics` query these indices to efficiently locate relevant DigFiles.

---

## 12. What guarantees do you have around atomicity and durability?

The code implements **best-effort atomic writes**:

- Roots state (`utld_roots.json`), DigFiles, and index updates are written to a temp file, fsynced, then renamed.
- This pattern ensures that at any point, consumers see **either the old or new complete file**, never a partial write.
- Durability is bounded by filesystem semantics and host configuration; Ritma doesn’t implement distributed consensus yet.

From an investor perspective, this is **industry-standard local atomicity**, not full distributed durability.

---

## 13. How do tenants and lawbooks fit into the model?

The `tenant_policy` crate defines a **`Lawbook`** with:

- `tenant_id`, `policy_id`, `version`, and `rules`.
- Rules express:
  - `event_kind`, conditions, and `RuleAction` (Allow, Deny, Rewrite, Escalate).
  - Required `EvidenceKind` (e.g. `SealDigfile`, `MustLog`).

`utl_cli` exposes `lawbook-validate`, which enforces invariants like:

- Non-empty tenant and policy IDs.
- Positive version.
- For certain high-risk `event_kind`s, rules **must request evidence**.

This is the beginning of a **multi-tenant governance layer** on top of TruthScript policies.

---

## 14. How does the Unix socket protocol work?

- `utld` reads `UTLD_SOCKET` (default `/tmp/utld.sock`) and binds a Unix domain socket.
- Each client connection is handled in a loop:
  - Read a line of newline-delimited JSON.
  - Deserialize into `NodeRequest`.
  - Process request and serialize a `NodeResponse`.
- This protocol is simple but expressive; language-specific SDKs or sidecars can speak it easily.

---

## 15. How does Ritma verify transition signatures?

In `verify_signature` (utld):

- If `UTLD_SIG_KEY` is set:
  - It is parsed as a hex-encoded HMAC-SHA256 key.
  - The daemon computes HMAC over the concatenation of:
    - `entity_id` bytes.
    - `root_id` bytes.
    - `addr_heap_hash` bytes.
    - `hook_hash` bytes.
    - Raw `data` bytes.
  - Compares with `Sig(signature)` from the request.
- If key is missing or invalid, verification is **skipped with a log**, not fatal.

This provides **optional authenticity** of transitions, which can be hardened further with dedicated key management.

---

## 16. How are IDs and hashes modeled?

The `core_types` crate defines:

- `UID(u128)` – random UUID-like identifiers for roots, files, bins, circuits.
- `Hash([u8; 32])` – SHA-256 digests via `hash_bytes`.
- `Sig(Vec<u8>)` – opaque signatures.

These primitives are reused consistently across DigFiles, roots, entropy trees, and proofs to ensure **type safety** and **hash-consistency**.

---

## 17. How does Ritma compute entropy for forensic analysis?

The `entropy_tree` crate:

- Derives `EntropyBin`s from DigRecords by hashing `data_container.content_hash()` and collecting the first-byte distribution.
- `compute_entropy` computes a Shannon-like entropy score from this distribution.
- `EntropyHeapNode::from_bins` builds a Merkle-like tree of entropy summaries.

Policies can then use `Condition::EntropyGreaterThan { threshold }` on an `entropy` field to react to anomalous behavior.

---

## 18. What is an Unknown Logic Capsule and why is it important?

The `tracer` crate defines `UnknownLogicCapsule`:

- Captures:
  - Input snapshot (`TataFrame<Vec<u8>>`).
  - `LogicDescriptor` describing untrusted or external logic.
  - `BridgeInfo { trusted, location }`.
  - Output snapshot and output address.
- These capsules are attached to a `StateOfTruthRoot` via `UtlNode::record_unknown_logic_capsule`.

Policies can require capsules (`RequireUnknownLogicCapsule`), which is key for **observability and evidentiary coverage around opaque or third-party logic** (e.g., SaaS APIs, ML models).

---

## 19. How does zkSNARK integration work today?

The `zk_snark` crate implements a **Groth16 equality circuit** on BN254:

- `EqualityCircuit` enforces `a == b` for field elements.
- `setup_equality` generates proving and verifying keys (`SnarkKeys`) for a `circuit_id`.
- `prove_equality` and `verify_equality` perform a full proof/verification loop.

`apply_engine_actions` uses `RequireSnarkProof` to:

- Allocate a new `circuit_id` (`UID::new()`).
- Map `root_id` into the field as both `a` and `b`.
- Run setup, prove, and verify, logging success/failure.

Currently this is **demonstrative**, but it proves that Ritma can host **cryptographic proof workflows around state of truth**.

---

## 20. What are Distillium micro-proofs in this context?

The `distillium` integration exposes `DistilliumMicroProof`:

- `UtlNode::generate_micro_proof_for_root` creates a micro-proof for a root using `(root_id, state_hash, true, None)`.
- Triggered by the `RequireDistilliumProof` action.
- Proofs are stored in `UtlNode.micro_proofs` keyed by `root_id`.

This is an early **micro-proof abstraction** that can later be bound to specific compliance claims or invariants about root state.

---

## 21. How do DecisionEvents connect to OS-level enforcement?

The `security_events` crate defines `DecisionEvent`:

- Contains timestamps, tenant/root/entity IDs, event kind.
- Embeds policy metadata and optional DIDs/zones.

The `security_host` process:

- Tails `decision_events.jsonl`.
- For each entry, derives a `FlowDecision` (Allow/Deny/Throttle/Isolate) from `policy_decision`.
- Invokes `FirewallController::enforce_flow` and (future) `CgroupController::apply_profile`.

Current controllers primarily **log intended actions**, but the traits are defined to plug into **real firewall and cgroup backends**.

---

## 22. How are DIDs and zones modeled?

The `security_os` crate defines:

- `Did` parsed from strings like `did:ritma:tenant:...` or `did:ritma:service:...`.
- `DidKind` (Tenant, Service, Zone, Identity) for classification.
- `IsolationScope` and `IsolationProfile` for CPU/memory/egress/ingress controls.

These are used in `DecisionEvent` to provide **identity and isolation context** that OS controllers can act on.

---

## 23. How does the HTTP forensics API work?

`utl_forensics` exposes an HTTP server over the dig index / forensics store:

- Endpoints (from code):
  - List dig index entries with filters (tenant, root, time range, policy decision).
  - Fetch a specific DigFile or evidence bundle by `file_id`.
- Internally it:
  - Reads `DigIndexEntry` records from JSONL/SQLite.
  - Resolves paths into the forensics store (`UTLD_FORENSICS_DIR`).

This provides a **programmatic way for dashboards, SIEMs, or audit tools** to query and download evidence.

---

## 24. How does the CLI (`utl_cli`) support operators and developers?

Key commands include:

- Roots: `roots-list`, `root-register`.
- Transitions: `tx-record`, `tx-list` (depending on current code wiring).
- Digs: `digs-list`, `dig-inspect`, `dig-inspect-id`.
- Policy: `policy-validate`, `policy-test`.
- Lawbooks: `lawbook-validate`.

These commands:

- Connect to the Unix socket.
- Construct structured requests.
- Render human-readable summaries and errors.

They make **policy experimentation and forensic exploration** accessible without writing code.

---

## 25. How is the Rust workspace organized for modularity?

The repository is a **multi-crate Rust workspace**:

- Runtime binaries: `utld`, `utl_cli`, `utl_forensics`, `security_host`.
- Policy system: `truthscript`, `policy_engine`, `tenant_policy`.
- Forensics: `dig_mem`, `dig_index`, `forensics_store`.
- Core types and primitives: `core_types`, `sot_root`, `entropy_tree`, `tracer`, `zk_snark`, `distillium`, `trust_container`.

Each crate has a focused responsibility, reducing coupling and making it possible to **swap implementations** (e.g. different forensics stores) over time.

---

## 26. What is the current concurrency and scaling model?

Today, `utld` is essentially:

- A **single-process, single-node daemon**.
- Handling client connections sequentially on one `UtlNode` state instance (no sharding or distributed coordination in-repo).

Scaling path (future work):

- Run multiple UTL nodes behind a load balancer.
- Use external consensus or database for shared state of truth and dig indices.

For investors, this is a **deliberate MVP tradeoff**: focus on correctness and evidence semantics first, then distributed scale.

---

## 27. How is configuration handled?

Primarily via **environment variables** documented in `README.md`:

- `UTLD_POLICY`, `UTLD_DIG_INDEX`, `UTLD_DIG_DIR`, `UTLD_FORENSICS_DIR`, `UTLD_DIG_INDEX_DB`, `UTLD_DECISION_EVENTS`, `UTLD_SOCKET`, `UTLD_SIG_KEY`, `UTLD_DIG_SIGN_KEY`, etc.

This keeps the binary stateless and makes it easy to:

- Run multiple nodes with different configs.
- Integrate with container orchestrators that manage env vars and secret mounts.

---

## 28. What happens if policy evaluation fails or no policy is configured?

- If `UTLD_POLICY` is not set or the policy fails to load, `utld` can run in a **policy-less mode**, effectively acting as a recorder without enforcement.
- If evaluation itself errors (parsing, invalid fields), current behavior is best-effort logging and falling back to a conservative decision.

This preserves **availability over strictness** while still encouraging strong policy usage.

---

## 29. How does Ritma avoid becoming a bottleneck in the hot path?

Current design considerations:

- Policy evaluation is **in-memory and relatively cheap** (map lookups, simple math).
- Dig sealing and persistent writes are batched via policy actions rather than per-event.
- JSONL appends and SQLite writes are sequential but typically low-latency.

Future optimizations can include:

- Async IO, sharding roots across threads or processes, and batched index writes.

---

## 30. How test-covered is the policy language and engine?

Evidence in code:

- `truthscript` has unit tests for JSON round-trip and rule construction.
- `policy_engine` has tests for rule matching, condition evaluation, and counter semantics.
- CLI commands like `policy-test` enable **manual and scripted testing** of real policy JSON files.

While this isn’t a full formal verification, it shows **non-trivial testing** of the most critical correctness core.

---

## 31. How does Ritma handle schema evolution for events and policies?

- Events use a `BTreeMap<String, Value>` for fields, where `Value` is an enum (String, Number, Bool).
- Policies refer to fields by string key.

This means:

- New fields can be added to events without breaking existing policies.
- Policies that reference missing fields simply see a default “no match” behavior.

For policies themselves, `truthscript::Policy` is a versioned struct (`version: String`), letting operators maintain multiple versions side-by-side.

---

## 32. How does Ritma support multi-tenant isolation in practice?

- Each tenant can have its own **root(s) of truth** (`StateOfTruthRoot`).
- `tenant_policy::Lawbook` binds tenant IDs to event rules and evidence requirements.
- Dig indices include tenant information, enabling tenant-scoped queries.
- DIDs and zones allow OS-level enforcement to honor tenant boundaries.

This provides the primitives required for a **multi-tenant governance plane**, even though a full control-plane service is not yet implemented.

---

## 33. What happens if a DigFile write or index update fails?

Current behavior (based on code patterns):

- Errors during DigFile persistence or index append are propagated up and logged.
- The operation that triggered the seal may return an error to the caller.

There is **no complex retry/compensation logic yet**, which is appropriate for an early production slice but something to harden later.

---

## 34. How do you query for “why was this denied?” in practice?

Using the existing tools:

1. Inspect `decision_events.jsonl` (or via `security_host` logs) to locate the relevant `DecisionEvent`.
2. Use `utl_cli` or `utl_forensics` to:
   - Filter dig index entries by `root_id`, `entity_id`, time, or policy decision.
   - Fetch the DigFile containing the relevant decision.
3. The DigFile contains `p_container` with `policy_decision`, `policy_rules`, and `policy_actions`.

So “why denied?” becomes “look up the decision in `DecisionEvent` and then see the exact policy that fired in the DigFile.”

---

## 35. How does Ritma integrate with existing SOC and SIEM tooling?

- **DecisionEvents** are JSONL, easily tail-able into SIEMs.
- **Forensics HTTP API** (`utl_forensics`) is suitable for:
  - Dashboards.
  - SOC workflows.
  - Automation retrieving evidence bundles.
- The **CLI** can be scripted in incident-response playbooks.

The design is **integration-friendly** rather than vertically integrated into a single UI.

---

## 36. What are the main technical risks or limitations today?

From code and README:

- Single-node `utld` with no built-in HA / clustering.
- Best-effort cryptographic verification (keys via env vars, skip-on-misconfig).
- Host agent `security_host` is mostly a **logging stub**, not wired to real firewall/cgroup backends.
- zkSNARKs and Distillium micro-proofs are **demonstrative** rather than production circuits / protocols.

These are all **tractable engineering tasks**, but important to call out in due diligence.

---

## 37. How hard would it be to port enforcement to a kernel module or eBPF?

The existing design helps:

- Policy evaluation and evidence management are **user-space** concerns.
- `security_os` traits define a clean boundary for OS-level controls.

A future architecture could:

- Keep Ritma (`utld`) as the policy/evidence brain.
- Implement `FirewallController` via kernel modules or eBPF programs that are **driven by DecisionEvents**.

So porting is more about building **new controllers** than rewriting Ritma’s core.

---

## 38. How does Ritma ensure forward compatibility of forensic data?

- DigFiles are **self-describing JSON** with stable field names and Merkle roots.
- The index stores both paths and minimal metadata.
- New fields can be added without breaking old readers.

This provides a robust base for **long-lived evidence** even as the surrounding system evolves.

---

## 39. How would you integrate Ritma into a typical microservices stack?

A likely integration pattern:

- Deploy `utld`, `utl_forensics`, and `security_host` as sidecar or infra services.
- Have each microservice:
  - Send `RecordTransition` events for security-relevant actions (auth, payments, AI calls, PII access).
  - Optionally sign transitions with an HMAC or key owned by the service.
- Use tenant-specific lawbooks to define allowed behaviors and required evidence.

This keeps application changes limited to **emitting structured transitions**, while Ritma handles policy and evidence.

---

## 40. What’s the story around cryptographic key management?

Currently:

- Keys like `UTLD_SIG_KEY` and `UTLD_DIG_SIGN_KEY` are passed via environment variables.
- There is no in-repo integration with HSMs or cloud KMS.

Future direction:

- Swap env vars for **KMS/HSM-backed key providers** and rotate keys automatically.

For now, Ritma assumes the **host environment** is responsible for secure key provisioning.

---

## 41. How does Ritma interoperate with different data formats (JSON, binary, etc.)?

- `data` is a raw byte payload; `TataFrame` embeds it as `Vec<u8>`.
- `p_container` is a string-based parameter bag.

This means:

- Applications can send either JSON, protobuf, or arbitrary binary as `data`.
- Policies operate on **parsed or summarized fields** injected into `p_container` by the client or a thin adapter layer.

---

## 42. How are time and ordering represented?

- `TimeTick::now()` captures logical time when a transition is recorded.
- DigRecords store this tick in `timeclock`.
- DigFiles record an overall time range (`time_start`, `time_end`).

Within a single root on a single node, this yields a **consistent total order** of events.

---

## 43. Can Ritma support real-time blocking in high-frequency environments?

Baseline capability:

- `Deny` actions can short-circuit `RecordTransition` and return a `NodeResponse` immediately.
- Overhead is primarily JSON parse + in-memory policy evaluation + simple hashing.

For very high-frequency (e.g. line-rate network), it would require:

- Native bindings or in-process SDKs to avoid JSON overhead.
- Possibly pre-compiled policies and more aggressive batching.

The core algorithms are suitable; the main work is **systems engineering and packaging**.

---

## 44. How does Ritma support explainability for AI or ML actions?

- Event kinds like `"ai_call"` can be modeled explicitly.
- Policies can:
  - Require `CaptureInput`/`CaptureOutput` for certain model or tenant IDs.
  - Require `UnknownLogicCapsule` for external model serving endpoints.
  - Require `Distillium` or zk proofs for specific high-risk workflows.
- DigFiles and index entries then serve as **explainable audit logs** for AI decisions.

This makes Ritma a good substrate for **AI governance and explainable security**.

---

## 45. How easy is it to extend TruthScript with new conditions or actions?

Steps, based on existing code patterns:

1. Add a new variant to the `Condition` or `Action` enum in `truthscript`.
2. Update serialization via serde (already tagged enums).
3. Extend `condition_matches` (for conditions) or `apply_engine_actions` (for actions) to implement new behavior.
4. Add tests and CLI support if needed.

Because the system is **strongly typed and centered on enums**, extensions are local and maintainable.

---

## 46. How does Ritma support partial adoption (record-only vs enforce+record)?

- If `UTLD_POLICY` is absent or configured in a permissive mode, Ritma can run as a **pure recorder**:
  - All transitions become DigRecords.
  - Policies may only request evidence, not denies.
- Over time, operators can tighten policies to introduce **deny rules** and advanced evidence requirements.

This phased adoption is important for real environments that cannot flip to hard enforcement on day one.

---

## 47. How is observability (logging, errors) handled inside Ritma?

- The code uses structured error types and propagates them up to CLI responses and logs.
- `security_host` logs every DecisionEvent in human-friendly form.
- Dig indices and DigFiles themselves are a form of **self-observability**, making many internal decisions externally inspectable.

More advanced metrics and tracing can be added, but the core **evidence layer doubles as observability**.

---

## 48. Are there any external dependencies that could be risky?

Key dependencies include:

- Rust standard ecosystem crates: `serde`, `clap`, `rusqlite`, crypto libraries (for HMAC, Groth16/BN254).
- No heavy external services are hard-wired; all storage is local FS + optional SQLite.

The main risks are **cryptographic library correctness** (standard in the ecosystem) and **standard FS/SQLite reliability**.

---

## 49. What is the typical developer workflow to add a new governed action?

Example:

1. Developer decides to govern a new action (e.g. “user exports PII”).
2. Application code emits a `RecordTransition` with `event_kind = "pii_export"` and relevant fields.
3. Operator writes or updates a TruthScript policy / tenant lawbook:
   - Adds rules matching `event_kind = "pii_export"`.
   - Requires evidence (`SealCurrentDig`, `CaptureOutput`, `MustLog`).
   - Optionally sets `Deny` for abnormal conditions.
4. Use `utl_cli policy-validate` and `policy-test` to sanity-check.
5. Roll out updated policy and monitor DecisionEvents/DigFiles.

This loop is **fast and code-light** on the application side, with most complexity in policy and evidence design.

---

## 50. From a technical due-diligence lens, what is the essence of Ritma’s moat?

Ritma already encodes, in real Rust code:

- A coherent **state of truth model** (roots, framed transitions, DigFiles).
- A **governance and evidence** fabric (TruthScript, lawbooks, Dig indices, entropy, unknown logic, proofs).
- A clear **integration path to OS controls** (security_host + security_os traits).

The moat is in combining **policy + forensics + cryptography + OS hooks** into a **unified runtime fabric** that can become the de facto **Universal Truth Layer for security** across different domains (hosts, SaaS, AI, compliance).
