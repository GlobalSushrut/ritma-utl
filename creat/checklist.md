# UTL Enterprise Readiness Checklist

This checklist tracks the implementation level of the Universal Truth Layer
(UTL + .dig + TruthScript + Handshake + Micro‑proofs) against enterprise use
requirements.

Legend:
- **[x]** Implemented in this repo (initial version)
- **[~]** Partially implemented – architecture + some code, needs expansion
- **[ ]** Not yet implemented – planned in `arch.md`

---

## 1. Core Truth Layer

- **[x] State of Truth Root (SoT)**  
  Crate: `sot_root` – `StateOfTruthRoot`, `RootParams`, `TransitionHookId`.

- **[x] Universal Clock & Handshake**  
  Crates: `clock`, `handshake` – `TimeTick::now()`, `TransitionHandshake`.

- **[x] TATA Frames (Hashed Polar Container)**  
  Crate: `tata` – `TataFrame<D>` + `content_hash()`.

- **[x] Merkle Memory & .dig Structures**  
  Crate: `dig_mem` – `DigRecord`, `DigFile`, leaf hashing, Merkle root.

- **[x] Entropy Bins & Heap**  
  Crate: `entropy_tree` – `EntropyBin` with `local_entropy`, `EntropyHeapNode`.

- **[x] Unknown Logic Capsule**  
  Crate: `tracer` – `BridgeInfo`, `UnknownLogicCapsule` with input/output snapshots.

- **[~] Distillium Micro‑Proofs**  
  Status: architected in `arch.md`, not yet coded as a crate.

- **[~] Trust Agreement Container**  
  Status: architected in `arch.md`, not yet coded as a crate.

---

## 2. Node Daemon & Event Pipeline

- **[x] Node Engine (UtlNode)**  
  Crate: `utld::lib` – manages SoT roots, `DigRecord`s, entropy bins, capsules.

- **[x] Daemon Process (`utld` binary)**  
  Crate: `utld::bin` – Unix domain socket server with JSON protocol.

- **[x] JSON Protocol (NodeRequest/NodeResponse)**  
  Operations: register_root, record_transition, build_dig_file, build_entropy_bin, list_roots.

- **[~] Persistent `.dig` File Writing**  
  Status: structures + Merkle implemented; file IO/rotation not yet wired into `utld`.

- **[ ] OS/Container Hooks (cgroups, namespaces, eBPF)**  
  Status: defined in `arch.md` as Phase 2; no kernel/cloud agent yet.

---

## 3. Programmable Compliance & Policy (TruthScript)

- **[x] TruthScript Policy IR**  
  Crate: `truthscript` – `Policy`, `Rule`, `When`, `Condition`, `Action` with JSON serialization.

- **[x] Policy Engine**  
  Crate: `policy_engine` – `PolicyEngine` with counters, `EngineEvent`, `EngineAction`.

- **[x] Daemon–Policy Wiring**  
  Crate: `utld::bin` – loads policy from `UTLD_POLICY` JSON, evaluates `RecordTransition` events.

- **[x] Hard Enforcement Path (Deny)**  
  A `Deny` action in policy returns `NodeResponse::Error` and prevents state mutation.

- **[~] Enforcement of Advisory Actions**  
  `SealCurrentDig`, `RequireDistilliumProof`, `RequireUnknownLogicCapsule`, etc.  
  Currently logged; must be wired into concrete `UtlNode` behavior and `.dig`/proof machinery.

- **[ ] Textual TruthScript Parser**  
  Current implementation uses JSON IR; text DSL from `arch.md` still to be implemented.

---

## 4. Security, Identity, and Multi‑Tenancy

- **[~] Signature Handling**  
  `TransitionHandshake` includes `Sig` type; signing/verification & key mgmt not implemented.

- **[ ] Identity / RBAC Integration**  
  No direct tie‑in to SSO, IAM, or per‑tenant roles yet.

- **[ ] Per‑Tenant Isolation**  
  Design supports SoT per namespace/cgroup; code still needs cloud/OS modules.

---

## 5. Observability, Tooling, and UX

- **[x] Basic Logging**  
  Daemon prints policy actions and JSON errors to stderr; suitable for early dev.

- **[~] Metrics & Health Probes**  
  No Prometheus/health endpoints yet; will be required for production.

- **[~] Forensic Replay Tools**  
  `.dig` structures and Merkle roots exist; replay/visualization tooling not yet implemented.

- **[ ] Auditor & SRE UI**  
  No web dashboard / UI at this stage.

---

## 6. Compliance / Domain Rulepacks

- **[~] Generic Rule Engine**  
  TruthScript/policy_engine can express HIPAA/GDPR/AI rules conceptually.

- **[ ] Domain‑Specific Rulepacks**  
  No prebuilt HIPAA, GDPR, SOC2, AI safety policies yet.

---

## 7. Enterprise Readiness Gaps To Code Next

1. **Implement `distillium` crate**
   - DistilliumMicroProof struct + hash‑based proofs over SoT + frames.
   - Integration hooks from utld when policies require proofs.

2. **Implement `trust_container` crate**
   - TrustAgreementContainer struct + helpers to bind SLAs/workflows to proof chains.

3. **Add `.dig` file IO and rotation**
   - Methods on `DigFile` to persist to disk (JSON/binary) under `UTLD_DIG_DIR`.
   - Rotation by time/size, with external anchors (signatures or ledgers).

4. **Wire advisory policy actions into behavior**
   - `SealCurrentDig` → trigger `.dig` seal + write.  
   - `RequireDistilliumProof` → call into distillium module.  
   - `RequireUnknownLogicCapsule` → enforce capsule presence on transitions.

5. **Add tests across crates for invariants**
   - Merkle consistency, SoT immutability, policy enforcement, denial behavior.

This file should be updated as we close gaps and move capabilities from **[~]** to
**[x]**.
