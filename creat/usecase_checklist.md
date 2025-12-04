# UTL Practical Use-Case Checklist

This document translates the Universal Truth Layer (UTL) into concrete,
enterprise-ready product surfaces: **API**, **CLI**, **SDKs**, and
**integrations**.

Legend:
- **[x]** Core engine capability implemented
- **[~]** Partially implemented; needs productization
- **[ ]** Not implemented yet

---

## 1. Priority Use Cases to Productize

These are the first flows we should expose via API/CLI/SDK.

### 1.1 AI Decision Audit Logs (Explainability)
- **Goal**: For each AI decision, record an immutable trace of
  `inputs → model → outputs → policy decisions`.
- **Capabilities required**
  - **[x]** TATA frames and `.dig` records per decision.
  - **[x]** Policy rules for fairness/safety (`truthscript` + `policy_engine`).
  - **[~]** API/SDK hooks to wrap model calls.
  - **[~]** CLI to inspect decisions and proofs.
- **Enterprise fit**
  - Proves why a decision was made (auditable trace).
  - Hooks into existing AI services via SDKs.

### 1.2 Zero-Tamper Logging for Compliance
- **Goal**: Replace or augment app logs with `.dig` Merkle logs and
  optional zk/micro-proofs.
- **Capabilities required**
  - **[x]** `.dig` structures + Merkle roots (now using `rs_merkle`).
  - **[x]** `SealCurrentDig` policy action + disk persistence.
  - **[~]** API for apps to send logs/events.
  - **[~]** CLI to rotate, export, and verify `.dig` files.
- **Enterprise fit**
  - Directly solves tampering risks for SOC2/SOX/HIPAA.

### 1.3 Medical / Sensitive Data Access Audit
- **Goal**: Record every access to a protected record (e.g. patient or
  customer) with strong proofs.
- **Capabilities required**
  - **[x]** TATA frames per access, SoT roots per service.
  - **[~]** Domain-specific tagging in `p_container` (user id, record id).
  - **[ ]** Pre-built policies for HIPAA/GDPR.
  - **[~]** CLI/query tools for auditors.
- **Enterprise fit**
  - Answers "who accessed what, when, under which policy".

### 1.4 Software Supply Chain / Runtime Integrity
- **Goal**: Prove which binary/config ran in prod and bind it to
  observed behavior.
- **Capabilities required**
  - **[x]** SoT roots for binaries/configs.
  - **[x]** Transition records tied to those roots.
  - **[ ]** CI/CD integration and CLI commands for attestation.
- **Enterprise fit**
  - Supports compliance and incident postmortems.

### 1.5 Policy-Enforced Security (Runtime Guardrails)
- **Goal**: Use TruthScript rules to block risky actions and trigger
  `.dig` sealing + proofs.
- **Capabilities required**
  - **[x]** `Deny`, `SealCurrentDig`, `RequireDistilliumProof`,
    `RequireSnarkProof` wired into `utld`.
  - **[~]** API/CLI to load/test policies and simulate effects.
- **Enterprise fit**
  - Real-time enforcement aligned with regulations and internal guardrails.

---

## 2. Product Surfaces Checklist

For each surface, we track what is needed for enterprise readiness.

### 2.1 Node API (Daemon Interface)
- **Shape**
  - **[x]** JSON-over-UNIX-socket protocol (`NodeRequest`/`NodeResponse`).
  - **[ ]** Network API (REST/gRPC) gateway for remote clients.
- **Requirements**
  - **[ ]** Versioned schema & OpenAPI/proto definitions.
  - **[ ]** AuthN/AuthZ (mTLS, JWT, or API keys).
  - **[ ]** Multi-tenant isolation (tenant in every call).

### 2.2 CLI (Operator & Auditor)
- **Binary**: `utl` or `utldctl`.
- **Capabilities**
  - **[ ]** Connect to `utld` over socket/HTTP.
  - **[ ]** Commands:
    - `root register` – register a StateOfTruthRoot.
    - `tx record` – send a RecordTransition (for testing/manual ops).
    - `dig seal` / `dig list` / `dig verify` – manage `.dig` files.
    - `policy load` / `policy test` – manage TruthScript policies.
    - `audit query` – filter events by entity, root, time.
- **Enterprise fit**
  - Fits into SRE/infosec workflows; usable in CI and incident response.

### 2.3 SDKs (Application Integration)
- **Languages (phased)**
  - **[ ]** Rust SDK (thin wrapper over daemon API; used internally).
  - **[ ]** TypeScript/Node SDK.
  - **[ ]** Python SDK.
- **Core SDK features**
  - Easy `with_utl` wrapper for:
    - **AI decisions**: `with_utl_ai_call(model, input, context)`.
    - **Data access**: `with_utl_access(record_id, actor, action)`.
  - Built-in retry, backpressure, and batching.
  - Structured error types and policy-denial handling.

### 2.4 Integration Hooks
- **[ ]** Database hooks (e.g. Postgres logical decoding → utld).
- **[ ]** Log shippers (e.g. sidecar that forwards logs to utld).
- **[ ]** K8s/node agents for container SoT roots.

---

## 3. Enterprise Fit Checklist

High-level dimensions to satisfy for a production UTL deployment.

### 3.1 Security & Compliance
- **[ ]** AuthN/AuthZ for all API calls.
- **[ ]** Role-based access for `.dig` reads vs writes.
- **[ ]** Key management guidance (signatures, SNARK keys).
- **[ ]** Data-at-rest encryption and secure key storage.

### 3.2 Reliability & Operations
- **[ ]** Health/Liveness endpoints for `utld`.
- **[ ]** Metrics (Prometheus) for throughput, latency, failures.
- **[ ]** Configurable retention & rotation for `.dig`.
- **[ ]** Backup/restore procedures for `.dig` and configs.

### 3.3 Performance & Scalability
- **[ ]** Benchmarks for typical workloads (AI calls, logs/sec).
- **[ ]** Sharding or multi-node layout for `utld`.
- **[ ]** Batching of events in SDKs.

### 3.4 Developer Experience
- **[ ]** Clear quickstart for each SDK.
- **[ ]** Example policies and sample apps (AI audit, log hardening).
- **[ ]** Error messages that surface policy denials clearly.

---

## 4. Execution Plan (High-Level)

1. **Stabilize Protocol and Network API**
   - Freeze `NodeRequest`/`NodeResponse` JSON schema.
   - Add HTTP/REST gateway on top of `utld`.

2. **Build CLI (`utl` / `utldctl`)**
   - Focus on: register root, record tx, seal/list/verify `.dig`, load/test policy.

3. **Implement Rust SDK**
   - Target use cases 1.1 (AI decisions) and 1.2 (zero-tamper logs) first.
   - Provide wrappers that call into the daemon or HTTP gateway.

4. **Implement TypeScript and Python SDKs**
   - Mirror Rust SDK surface where possible.

5. **Ship Example Use-Case Bundles**
   - AI decision audit demo.
   - Compliance log hardening demo.
   - Medical access audit demo.

This checklist should drive which crates, binaries, and examples we
implement next.
