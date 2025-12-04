# UTL Core Hardening Plan (v1.0)

This plan tracks hardening work for the Universal Truth Layer (UTL)
engine and daemon, targeting a **v1.0 readiness level** suitable for
serious pilot deployments.

Status legend:
- **[x]** Implemented in code
- **[~]** Partially implemented / planned
- **[ ]** Not yet started

---

## 1. Integrity & Cryptography

- **[x] Merkle trees via real library**  
  `dig_mem` uses `rs_merkle` to compute `.dig` Merkle roots.

- **[x] Distillium micro-proofs with arkworks**  
  `distillium` maps state hashes into BLS12-381 field elements via
  `ark-bls12-381` and `ark-ff` and stores them as `ZkProof` payloads.

- **[x] SNARK engine (Groth16/BN254)**  
  `zk_snark` crate implements a working Groth16 equality circuit and
  integration tests.

- **[x] Policy-driven SNARK invocation**  
  TruthScript `RequireSnarkProof` is wired in `utld` to run a real
  Groth16 proof (demo circuit).

- **[x] Atomic `.dig` writes with optional signing**  
  `.dig` files are written via temp-file + fsync + atomic rename. When
  `UTLD_DIG_SIGN_KEY` is set, an HMAC-SHA256 signature over the JSON is
  emitted as a separate `.sig` file.

- **[x] HMAC-based signature verification for transitions**  
  When `UTLD_SIG_KEY` is set, `utld` verifies `Sig` on
  `RecordTransition` requests using HMAC-SHA256 over a stable encoding of
  core fields. Invalid signatures are rejected.

- **[ ] Full SNARK circuits for `.dig` inclusion / state invariants**  
  Planned post-v1.0; current equality circuit is a working foundation.

---

## 2. Daemon & Persistence

- **[x] Structured error handling for `.dig` sealing**  
  Failures to seal or persist `.dig` now produce clear errors and do not
  silently drop data.

- **[~] Crash semantics documented and tested**  
  `.dig` is authoritative; in-memory `records` are ephemeral. Additional
  journaling or recovery indexing is planned.

- **[ ] Configurable rotation / retention policies**  
  Rotation by size/time and retention windows to be added.

---

## 3. Policy Engine & TruthScript

- **[x] Rich action set**  
  Includes `Deny`, `SealCurrentDig`, `RequireDistilliumProof`,
  `RequireSnarkProof`, `CaptureInput`, `CaptureOutput`, `RecordField`,
  `FlagForInvestigation`.

- **[x] Policy CLI tooling**  
  `utl` CLI provides `policy-validate` and `policy-test` to iterate
  safely on policies.

- **[x] Policy packs for common domains**  
  Example policies for AI audit, log hardening, and access audit live
  under `creat/policies/`.

- **[ ] Policy versioning / rollout strategies**  
  Future: tag `.dig` events with policy version and add offline
  re-evaluation tooling.

---

## 4. APIs, SDKs, and Gateways

- **[x] Rust SDK (utl_client)**  
  Thin client over `utld` Unix socket.

- **[x] CLI (utl)**  
  Roots, transitions, `.dig`, entropy, and policy test commands.

- **[x] HTTP gateway (utl_http)**  
  Exposes `/health`, `/roots`, `/transitions`, `/dig`, `/entropy`.

- **[x] TS/Node SDKs and demos**  
  `creat/ts-sdk/`, `creat/node-sdk/`, and multiple demos for AI, logs,
  and access audit.

- **[x] Python SDK**  
  `creat/python-sdk/utl_client.py` for Python services.

- **[x] Authenticated HTTP gateway**  
  `utl_http` enforces a bearer token (when `UTLD_API_TOKEN` is set) on
  all non-health endpoints. mTLS and finer-grained RBAC are planned.

---

## 5. Entropy & Anomaly Detection

- **[x] Entropy bins over `.dig` records**  
  `EntropyBin` and `EntropyHeapNode` compute simple local entropy
  metrics.

- **[~] Policy-integrated entropy thresholds**  
  Policies can already use `EntropyGreaterThan`; more calibrated
  thresholds and per-tenant baselines are planned.

- **[ ] Continuous entropy monitoring / alerting**  
  Future: scheduled entropy computations, alerts, and dashboards.

---

## 6. Security & Multi-Tenancy

- **[x] Structural support for signatures and zk**  
  `Sig`, `ZkArcCommitment`, `DistilliumMicroProof`, and Groth16
  integration.

- **[ ] Tenant tagging and isolation**  
  Future: explicit `tenant_id` in roots and transitions, and isolation
  in all storage and metrics.

- **[x] Authenticated HTTP gateway**  
  `utl_http` enforces a bearer token (when `UTLD_API_TOKEN` is set) on
  all non-health endpoints. mTLS and finer-grained RBAC are planned.

---

## 7. v1.0 Readiness Summary

For v1.0 we consider the following **must-have** items satisfied:

- Real Merkle and zk primitives wired into the engine.
- Atomic, signed `.dig` persistence.
- Optional but real signature verification path for transitions.
- Policy engine with strong enforcement hooks in `utld`.
- Multi-language SDKs and gateway for practical integration.

The remaining items (auth/RBAC, advanced SNARK circuits, entropy
analytics, and multi-tenant ops) are tracked for v1.1+.
