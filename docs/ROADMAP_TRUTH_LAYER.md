# Ritma: Truth-Layer Roadmap (Engineering)

This roadmap is **code-grounded**: every item names the authoritative module(s) and has objective acceptance criteria.

This document is intended to be the **single execution plan** for turning the current repo into a production-grade, universal “Truth Layer” cybersecurity tool.

## Scope and Definitions

### Authoritative product binary

- The product CLI is `crates/ritma_cli` (binary name: `ritma`).
- Any other CLI in this workspace must either:
  - be routed/aliased into `ritma_cli`, or
  - be explicitly labeled as legacy/experimental.

### What “Truth Layer” means (non-negotiable)

A truth artifact must satisfy:

- **Evidence-first**: claims must map to artifacts written to disk.
- **Tamper-evident**: modifications are detectable offline.
- **Portable verification**: verification works on an air-gapped machine.
- **Non-custodial by default**: store hashes/redactions by default; raw payloads are explicit opt-in.
- **Diffable continuity**: windows are diffable and explainable.

### Not in scope (unless explicitly added)

- Real-time threat blocking by default.
- Threat actor attribution.

## Current Reality (baseline)

### Implemented today

- Docker-operable baseline UX exists: `up/down/ps/logs/restart` in `crates/ritma_cli/src/main.rs`.
- ProofPack sealing + offline integrity verification exists (hash completeness) in `crates/ritma_cli/src/main.rs`.
- Runtime window pipeline exists in `crates/bar_orchestrator/src/lib.rs`.
- Tracer sidecar exists in `crates/tracer_sidecar/src/main.rs` (auditd tail + /proc/net/tcp scan).
- CI exists with: tests, clippy, fmt, audit, deny, docker builds, basic e2e in `.github/workflows/ci.yml`.

### Known “half-done” seams

- `bar_orchestrator` uses `ProofManager::with_noop_backend()` and returns `proof_type = "noop"`.
- `bar_orchestrator` inserts synthetic receipt refs (`noop_r_*`) for continuity.
- Compliance pipeline / CUE integration contains stubs:
  - `crates/policy_engine/src/cue_integration.rs`
  - `crates/policy_engine/src/compliance_pipeline.rs`
- K8s operational parity is incomplete: some `--mode k8s` commands return “not implemented yet”.

## Infra Reality Map (authoritative code pointers)

This section links the roadmap to the **actual infra implementation** in `crates/ritma_cli/src/main.rs`.

### Command → function map

| CLI surface | Function(s) | Notes / current constraints |
|---|---|---|
| `ritma init` | `cmd_init`, `write_compose_bundle`, `compose_variant_paths` | Writes compose v1/v2 variants and a pointer file; k8s mode writes manifests to `./k8s/`. |
| `ritma up` | `cmd_up`, `ensure_compose_compatible` | Docker: compose v2/v1 preferred, else “minimal fallback” via `docker run`; k8s: `cmd_up_k8s` applies `./k8s/`. |
| `ritma down` | `cmd_down` | `--mode k8s` currently returns `k8s down not implemented yet`. |
| `ritma ps` | `cmd_ps`, `docker_ps_names` | Docker uses `docker ps`; k8s parity is not yet implemented. |
| `ritma logs` | `cmd_logs` | `--json` not supported; `--mode k8s` not implemented. |
| `ritma restart` | `cmd_restart` | `--mode k8s` not implemented. |
| `ritma status` | `cmd_status`, `detect_capabilities`, `detect_runtime_state` | Has JSON output including capabilities and next steps. |
| `ritma doctor` | `cmd_doctor` | Has readiness scoring; checks host + container volume visibility for `index_db`. |
| `ritma deploy …` | `cmd_deploy_export`, `cmd_deploy_k8s`, `cmd_deploy_systemd`, `cmd_deploy_status` | Deploy export writes compose + k8s + systemd artifacts; deploy k8s applies manifests; deploy status reports docker/k8s/systemd. |
| `ritma upgrade` | `cmd_upgrade` | `--mode k8s` prints “not yet implemented” and falls back to `cmd_up_k8s`. |

### Infra Gap Register (must be eliminated or explicitly quarantined)

- `cmd_logs`: `--json` is not supported.
- `cmd_logs`: `--mode k8s` is not implemented.
- `cmd_down`: `--mode k8s` is not implemented.
- `cmd_restart`: `--mode k8s` is not implemented.
- `cmd_upgrade`: `--mode k8s` is not a real upgrade flow (currently routes to `cmd_up_k8s`).

### Port / Proxy / Auth hardening gaps (industry-readiness)

- Port exposure is not yet treated as an explicit contract across docker/k8s/systemd.
- UTLD is currently published/exposed on port `8088` in templates and Dockerfile, but UTLD’s default listener is unix-socket (`UTLD_SOCKET`) unless a TCP/TLS listener is enabled at runtime (feature `tls` + `UTLD_TLS_ADDR`). This must be made consistent (either enable a real listener or stop publishing the port).
- Proxy boundary behavior is not yet standardized:
  - templates do not explicitly set a safe `NO_PROXY` baseline for in-cluster/local service names.
- Authentication isolation is not yet expressed as a deployment contract:
  - UTLD mTLS env knobs exist (`UTLD_MTLS_*`), but deployment templates/systemd do not define a standard “when TCP is enabled, TLS+mTLS is required” rule.

### Operational side-effects (must be made explicit and tested)

- `ensure_compose_compatible()` may remove docker containers named `bar_daemon`, `utld`, `tracer_sidecar`, `bar_orchestrator` when it finds `container_name:` directives in compose files.
- Any roadmap item that modifies compose generation or compatibility patching must include tests validating safe behavior.

## Artifact Contracts (infra outputs that must remain stable)

### Compose bundle contract

Generated by `write_compose_bundle()`:

- Pointer file: `ritma.sidecar.yml`
- Variants:
  - `ritma.compose.v1.yml` (version downgraded to `3.3` for legacy docker-compose)
  - `ritma.compose.v2.yml` (version `3.9`)

### Deploy export contract

Generated by `cmd_deploy_export()`:

- `deploy-out/ritma.sidecar.yml`
- `deploy-out/ritma.compose.v1.yml`
- `deploy-out/ritma.compose.v2.yml`
- `deploy-out/k8s/*.yaml`
- `deploy-out/ritma-security-host.service`

Any change to these names/paths must be treated as a breaking UX change and requires an explicit migration note.

## Security/Boundary Contracts (must be explicit)

These are not “new features”; they are deployment correctness and safety contracts.

- **Ports**: only publish ports that have real listeners and explicit auth boundaries.
- **Routes**: orchestrator-to-UTLD route is explicit and consistent across docker/k8s.
- **Proxy**: when proxy env vars are present, internal traffic remains local (requires explicit `NO_PROXY`).
- **Auth**:
  - unix-socket permissions are `0660` (already implemented in UTLD/BAR daemon)
  - if TCP listeners exist, TLS+mTLS must be the default.

## Canonical Smoke Paths (must work at all times)

These command sequences must remain valid and are the minimum acceptance paths.

### Smoke path A (developer / local)

1. `cargo run -p ritma_cli -- status`
2. `cargo run -p ritma_cli -- doctor`
3. `cargo run -p ritma_cli -- demo --window-secs 10`
4. `cargo run -p ritma_cli -- export report --namespace ns://demo/dev/hello/world --start <t0> --end <t1> --out ./ritma-report`

### Smoke path B (runtime baseline)

1. `cargo run -p ritma_cli -- init --output ritma.sidecar.yml --namespace ns://demo/dev/hello/world --mode docker`
2. `cargo run -p ritma_cli -- up --compose ritma.sidecar.yml --mode docker`
3. `cargo run -p ritma_cli -- ps --mode docker`
4. `cargo run -p ritma_cli -- logs --mode docker --tail 200`
5. `cargo run -p ritma_cli -- down --mode docker --compose ritma.sidecar.yml`

## Execution Plan (Milestones)

Only one milestone should be “in progress” at a time.

### Milestone 0 — Single Source of Truth for the CLI

**Goal**: eliminate “wrong binary” confusion and ensure the intended command tree is stable.

- **Targets**:
  - `crates/ritma_cli/src/main.rs`
  - Workspace crates that produce CLIs (e.g., `crates/ritma`, `crates/utl_cli`) for naming/positioning.

- **Tasks**:
  - Ensure `ritma_cli` is the only recommended `ritma` entrypoint.
  - Add explicit messaging and/or rename other binaries if they currently produce confusing UX.

- **Acceptance**:
  - `cargo run -p ritma_cli -- --help` exposes the full intended UX tree.
  - A developer following README commands cannot accidentally run a different `ritma` binary.
  - `ritma status` and `ritma doctor` remain the first two commands for any operator, and must not regress.

- **Tests**:
  - Add a CI smoke test that runs `cargo run -p ritma_cli -- --help` and checks for presence of core verbs.

### Milestone 1 — Truth Core: Signed, Offline-Verifiable Bundles

**Goal**: exported artifacts are both integrity-verifiable and authenticity-verifiable.

- **Targets**:
  - `crates/ritma_cli/src/main.rs` (export + verify)
  - `crates/evidence_package/*` (signing/verifying primitives)
  - `crates/node_keystore/*` (key source)

- **Tasks**:
  - Add signature support to exported ProofPacks/bundles:
    - sign `manifest.json` (or a canonical hash of it)
    - store signature + algorithm + key id + public key/DID in the bundle
  - Extend `ritma verify` to validate:
    - hashes and completeness (existing)
    - signature authenticity (new)

- **Acceptance**:
  - Mutating any artifact causes `ritma verify <bundle>` to fail offline.
  - Verification does not require network access.
  - Artifacts include algorithm identifiers (crypto agility).
  - `ritma verify --json` output format is stable (field names and exit codes) for automation.

- **Required tests**:
  - Mutation tests:
    - modify one byte in an artifact → verify fails
    - remove one artifact → verify fails
    - swap receipts/public_inputs.json → verify fails

### Milestone 2 — Eliminate Demo-Only Truth (No Synthetic Chain, No Noop Proofs)

**Goal**: no fabricated continuity and no noop proof paths in non-demo mode.

- **Targets**:
  - `crates/bar_orchestrator/src/lib.rs`

- **Tasks**:
  - Remove or hard-gate synthetic receipt ref insertion:
    - the `noop_r_*` insertion in `PipelineOrchestrator::run_window()`
  - Replace `ProofManager::with_noop_backend()` with a real proof/signature strategy OR gate behind demo.

- **Acceptance**:
  - In non-demo mode:
    - no synthetic receipt refs are created
    - no `proof_type = "noop"` is produced

- **Tests**:
  - Add a test that asserts non-demo builds do not emit synthetic receipts.

### Milestone 3 — Canonical Ingestion: Real Adapters into One Truth Event Model

**Goal**: multiple domains feed the same canonical event schema and can be replayed deterministically.

- **Targets**:
  - `common_models::{TraceEvent, DecisionEvent, Verdict, MLScore, EvidencePackManifest, ProofPack}`
  - `crates/tracer_sidecar/src/main.rs`
  - `crates/middleware_adapters/*` (e.g., HTTP)
  - `crates/index_db/src/lib.rs`

- **Tasks**:
  - Declare an authoritative “truth envelope”:
    - system-plane events (host/k8s/network) and app-plane events (gateway/http/identity)
  - Require adapters to emit canonical events with stable fields.
  - Ensure privacy mode is enforced by adapters (hash-only defaults).

- **Acceptance**:
  - Replaying the same adapter inputs yields identical canonicalized events and stable hashes.

- **Tests**:
  - Golden-file tests for canonical event serialization.

### Milestone 4 — Window Correlation & Attack Graph Determinism

**Goal**: same window inputs yield same summaries/graphs/hashes across machines.

- **Targets**:
  - `crates/bar_orchestrator/src/lib.rs` (`correlate_window`)
  - `crates/attack_graph/*`
  - `crates/index_db/src/lib.rs` (edges + summaries)

- **Tasks**:
  - Remove in-memory DB use inside correlation:
    - eliminate `IndexDb::open(":memory:")` usage in the graph builder path.
  - Make window IDs canonical and stable.

- **Acceptance**:
  - `attack_graph_hash` remains stable given identical inputs.

- **Tests**:
  - Determinism test: run correlation twice with same event fixtures → identical output hashes.

### Milestone 5 — Operational Parity (Docker + K8s)

**Goal**: “Docker-standard” UX works for both docker and Kubernetes modes.

- **Targets**:
  - `crates/ritma_cli/src/main.rs` (`cmd_up/cmd_down/cmd_ps/cmd_logs/cmd_restart`)

- **Tasks**:
  - Implement missing k8s operations:
    - `down/logs/restart/ps` for `--mode k8s`
  - Improve capability detection and error messages:
    - “kubectl missing”, “namespace missing”, “cluster unreachable”
  - Add k8s parity for `ritma deploy status` narratives (ensure `next` is meaningful for k8s).

- **Acceptance**:
  - A user can operate Ritma in k8s with the same muscle-memory verbs.

- **Tests**:
  - E2E tests should validate command behavior surfaces consistent errors when no cluster is available.

### Milestone 6 — Compliance/Policy: Real or Explicitly Experimental

**Goal**: stop shipping stubbed compliance as real; either implement it fully or hide it.

- **Targets**:
  - `crates/policy_engine/src/cue_integration.rs`
  - `crates/policy_engine/src/compliance_pipeline.rs`
  - `crates/utl_cue/*`
  - `crates/compliance_*/*`

- **Tasks (Option A: Implement)**:
  - Load real CUE config via `utl_cue`.
  - Replace stage stubs with actual evaluation and evidence emission.

- **Tasks (Option B: Quarantine)**:
  - Gate compliance commands behind feature flags.
  - Mark as experimental in help output.

- **Acceptance**:
  - No command outputs “allow/pass” for compliance unless computed from real policy + real evidence.

## Acceptance Tests (Global)

These must pass before calling the project “truth-layer complete”:

- **Offline verification**: copy exported bundle to a fresh machine → `ritma verify` succeeds.
- **Tamper detection**: mutate one byte in any artifact → verify fails.
- **Completeness**: remove a file listed in manifest → verify fails.
- **Privacy mode**:
  - hash-only mode never exports raw sensitive identifiers by default.
- **Determinism**:
  - identical event inputs produce identical hashes and stable artifact layouts.

## CI/Test Matrix (must align with roadmap)

### Existing CI coverage

- `cargo test --workspace --locked`
- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo audit` and `cargo deny check`
- Docker image builds
- E2E (current): `doctor` + `demo` only

### Missing CI gates (required for “truth layer” claims)

- Offline verify E2E: generate an export bundle in CI, copy to a temp dir, run `ritma verify`.
- Mutation E2E: mutate one exported artifact and assert `ritma verify` fails.
- Determinism E2E: run the same seed window twice and assert stable hashes for canonical outputs.

## PR Sequencing (recommended execution order)

This section translates milestones into PR-sized batches.

1. PR-0: CLI authority hardening (entrypoint clarity; smoke test for `--help` command tree)
2. PR-1: Signed manifest + signature verification (minimum crypto truth)
3. PR-2: Verify JSON stability + exit-code contract
4. PR-3: Remove/gate synthetic receipts and noop proofs in non-demo mode
5. PR-4: Deterministic correlation fixes (remove in-memory DB usage in attack graph path)
6. PR-5: K8s parity for `ps/logs/down/restart`
7. PR-6: CI adds offline-verify + mutation + determinism gates

## Decision Points (must be explicitly chosen, not implicit)

- Proof strategy (near-term): signatures + merkle roots vs other proof types.
- Receipt continuity source of truth: UTLD receipts vs orchestrator-derived continuity.
- Privacy baseline: `hash-only` default vs raw mode opt-in semantics.

## Recommended Development Commands

- Build:
  - `cargo build --workspace --locked`
- Run product CLI:
  - `cargo run -p ritma_cli -- <command>`
- Tests:
  - `cargo test --workspace --locked`

## Done Criteria

This roadmap is considered complete when:

- ProofPacks and bundles are signed and verifiable offline.
- No demo-only truth (synthetic receipts, noop proofs) appears in production paths.
- Ingestion adapters can feed canonical events across multiple domains.
- Window correlation outputs are deterministic and diffable.
- Docker and K8s operational UX are both complete for core verbs.
