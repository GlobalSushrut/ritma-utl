# Ritma Truth Layer — Coding Playbook (Guide Book)

This is a **coding checklist** and execution guide for implementing `docs/ROADMAP_TRUTH_LAYER.md` safely.

Rules for this playbook:

- Every checklist item must be:
  - tied to a concrete file/module/function, and
  - validated by a test or an objective acceptance command.
- No “demo truth” ships in production paths.
- No merge without CI passing.

## 0) How to run the authoritative CLI during development

Recommended:

```bash
alias ritma='cargo run -p ritma_cli --'
```

Sanity:

```bash
ritma status
ritma doctor
```

## 1) Definition of Done (global)

The project is “truth-layer complete” only when all are true:

- Exported bundles are **signed** and **verifiable offline**.
- Any mutation/removal of an exported artifact causes `ritma verify` to fail.
- No synthetic continuity or noop proofs appear in non-demo mode.
- Determinism: identical inputs → identical hashes and stable outputs.
- Docker and K8s parity for operator verbs: `up/down/ps/logs/restart/status/doctor`.

## 1.1) Industry Solidification Checklist (no new product features)

This checklist is about making existing capabilities **sharp, stable, and industry-usable**. It does not add new product scope; it eliminates ambiguity, stubs, and unstable behavior.

### A) CLI stability and unambiguous entrypoint

- [x] **One authoritative binary**
  - **Target**: `crates/ritma_cli` (binary `ritma`)
  - **Acceptance**: ✓ `cargo run -p ritma_cli -- --help` includes all core verbs.

- [ ] **Backwards-compatible routing remains correct**
  - **Target**: `crates/ritma_cli/src/main.rs` (command routing in `main()`)
  - **Acceptance**:
    - legacy aliases (`export-proof`, `export-incident`, `verify-proof`, etc.) route to the umbrella commands consistently.

### B) Infra UX: predictable operator verbs (Docker + K8s)

- [x] **`status` is stable and machine-readable**
  - **Target**: `cmd_status`, `detect_capabilities`, `detect_runtime_state`
  - **Acceptance**: ✓ `ritma status --json` emits stable keys: `capabilities`, `runtime`, `next`, `status`

- [x] **`doctor` is stable and action-guiding**
  - **Target**: `cmd_doctor`
  - **Acceptance**: ✓ `ritma doctor --json` emits stable keys: `score`, `blockers`, `fix`, `verify`, `port_conflicts`

- [ ] **K8s parity removes “not implemented yet” for core verbs**
  - **Targets**: `cmd_down`, `cmd_logs`, `cmd_restart`, `cmd_ps` (k8s mode)
  - **Acceptance**: `--mode k8s` works for `down/logs/restart/ps`, or fails with precise capability guidance.

- [ ] **Eliminate surprising side effects in compose patching**
  - **Target**: `ensure_compose_compatible()`
  - **Acceptance**:
    - container cleanup behavior is explicit in user output or gated to only act on containers created by Ritma.
    - tests exist to ensure it does not delete unrelated containers.

### C) Artifact stability and verification (no “trust me”)

- [x] **Canonical JSON is deterministic**
  - **Target**: `write_canonical_json()`
  - **Acceptance**: ✓ Tests in `tests/integration/test_canonical_json.rs`

- [ ] **ProofPack sealing is strict and complete**
  - **Targets**: `seal_manifest_and_proofpack()`, `iter_pack_files_for_manifest()`, `verify_manifest_artifacts()`
  - **Acceptance**:
    - sealed packs fail verification if any unmanifested file exists.
    - sealed packs fail verification if any manifested file is missing or hash-mismatched.

- [ ] **Verify output is automation-safe**
  - **Target**: `cmd_verify_proof` / `verify_proofpack_silent`
  - **Acceptance**: `ritma verify --json` is stable and includes:
    - expected vs actual hashes
    - sealed status
    - missing required fields

### D) Remove demo-only truth from non-demo paths

- [ ] **No synthetic receipts in production runs**
  - **Target**: `crates/bar_orchestrator/src/lib.rs` (`PipelineOrchestrator::run_window`) `noop_r_*` insertion
  - **Acceptance**: synthetic continuity is either removed or explicitly gated behind a demo flag.

- [ ] **No noop proofs in production runs**
  - **Target**: `crates/bar_orchestrator/src/lib.rs` (`ProofManager::with_noop_backend()`)
  - **Acceptance**: production sealing uses a real authenticity primitive (signature-backed minimum).

### E) CI hardening (industry standard)

- [ ] **E2E must prove offline verification**
  - **Target**: `.github/workflows/ci.yml`
  - **Acceptance**:
    - CI exports a bundle/proofpack, copies it to a temp directory, and `ritma verify` succeeds.

- [ ] **E2E must prove tamper detection**
  - **Target**: `.github/workflows/ci.yml`
  - **Acceptance**: CI mutates a file in the exported artifact and `ritma verify` fails (nonzero).

### F) Container / Network / OS engineering solidification (Docker + K8s + systemd)

This section is specifically about hardening what already exists in:

- Docker compose generation: `write_compose_bundle()`
- Compose compatibility patching: `ensure_compose_compatible()`
- K8s templates: `k8s_manifest_bundle()`
- systemd generation: `systemd_unit_template()`
- Runtime UX: `cmd_up/cmd_down/cmd_ps/cmd_logs/cmd_restart/cmd_status/cmd_doctor`

#### F1) Docker/Compose runtime correctness

- [x] **Compose file contract stays stable and is self-consistent**
  - **Targets**:
    - `write_compose_bundle()`
    - `compose_variant_paths()`
  - **Acceptance**:
    - ✓ `ritma init` writes `<base>.compose.v1.yml`, `<base>.compose.v2.yml`, `<base>.sidecar.yml`

- [ ] **No silent destructive side-effects**
  - **Target**: `ensure_compose_compatible()`
  - **Acceptance**:
    - If container cleanup is performed, it is either:
      - limited to containers created by Ritma in the current project, or
      - loudly announced in CLI output before taking action.
    - Add a regression test or documented safety rule so unrelated containers are never removed.

- [ ] **Network and ports are explicit and conflict-safe**
  - **Targets**:
    - compose templates produced by `write_compose_bundle()`
    - `docker/compose.sidecar.yml`
  - **Acceptance**:
    - Ports exposed are intentional and documented:
      - UTLD `8088`
      - BAR health `8090`
    - If ports are already in use, `ritma up` fails with a fix chain (not raw docker output).

- [ ] **Privileged/host mounts are minimal and intentional**
  - **Targets**:
    - `write_compose_bundle()` tracer section
    - `docker/compose.sidecar.yml` tracer section
  - **Acceptance**:
    - Minimal baseline (`utld + bar-daemon`) does not require privileged mode.
    - Full baseline (tracer/orchestrator) clearly declares required mounts and privileges:
      - audit log mount (`/var/log/audit`)
      - `/proc` mount (if needed)
      - `/sys/fs/bpf` mount (if eBPF-ready mode is claimed)

#### F2) Kubernetes manifests correctness and operational parity

- [x] **K8s manifests include required mounts and env vars**
  - **Target**: `k8s_manifest_bundle()`
  - **Acceptance**:
    - ✓ tracer DaemonSet sets: `NAMESPACE_ID`, `AUDIT_LOG_PATH`, `INDEX_DB_PATH`, `PROC_ROOT`, `PRIVACY_MODE`
    - ✓ orchestrator Deployment sets: `NAMESPACE_ID`, `INDEX_DB_PATH`, `TICK_SECS`, `UTLD_URL`

- [ ] **K8s operational verbs are not “not implemented yet”**
  - **Targets**:
    - `cmd_ps/cmd_logs/cmd_down/cmd_restart` for `--mode k8s`
  - **Acceptance**:
    - `ritma ps --mode k8s` uses `kubectl get pods -n ritma-system`
    - `ritma logs --mode k8s` uses `kubectl logs` with service selection
    - `ritma down --mode k8s` uses `kubectl delete -f <dir>` (or equivalent) and prints next steps
    - `ritma restart --mode k8s` uses `kubectl rollout restart` (or equivalent) and prints next steps

#### F3) systemd deployment correctness

- [x] **systemd unit is deterministic and safe**
  - **Targets**:
    - `systemd_unit_template()`
    - `cmd_deploy_systemd()`
  - **Acceptance**:
    - ✓ Unit sets `RITMA_NAMESPACE` and `RITMA_PRIVACY_MODE=hash-only`
    - ✓ ExecStartPre creates data directory

### G) Ritma filesystem + namespace isolation solidification

Goal: prevent cross-namespace evidence mixing and make the data path explainable.

- [x] **One namespace → one data root**
  - **Targets**:
    - `write_compose_bundle()` data_dir argument
    - docker minimal fallback in `cmd_up()`
    - `cmd_doctor()` checks (`INDEX_DB_PATH`, `/data/index_db.sqlite`)
  - **Acceptance**:
    - ✓ `ritma doctor --json` shows `namespace_id` and `index_db` path

- [x] **Namespace identity is consistent across all subsystems**
  - **Targets**:
    - env vars in compose and k8s manifests: `NAMESPACE_ID` vs `RITMA_NAMESPACE`
    - `cmd_status`, `cmd_doctor`, `cmd_capture`
  - **Acceptance**:
    - ✓ `NAMESPACE_ID` canonical in compose/k8s; `RITMA_NAMESPACE` alias in systemd
    - ✓ `ritma doctor --json` shows `namespace_id`

- [x] **Data directory permissions and ownership are explicit**
  - **Targets**:
    - compose templates
    - systemd unit `ExecStartPre=/bin/mkdir -p /var/ritma/data`
  - **Acceptance**:
    - ✓ `ritma doctor` detects `not_writable_in_container` state and reports fix command
    - ✓ systemd unit creates `/var/ritma/data` via ExecStartPre

### H) Port vigilance + network boundary solidification

Goal: make ports, routes, and exposure **explicit**, **least-privilege**, and **auditable**.

#### H1) Port inventory must be explicit and consistent

- [x] **Define the authoritative port map (and keep it consistent across docker/k8s/systemd)**
  - **Targets**:
    - `write_compose_bundle()` templates (ports)
    - `docker/compose.sidecar.yml` (ports)
    - `k8s_manifest_bundle()` service specs (ports)
    - `docker/Dockerfile-*` `EXPOSE` lines
  - **Acceptance**:
    - ✓ UTLD: 8088 (consistent across docker/k8s)
    - ✓ Redis: 6379 internal-only
    - ✓ Orchestrator/tracer do not expose ports

- [ ] **No port is published unless there is a real listener**
  - **Targets**:
    - UTLD container exposure (`docker/Dockerfile-utld`, compose/k8s service for utld)
    - UTLD runtime listeners (`crates/utld/src/main.rs`, optional `UTLD_TLS_ADDR`)
  - **Acceptance**:
    - If UTLD is published on `8088`, the deployment wiring must also enable a TCP listener (e.g., TLS listener when compiled with `tls`).
    - Otherwise, `8088` must not be published and must be removed from templates.

#### H2) Bindings and exposure must be least-privilege

- [x] **Docker host port bindings default to localhost where possible**
  - **Targets**:
    - `write_compose_bundle()` output for `ports:`
    - checked via `ritma init` outputs
  - **Acceptance**:
    - ✓ Developer defaults bind as `127.0.0.1:PORT:PORT`

- [x] **K8s services default to ClusterIP**
  - **Target**: `k8s_manifest_bundle()`
  - **Acceptance**:
    - ✓ No default NodePort/LoadBalancer (ClusterIP is default).
    - Any external exposure is an explicit operator action.

#### H3) Route/proxy boundary is explicit (no accidental egress paths)

- [x] **Document and enforce the internal route topology**
  - **Targets**:
    - compose templates (`depends_on`, service names)
    - k8s manifests (service names, namespace)
  - **Acceptance**:
    - ✓ Docker: service name `utld`, `depends_on: [utld]`
    - ✓ K8s: `UTLD_URL=http://utld:8088` in orchestrator env

- [x] **Proxy environment variables do not break local/cluster connectivity**
  - **Targets**:
    - environment handling for HTTP clients (e.g., UTLD business plugin HTTP sink)
    - deployment env templates (compose/k8s/systemd)
  - **Acceptance**:
    - ✓ Compose: `NO_PROXY=localhost,127.0.0.1,utld,bar_daemon,redis`
    - ✓ K8s: `NO_PROXY=localhost,127.0.0.1,utld,redis,.ritma-system.svc.cluster.local`

#### H4) Port conflict detection is actionable

- [x] **`ritma doctor` reports port conflicts with fix commands**
  - **Targets**: `cmd_doctor`, `cmd_status`
  - **Acceptance**:
    - ✓ If `8088` or `8090` are in use, `doctor` reports the conflict in `port_conflicts` and `blockers`, and prints fix command.

### I) Authentication and isolation solidification (no new auth features)

Goal: use existing auth/isolation mechanisms correctly and consistently.

#### I1) UNIX socket isolation (local auth boundary)

- [x] **Sockets are not world-accessible**
  - **Targets**:
    - UTLD: `crates/utld/src/main.rs` sets socket perms `0o660` ✓
    - BAR daemon: `crates/bar_daemon/src/main.rs` sets socket perms `0o660` ✓
    - Docker volumes: ensure `/data` is not world-writable
  - **Acceptance**:
    - ✓ Default runtime does not expose BAR socket outside the container/host boundary.
    - ✓ Socket permissions are set to `0660`.

#### I2) mTLS isolation (existing capability)

- [ ] **mTLS is wired consistently when enabled**
  - **Targets**:
    - UTLD env keys: `UTLD_MTLS_CA`, `UTLD_MTLS_CERT`, `UTLD_MTLS_KEY`, `UTLD_MTLS_REQUIRE_CLIENT_AUTH`
    - Optional TCP/TLS listener: `UTLD_TLS_ADDR` (when built with feature `tls`)
    - `deploy export` templates and systemd unit
  - **Acceptance**:
    - If UTLD is exposed over TCP, it must be via TLS, and client auth is required by default.
    - If mTLS is not configured, UTLD remains unix-socket-only and should not be publicly reachable.

#### I3) HTTP API auth (existing capability, if `utl_http` is deployed)

- [ ] **No unauthenticated public HTTP endpoints**
  - **Targets**:
    - `crates/utl_http/src/main.rs` (JWT auth knobs)
  - **Acceptance**:
    - If `utl_http` is deployed behind a proxy/ingress, JWT verification is enabled via:
      - `UTL_HTTP_AUTH_JWT_PUBKEY_PATH` or `UTL_HTTP_AUTH_JWT_PUBKEY_PEM`
      - optional `UTL_HTTP_AUTH_JWT_ISS` and `UTL_HTTP_AUTH_JWT_AUD`
    - Tenant isolation rules are enforced consistently (no cross-tenant reads by default).

## 1.2) AI Decision Forensics Box (packaging + simplification only)

This is a **standardized deployment and operating mode** using existing Ritma primitives.

Goal: make it easy for teams to treat AI decisions as an auditable, exportable evidence stream.

### Box definition (what it must include)

- [ ] **Single-command deploy artifact generation**
  - **Target**: `cmd_deploy_export()`
  - **Acceptance**: `ritma deploy export --out <dir> --namespace <ns>` produces the full artifact set (compose + k8s + systemd) and prints the next commands.

- [ ] **Privacy mode is consistent across deploy outputs**
  - **Targets**: `write_compose_bundle()`, k8s manifest generation
  - **Acceptance**: all templates default to `hash-only` and use consistent env variable wiring.

- [ ] **AI forensics workflow uses an existing capture profile**
  - **Target**: `cmd_capture()` with `CaptureProfile::AiIncidentK8s`
  - **Acceptance**:
    - `ritma capture --profile ai-incident-k8s ...` produces a ProofPack directory with:
      - `proofpack.json`, `manifest.json`, `receipts/`, `verify.txt`, `events.ndjson`, `graph.json`, `findings.json`.
    - If prerequisites are missing (no events / no ML record), the command fails with an explicit fix chain.

- [ ] **AI forensics export is the same auditor bundle path**
  - **Target**: `ExportCommands::Bundle` and `Verify` path
  - **Acceptance**:
    - the exported bundle can be moved to a fresh machine and verified offline.

## 2) Work style standard (how we code)

- One PR = one milestone slice (small, testable).
- Every PR must add/extend tests.
- Any schema change must:
  - bump version fields,
  - include migration notes,
  - update verification logic.

## 3) Repo map (where to code)

### Product CLI

- `crates/ritma_cli/src/main.rs`

### Truth artifacts / signing

- `crates/evidence_package/{builder.rs,manifest.rs,signer.rs,verifier.rs}`
- `crates/node_keystore/*`

### Window pipeline

- `crates/bar_orchestrator/src/lib.rs`

### Ingestion

- `crates/tracer_sidecar/src/main.rs`
- `crates/middleware_adapters/*`

### Persistence

- `crates/index_db/src/lib.rs`

### CI

- `.github/workflows/ci.yml`

## 4) Milestone Playbooks (do these in order)

### Milestone 0 — CLI authority hardening

**Goal**: ensure nobody runs the wrong `ritma` binary.

#### Checklist

- [ ] Confirm `crates/ritma_cli` produces `ritma` (source-of-truth).
  - **File**: `crates/ritma_cli/Cargo.toml`
  - **Verify**: `cargo run -p ritma_cli -- --help`

- [ ] Add a smoke test for command tree stability.
  - **File**: `.github/workflows/ci.yml` or `tests/` (prefer `tests/integration/`)
  - **Acceptance**: CI fails if core verbs are missing.

#### Acceptance commands

```bash
cargo run -p ritma_cli -- --help
cargo run -p ritma_cli -- status
cargo run -p ritma_cli -- doctor
```

---

### Milestone 1 — Signed, offline-verifiable bundles (minimum crypto truth)

**Goal**: upgrade from “hash integrity” to “authentic + integrity”.

#### Design decision (must pick one)

- [x] **Signing format**: signature file vs signatures embedded in `manifest.json`.
  - ✓ Implemented: `manifest.sig` alongside `manifest.json`.

#### Checklist

- [x] Add signing on export.
  - **Files**:
    - `crates/ritma_cli/src/main.rs` (export path)
    - `crates/evidence_package/*` (sign + verify helpers)
  - **Acceptance**:
    - ✓ exported bundle contains `manifest.sig`

- [x] Add signature verification on `ritma verify`.
  - **Files**: `crates/ritma_cli/src/main.rs`
  - **Acceptance**:
    - ✓ tampering fails verification offline

- [x] Add `--json` stable output for verify.
  - **Files**: `crates/ritma_cli/src/main.rs`
  - **Acceptance**:
    - ✓ `ritma verify --json` includes signature status.

#### Required tests

- [x] Mutation test: flip a byte in one artifact → verify fails.
- [x] Removal test: delete a file listed in manifest → verify fails.
- [x] Signature test: replace `manifest.sig` → verify fails.
  - ✓ Tests added in `tests/integration/test_manifest_signature.rs`

#### Acceptance commands

```bash
ritma demo --window-secs 10
# export a bundle/proofpack to a directory
# ritma export bundle ...
ritma verify <bundle_dir>
```

---

### Milestone 2 — Remove demo-only truth (no synthetic continuity, no noop proofs)

**Goal**: eliminate fabricated chain and non-cryptographic “proofs” from non-demo runs.

#### Checklist

- [x] Remove or hard-gate synthetic receipt refs (`noop_r_*`).
  - **File**: `crates/bar_orchestrator/src/lib.rs` (`PipelineOrchestrator::run_window`)
  - **Acceptance**:
    - ✓ in non-demo mode (`new_production()`), no synthetic receipts are inserted.

- [ ] Remove or gate `ProofManager::with_noop_backend()`.
  - **File**: `crates/bar_orchestrator/src/lib.rs` (`Orchestrator::new`)
  - **Acceptance**:
    - non-demo proof outputs are cryptographically meaningful (signature-backed minimum).

#### Required tests

- [x] Test that non-demo pipeline does not create synthetic receipts.
  - ✓ Tests added in `crates/bar_orchestrator/src/lib.rs`

---

### Milestone 3 — Canonical ingestion (adapters into one truth event model)

**Goal**: replayable, deterministic event ingestion across domains.

#### Checklist

- [x] Declare canonical truth envelope: define required fields and invariants.
  - **Files**: `crates/common_models/*`
  - **Acceptance**:
    - ✓ event serialization is stable; hashes are stable.

- [ ] Ensure adapters enforce privacy mode.
  - **Targets**:
    - `crates/tracer_sidecar/src/main.rs`
    - `crates/middleware_adapters/*`

#### Required tests

- [x] Golden-file tests for canonical event serialization.
  - ✓ Added in `crates/common_models/src/lib.rs`

---

### Milestone 4 — Deterministic correlation and attack graph

**Goal**: same input events => same graph hash and summaries.

#### Checklist

- [x] Remove in-memory DB usage during correlation.
  - **File**: `crates/bar_orchestrator/src/lib.rs` (`correlate_window`)
  - ✓ Now uses `AttackGraphBuilder::stateless()` for deterministic graph building

- [ ] Stabilize window ID format.
  - **File**: `crates/bar_orchestrator/src/lib.rs`

#### Required tests

- [x] Determinism test for correlation output hashes.
  - ✓ Added in `crates/bar_orchestrator/src/lib.rs`

---

### Milestone 5 — K8s operational parity

**Goal**: `--mode k8s` supports core verbs like Docker.

#### Checklist

- [x] Implement k8s versions of:
  - `down` ✓
  - `logs` ✓
  - `restart` ✓
  - `ps` ✓
  - **File**: `crates/ritma_cli/src/main.rs`

- [ ] Add meaningful `next` suggestions for k8s in `deploy status`.
  - **File**: `crates/ritma_cli/src/main.rs`

#### Acceptance

- Running the above commands gives predictable output or capability-guided errors.

---

### Milestone 6 — Compliance/policy: real or explicitly experimental

**Goal**: no stubbed compliance is presented as real.

#### Checklist

- [x] Either implement CUE loading and stage execution for real OR gate the feature.
  - **Files**:
    - `crates/policy_engine/src/cue_integration.rs` ✓ Added experimental warnings + feature flag
    - `crates/policy_engine/src/compliance_pipeline.rs` ✓ Added experimental warning

---

## 5) CI upgrades (required)

Update CI so “truth layer” claims are enforced:

- [x] Add E2E: export bundle → copy to temp dir → `ritma verify` succeeds.
- [x] Add E2E: mutate an artifact → `ritma verify` fails.
  - ✓ Added to `.github/workflows/ci.yml`
- [x] Add E2E: determinism check for seeded window artifacts.
  - ✓ Added to `.github/workflows/ci.yml`

**Files**:

- `.github/workflows/ci.yml`

## 6) Release discipline (to keep it universal)

- [x] All artifact schemas are versioned and backward-compatible.
  - ✓ All exports include `"version": "0.1"` field
- [ ] `ritma verify` supports older schema versions or fails with explicit upgrade instructions.
- [ ] `release.yml` assets include checksums (already present) and future signature support.

## 7) “Do not regress” list (always keep green)

These must always work:

- `ritma status`
- `ritma doctor`
- `ritma demo --window-secs 10`
- `ritma verify <proofpack_dir>`
- Docker baseline: `init/up/ps/logs/down`

## 8) When in doubt: truthfulness rules

- If a capability is missing, fail with a precise next step.
- If a proof is not cryptographic, label it as non-cryptographic (or hide it).
- Never assert attribution.
