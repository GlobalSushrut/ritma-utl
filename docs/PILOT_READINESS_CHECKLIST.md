# Ritma Pilot Readiness Checklist (5 Wedges + Institutional Hardening)

This checklist is meant to be **pass/fail**. If the items are green, Ritma is ready to be discussed with institutional buyers (including government) in a credible, operationally grounded way.

## 0) How to run commands

Choose one:

- [ ] **Installed binary**: use `ritma ...`
- [ ] **From source** (developer mode):

```bash
alias ritma='cargo run -p ritma_cli --'
```

Before every pilot session:

```bash
ritma status
ritma doctor
```

---

# 1) The 5 narrow “product wedges” (buyer-pilotable runbooks)

Each wedge below has:

- **Goal**: the buyer-facing outcome
- **Inputs**: what you need to run the pilot
- **Runbook**: copy/paste commands
- **Pass criteria**: what must be true for the pilot to be considered a success

## 1.1 AI Gateway Evidence + Continuity (LLM / agent calls)

- [ ] **Goal**
  - Produce an **independently verifiable** record of AI decisions/events over time.
  - Export a **portable evidence bundle** and a **continuity chain** (hash-only).

- [ ] **Inputs**
  - `namespace` for the AI system (example: `ns://acme/prod/ai/gateway`)
  - A stream of “AI events” (for pilot: can be synthetic JSON events; later: gateway logs)

- [ ] **Runbook (phase 1: observe-only decisions)**

```bash
# 1) Observe-only policy evaluation loop (safe by default)
# Replace this JSON with your own event envelope as you evolve the adapter.
echo '{"namespace_id":"ns://acme/prod/ai/gateway","kind":"event","bar_decision":"deny"}' | ritma bar-run-observe-only
```

```bash
# 2) Produce a verifiable, offline artifact (demo evidence pack)
ritma demo-enhanced

# 3) Verify offline (receipt hash) using printed instructions
# (see docs/EVIDENCE_AND_ATTESTATION.md)
```

```bash
# 4) Build/inspect continuity chain (when windows exist in your index DB)
ritma dna status --namespace ns://acme/prod/ai/gateway
ritma dna trace --namespace ns://acme/prod/ai/gateway --since 10
```

- [ ] **Pass criteria**
  - [ ] Evidence artifacts are written to disk and can be checked offline (receipt hash matches)
  - [ ] `dna status` returns integrity `ok` (or fails loudly with nonzero exit when broken)
  - [ ] The buyer can take the output folder to another machine and validate it without your infrastructure

---

## 1.2 B2B SaaS “Customer Trust Pack” (provenance + exportable proof)

- [ ] **Goal**
  - Generate a **customer-facing trust pack** you can hand to procurement/security:
    - attestation over the deployed repo/config
    - checksums / receipts
    - (optionally) report export

- [ ] **Inputs**
  - Path to a repo/config/deploy folder
  - A stable `namespace` (example: `ns://acme/prod/svc/payments-api`)

- [ ] **Runbook**

```bash
# 1) Attest the repo/folder (canonical JSON + receipt)
ritma attest --path . --namespace ns://acme/prod/svc/payments-api

# 2) (Optional) Export an auditor-readable HTML report if index DB windows exist
ritma export report \
  --namespace ns://acme/prod/svc/payments-api \
  --start <unix_seconds> \
  --end <unix_seconds> \
  --out ./ritma-report

# 3) Bundle the folder (zip/tar) and share externally
# 4) The recipient verifies the receipt hash(s) offline
```

- [ ] **Pass criteria**
  - [ ] Attestation JSON is canonical and has a stable `sha256` receipt
  - [ ] Recipient can verify without access to your systems
  - [ ] Output includes enough metadata to answer “what version/config was running?”

---

## 1.3 Kubernetes / Platform “Forensics Sidecar” (observe-first)

- [ ] **Goal**
  - Deploy a runtime sidecar baseline and make it operable like Docker:
    - `up`, `ps`, `logs`, `down`, `restart`
  - Demonstrate “what changed?” via `investigate diff` and exportable artifacts.

- [ ] **Inputs**
  - Docker or Kubernetes access
  - A target `namespace` (example: `ns://acme/prod/k8s/cluster-1`)

- [ ] **Runbook (Docker baseline first)**

```bash
# 1) Generate manifests
ritma deploy export --out deploy-out --namespace ns://acme/prod/k8s/cluster-1

# 2) Bring up the runtime (safe baseline)
ritma up --compose deploy-out/ritma.sidecar.yml --mode docker

# 3) Operate it like Docker
ritma ps --mode docker
ritma logs --mode docker --tail 200
ritma status
ritma doctor

# 4) Investigate changes (when index DB has windows)
ritma investigate diff --last --namespace ns://acme/prod/k8s/cluster-1

# 5) Tear down
ritma down --mode docker --compose deploy-out/ritma.sidecar.yml
```

- [ ] **Pass criteria**
  - [ ] `ritma up` succeeds on a clean machine with friendly guidance if a capability is missing
  - [ ] `ps/logs/down/restart` behave predictably
  - [ ] A human can run `investigate diff --last` and understand the change summary

---

## 1.4 IR / MDR “Proof-of-Incident Bundle” (portable evidence)

- [ ] **Goal**
  - Produce a **portable bundle** for an incident time range:
    - evidence artifacts
    - report
    - verification instructions
  - Make it easy for a third party to verify.

- [ ] **Inputs**
  - Incident time range
  - `namespace` for the environment

- [ ] **Runbook**

```bash
# 1) Export a report for the incident window
ritma export report \
  --namespace ns://acme/prod/ir/endpoint-42 \
  --start <unix_seconds> \
  --end <unix_seconds> \
  --out ./ritma-incident-report

# 2) (Optional) generate PDF if a headless browser is available
ritma export report \
  --namespace ns://acme/prod/ir/endpoint-42 \
  --start <unix_seconds> \
  --end <unix_seconds> \
  --out ./ritma-incident-report \
  --pdf

# 3) Export proof / bundle flows (if enabled in your build and DB state)
# ritma export proof ...
# ritma export bundle ...

# 4) Verify offline
# ritma verify proof --path ./ritma-incident-report
```

- [ ] **Pass criteria**
  - [ ] Report generation completes and produces a stable folder layout
  - [ ] Verification steps are explicit and succeed offline
  - [ ] You can rerun export for the same DB state and get stable hashes where expected

---

## 1.5 Data Access Boundary (warehouse/lakehouse/API) “Who accessed what” proof

- [ ] **Goal**
  - Turn existing access logs into a **verifiable audit artifact** + continuity chain.

- [ ] **Inputs**
  - A source of access events (warehouse query logs, data API logs)
  - A mapping to a Ritma namespace (example: `ns://acme/prod/data/warehouse`)

- [ ] **Runbook (pilot-friendly)**

```bash
# 1) Start with what you can always do: attest the policy/config repo
ritma attest --path . --namespace ns://acme/prod/data/warehouse

# 2) Produce a demo evidence pack to establish the verification pattern
ritma demo-enhanced

# 3) Once your adapter writes windows to the IndexDb, you can:
ritma export report \
  --namespace ns://acme/prod/data/warehouse \
  --start <unix_seconds> \
  --end <unix_seconds> \
  --out ./ritma-data-access-report

ritma dna build \
  --namespace ns://acme/prod/data/warehouse \
  --start <unix_seconds> \
  --end <unix_seconds>

ritma dna status --namespace ns://acme/prod/data/warehouse
```

- [ ] **Pass criteria**
  - [ ] You can answer: “who accessed what, when?” from exported artifacts (even if redacted/hash-only)
  - [ ] You can produce an evidence bundle for an audit request without live dependencies

---

# 2) “Institutional-grade” hardening checklist (supply chain, install, CI/CD)

This section is what makes the system credible for government/institutional procurement.

## 2.1 Release & installation (no Rust toolchain required)

- [ ] Publish versioned releases (Git tags + GitHub Releases)
- [ ] Provide prebuilt binaries for:
  - [ ] Linux x86_64
  - [ ] Linux arm64
  - [ ] macOS arm64 (optional)
- [ ] Provide:
  - [ ] `SHA256SUMS`
  - [ ] `SHA256SUMS.sig` (optional signing)
  - [ ] A minimal install doc: `curl -fsSL <url> | sh` OR “download binary” instructions
- [ ] Ensure builds use:
  - [ ] `cargo build --locked` (lockfile honored)
  - [ ] pinned toolchain (`rust-toolchain.toml`)

## 2.2 Provenance (build integrity)

- [ ] Emit build provenance for releases (SLSA-style attestation)
- [ ] Containers:
  - [ ] pin base images by digest
  - [ ] generate image SBOM
  - [ ] sign images (e.g., `cosign`)

## 2.3 Dependency vulnerability + license policy

Minimum:

- [ ] Add `cargo audit` to CI
- [ ] Add `cargo deny` (licenses + advisories) with a documented allowlist

Recommended:

- [ ] Container scanning in CI (tracer/orchestrator/utld images)
- [ ] If shipping UI components, scan JS deps and ensure lockfiles are governed

## 2.4 Security policy and disclosure

- [ ] Add repo-level `SECURITY.md` (vulnerability reporting)
- [ ] Define supported versions policy
- [ ] Document how secrets/keys are handled:
  - [ ] never store secrets in repo
  - [ ] secret rotation expectations
  - [ ] recommended secrets manager

## 2.5 CI/CD quality gates (already partially present)

- [ ] CI must block merges on:
  - [ ] `cargo fmt --check`
  - [ ] `cargo clippy -- -D warnings`
  - [ ] `cargo test --workspace`
  - [ ] docker image builds
  - [ ] E2E smoke (compose up + basic CLI checks)
- [ ] Branch protection rules enabled (required checks)
- [ ] Artifact retention policy set (and documented)

## 2.6 Operational readiness

- [ ] “Least privilege” mode documented for sidecar runtime
- [ ] Data paths documented (where state lives, what must be backed up)
- [ ] Retention defaults documented (and safe)
- [ ] Logs are parseable and stable
- [ ] Clear uninstall:
  - [ ] `ritma down` safe
  - [ ] explicit “remove data” path (separate command or documented manual step)

---

# 3) Required docs (must exist and be current)

- [ ] `docs/UX_GATE.md` reflects actual CLI behavior
- [ ] `docs/CLI_REFERENCE.md` up to date
- [ ] `docs/EVIDENCE_AND_ATTESTATION.md` up to date
- [ ] This checklist is kept current and used as the pilot acceptance artifact
