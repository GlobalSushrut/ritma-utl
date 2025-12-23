# UX_GATE: Ritma “Docker-Standard” Acceptance Checklist

This file is the **pass/fail gate** for Ritma’s CLI UX.

Non-negotiable:
- Install: 1 step
- Run: `ritma up` (safe minimal)
- Value: visible within 60 seconds
- Recover: `ritma doctor` prints exact fix steps
- Proof: `ritma export bundle …` works offline

---

## Phase 0 — Constitution

- [ ] **13 top-level verbs** only: `up/down/ps/logs/restart/upgrade/init/deploy/status/doctor/export/verify/dna`
- [ ] **Minimal is always safe**: `ritma up` starts minimal-only unless user opts in
- [ ] **Canonical nouns chosen**:
  - [ ] `window` vs `commit`
  - [ ] `namespace` vs `tenant`
  - [ ] `proof` vs `proofpack`

---

## Phase 1 — Capability Detection (no raw compose errors)

- [ ] `ritma status` works on a blank machine and prints:
  - red/yellow/green
  - why
  - next 1 command
- [ ] `ritma doctor` detects:
  - docker present?
  - compose v2 present?
  - compose v1 present?
  - kubectl present?
  - systemd present?
  and prints chosen path + exact install commands
- [ ] `ritma up` uses the same detection and never prints raw compose failure as the first output

---

## Phase 2 — Dual-Manifest Strategy

- [ ] `ritma init` writes:
  - `ritma.compose.v2.yml`
  - `ritma.compose.v1.yml`
  - `ritma.sidecar.yml` (pointer/copy to chosen)
- [ ] `ritma up` always selects the correct compose file automatically

---

## Phase 3 — Runtime Baseline Commands (Docker muscle memory)

- [ ] `ritma ps` works like `docker ps` for Ritma runtime
- [ ] `ritma logs` works for a service or whole stack
- [ ] `ritma down` stops without deleting data
- [ ] `ritma restart` restarts minimal baseline quickly

---

## Phase 4 — Export + Verify Umbrellas (offline auditor path)

- [ ] `ritma export proof …` works
- [ ] `ritma export proof --namespace <ns> --at <unix_ts> --out <dir>` works (export by timestamp)
- [ ] `ritma export report --namespace <ns> --start <unix_ts> --end <unix_ts> --out <dir>` writes:
  - [ ] `<dir>/index.html`
  - [ ] `<dir>/window_<ml_id>.html` per window in range
  - [ ] Index lists windows found in range even if window_summaries/edges are missing (partial pages are explicit)
- [ ] `ritma export report ... --pdf`:
  - [ ] generates `<dir>/index.pdf` when a headless Chrome/Chromium is available
  - [ ] prints a friendly capability error when no headless browser is found
- [ ] `ritma export incident …` works
- [ ] `ritma export bundle …` creates one folder containing:
  - proof output
  - incident manifest
  - attestation
  - README for auditors
  - checksums
  - exact verify command
- [ ] `ritma verify digfile <file>` works
- [ ] `ritma verify proof <folder>` works
- [ ] Backward-compatible aliases work (no breaks):
  - [ ] `ritma export-proof ...` routes to `ritma export proof ...`
  - [ ] `ritma export-incident ...` routes to `ritma export incident ...`
  - [ ] `ritma verify-proof ...` routes to `ritma verify proof ...`

---

## Phase 4.5 — Deploy Umbrella (real backend work)

- [ ] `ritma deploy export --out deploy-out --namespace <ns>` writes:
  - [ ] `deploy-out/ritma.sidecar.yml`
  - [ ] `deploy-out/ritma.compose.v1.yml`
  - [ ] `deploy-out/ritma.compose.v2.yml`
  - [ ] `deploy-out/k8s/*.yaml`
  - [ ] `deploy-out/ritma-security-host.service`
- [ ] `ritma deploy status` prints a meaningful `Next:` when systemd is:
  - [ ] `unit_not_found`
  - [ ] `inactive`
  - [ ] `activating`
  - [ ] `failed`
  - [ ] `active`
- [ ] `ritma deploy status --json` includes:
  - [ ] `systemd.state`
  - [ ] `next` array
- [ ] `ritma deploy systemd --out deploy-out --install` either installs successfully or prints the full sudo Fix chain

---

## Phase 5 — Investigate Umbrella (optional)

- [ ] `ritma investigate list/show/explain/diff/blame/tag add|list|rm` works
- [ ] Old aliases remain routed:
  - `commit-list/show-commit/explain/diff/blame/tag-add/tag-list`

---

## Phase 6 — Profiles Become Real

- [ ] `ritma up --profile dev|prod|regulated|defense` changes:
  - which services start
  - retention limits
  - redaction strictness
  - resource limits
  - signing behavior

---

## Phase 7 — Distribution

- [ ] “demo path must never compile” (no cargo build for end users)
- [ ] “deploy path must never compile”
- [ ] prebuilt binary or install script exists

---

## Phase 8 — Runtime DNA (continuous chain, non-custodial)

- [ ] `ritma dna build --namespace <ns> --start <unix_ts> --end <unix_ts>`:
  - [ ] appends a continuous per-namespace chain across ML windows in time order
  - [ ] never uploads data (hash-only / non-custodial)
  - [ ] refuses unsafe backfill when a chain tip already exists for newer windows
- [ ] `ritma dna trace --namespace <ns>`:
  - [ ] prints a human-readable chain trace with per-commit `link_ok` + `hash_ok`
  - [ ] exits nonzero if chain verification fails
