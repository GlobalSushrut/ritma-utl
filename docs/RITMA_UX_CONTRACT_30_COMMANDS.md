# Ritma UX Contract (Docker-Standard)

Goal: **the first ~5 minutes** should be enough for a Docker-literate engineer to operate Ritma.

Principles:
- **Minimal-first**: start the minimal baseline by default; optionally expand to full.
- **Self-guiding**: every command prints:
  - what just happened
  - where the artifacts/ports live
  - the next 1–2 commands
- **Truthful-by-default**: no ungrounded attribution; evidence/receipts over claims.
- **Predictable defaults**: no required flags for the common path.

Non-negotiable UX:
- **Install**: 1 step
- **Run**: `ritma up` (safe minimal)
- **See value**: within 60 seconds
- **Recover**: `ritma doctor` prints exact fix steps
- **Proof**: `ritma export bundle …` works offline

---

## Component Map (what we hide behind the UX)

- Runtime sidecars (docker/k8s): `utld`, `bar-daemon`, `tracer`, `orchestrator`, optional `redis`
- Index & evidence: `index_db` (SQLite), `evidence_package` (manifests), `attestation`
- “Security fabric” detectors (8 phases): fileless/eBPF/APT/container/memory/network/hardware/ML
- BAR layer: observe-only agent today; policy packs + enforcement are roadmap

---

## Constitution

### Top-level verbs are capped at 13

Top-level commands:
- `up`
- `down`
- `ps`
- `logs`
- `restart`
- `upgrade`
- `init`
- `deploy`
- `status`
- `doctor`
- `export`
- `verify`
- `dna`

Everything else is a subcommand under these verbs (or an alias that routes into one).

### Canonical nouns (pick ONE and use everywhere)

- `window` OR `commit`
- `namespace` OR `tenant`
- `proof` OR `proofpack`

Current codebase reality:
- The DB uses `ml_id` and `start_ts/end_ts` for a **window**.
- Most CLI commands already use `namespace`.

### Minimal is always safe

`ritma up` starts minimal baseline only by default (`utld` + `bar-daemon`).

---

## Command Tree (contract)

Notation:
- **EXISTS**: implemented today in `ritma`.
- **PROPOSED**: contract placeholder; to be implemented.

Output contract (every command):
- **Changed:** …
- **Where:** …
- **Next:** …

### 1) `ritma up` (**EXISTS**)

Subcommands/flags:
- `ritma up` (minimal)
- `ritma up --full` (full)
- `ritma up --profile <dev|prod|regulated|defense>` (**EXISTS**) real profile behavior

### 2) `ritma down` (**EXISTS**)

### 3) `ritma ps` (**EXISTS**)

### 4) `ritma logs` (**EXISTS**)

### 5) `ritma restart` (**EXISTS**)

### 6) `ritma upgrade` (**EXISTS**)

### 7) `ritma init` (**EXISTS**)

Dual-manifest strategy (**EXISTS**):
- Writes:
  - `ritma.compose.v2.yml`
  - `ritma.compose.v1.yml`
  - `ritma.sidecar.yml` (pointer/copy to chosen)

### 8) `ritma deploy` (**EXISTS**)

Subcommands:
- `ritma deploy export` (emit artifacts)
- `ritma deploy k8s`
- `ritma deploy systemd`
- `ritma deploy host`
- `ritma deploy app`
- `ritma deploy status`

### 9) `ritma status` (**EXISTS**)

### 10) `ritma doctor` (**EXISTS**)

### 11) `ritma export` (**EXISTS**)

Subcommands (final tree):
- `ritma export proof` (**EXISTS**, currently `export-proof`)
  - Export by time shortcut: `ritma export proof --namespace <ns> --at <unix_ts> --out <dir>` (**EXISTS**)
- `ritma export report` (**EXISTS**)
  - `ritma export report --namespace <ns> --start <unix_ts> --end <unix_ts> --out <dir>`
  - Optional: `--pdf` (prints a friendly error if no headless Chrome/Chromium is available)
- `ritma export incident` (**EXISTS**, currently `export-incident`)
- `ritma export bundle` (**EXISTS**) mandatory auditor path
- `ritma export attest` (**PROPOSED**) optional alias to `attest`

### 12) `ritma verify` (**EXISTS**)

Subcommands:
- `ritma verify digfile <file>` (**EXISTS** today as `verify`)
- `ritma verify proof <folder>` (**EXISTS** today as `verify-proof`)

### 13) `ritma dna` (**EXISTS**)

Subcommands:
- `ritma dna build --namespace <ns> --start <unix_ts> --end <unix_ts>`
  - Writes/extends a continuous per-namespace runtime-DNA chain (hash-only / non-custodial)
- `ritma dna trace --namespace <ns>`
  - Prints the chain and verifies linkage and commit hashes

---

## “5 minute learning path” (what the CLI should teach)

- `ritma up`
- `ritma doctor`
- `ritma commit-list --namespace <ns>`
- `ritma show-commit --ml-id <id>`
- `ritma export-incident --tenant <t> --time-start <s> --time-end <e>`
- `ritma export report --namespace <ns> --start <s> --end <e> --out <dir>`
- `ritma dna build --namespace <ns> --start <s> --end <e>`
- `ritma dna trace --namespace <ns>`

---

## Notes / Decisions Needed

- Define channel semantics for `ritma upgrade`:
  - image tags vs pinned digests vs policy strictness vs update strategy.
- Decide which commands are “hard” vs “soft” aliases (e.g. `status` may alias `doctor` initially).
- Decide the authoritative deploy targets:
  - `deploy k8s` vs `deploy host` vs `deploy systemd` vs `deploy app`.
- Decide which commands become routing aliases under the 12-verb constitution:
  - `commit-list/show-commit/explain/diff/blame/tag-add/tag-list` -> `investigate ...` (optional umbrella)
  - `bar-run-observe-only/bar-health` -> `ops bar ...` (optional umbrella)
