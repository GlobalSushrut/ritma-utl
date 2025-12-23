# Ritma / Universal Truth Layer (UTL)

Ritma is an experimental **Universal Truth Layer (UTL)**: an **evidence-first runtime forensics fabric**.
It turns runtime behavior into **diffable, exportable, verifiable artifacts** — like Git, but for forensic truth.

This repo is CLI-first. The fastest way to “get it” is: run a demo, generate an attestation, then diff two windows.

---

## 60-Second Quick Start (grounded demo + attestation)

```bash
# 1) Build
cargo build

# 2) Grounded 8-phase demo (real crate APIs; no hidden live hooks)
cargo run -p ritma_cli -- demo-enhanced

# 3) Attest a directory/repo tree (verifiable artifact + receipt hash)
cargo run -p ritma_cli -- attest \
  --path . \
  --namespace ns://demo/dev/hello/world
```

The demo prints an **Evidence Pack** with:

- `namespace_id`, `window_id`
- `attack_graph_hash`
- `evidence_pack_path` (JSON written to disk)
- `receipt_hash` (sha256 of the payload)
- `proof_status` (generated/skipped)

---

## Verify (offline, local)

1. Read the JSON: `cat <evidence_pack_path>/demo_evidence.json`
2. Verify the receipt hash:

   - `sha256sum <evidence_pack_path>/demo_evidence.json | cut -d' ' -f1`
   - Compare to the printed `receipt_hash`

Ritma’s claims should always be checkable from the produced artifacts.

---

## What exists in this repo (today)

- CLI (`ritma`) that produces and exports **verifiable forensic artifacts**
- Evidence + Index layer (SQLite/JSONL) used by audit/export flows
- 8 grounded detection phases as composable crates
- BAR policy pipeline (**safe by default**: observe-only unless operator wires enforcement)
- Some older UTL components still exist (e.g., `utld`, DigFiles), but the modern UX is **CLI-first**.

---

## Runtime DNA (continuous forensic chain)

Runtime DNA is a per-namespace **hash-chained commit log** derived from windows and evidence hashes (non-custodial: hashes only).

```bash
# Build/extend the chain for a time range
cargo run -p ritma_cli -- dna build \
  --namespace ns://demo/dev/hello/world \
  --start <unix_seconds> \
  --end <unix_seconds>

# Beginner-friendly status
cargo run -p ritma_cli -- dna status \
  --namespace ns://demo/dev/hello/world

# Trace last N commits
cargo run -p ritma_cli -- dna trace \
  --namespace ns://demo/dev/hello/world \
  --since 10
```

Quick “what changed?” between the last two windows:

```bash
cargo run -p ritma_cli -- investigate diff --last \
  --namespace ns://demo/dev/hello/world
```

---

## Truthful-by-Default Policy

- Evidence-first output; avoids threat-actor naming by default
- Reports classification as: cluster ID, template match, TTP bundle (MITRE ATT&CK), confidence + rationale
- Predictive language is conservative (e.g., “ransomware-like risk” + horizon) and never overstates certainty

---

## Module Map (high-level)

Detectors (8 phases):

- `fileless_detector`, `ebpf_hardening`, `apt_tracker`, `container_security`,
  `memory_forensics`, `network_analysis`, `hardware_monitor`, `ml_detector`

BAR core:

- `bar_core`, `bar_orchestrator`, `bar_pipeline`, `bar_daemon`

Evidence + Index:

- `evidence_package`, `forensics_store`, `dig_index`, `index_db`

Keys + Identity:

- `node_keystore`, `handshake`

Compliance (alpha):

- `compliance_engine`, `compliance_index`, `compliance_packs`

CLI:

- `ritma_cli` (demo-enhanced, attest, export, dna, investigate)

---

## Working with real windows (IndexDb)

Some commands require an `index_db.sqlite` that already contains windows and summaries.

```bash
cargo run -p ritma_cli -- investigate list \
  --namespace ns://demo/dev/hello/world \
  --limit 10
```

Export an auditor-readable HTML report:

```bash
cargo run -p ritma_cli -- export report \
  --namespace ns://demo/dev/hello/world \
  --start <unix_seconds> \
  --end <unix_seconds> \
  --out ./ritma-report
```

---

## Docs

- `docs/README.md` (docs index)
- `docs/ARCHITECTURE.md` (overview, boundaries, integration points)
- `docs/CLI_REFERENCE.md` (current CLI commands)
- `docs/EVIDENCE_AND_ATTESTATION.md` (artifacts + verification)
- `docs/UX_GATE.md` (UX contract / acceptance checklist)
- `demo/README.md` (node console demo)
