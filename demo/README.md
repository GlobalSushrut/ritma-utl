# Artifact-first demo

This folder contains a small **artifact-first** demo runner.

It follows the demo “golden spine”:

1. Capture a short time window (synthetic events are seeded if empty)
2. Emit a ProofPack (artifacts + hashes)
3. Verify + Diff (prove integrity + compare runs)

## Run

From the repo root:

```bash
bash demo/artifact_first_demo.sh
```

The script always runs the CLI via:

```bash
cargo run -p ritma_cli -- ...
```

(avoids confusion with other `ritma` binaries you might have installed).

## Outputs

Each run writes under:

- `ritma-demo-out/artifact-first/<RUN_ID>/`

Notable files:

- `store/index_db.sqlite`
- `proofpacks/baseline/` (exported ProofPack)
- `proofpacks/incident/` (exported ProofPack)
- `baseline.log`, `incident.log`

The ProofPack folders contain:

- `proofpack.json`
- `manifest.json`
- `receipts/`
- `index.html`

## What it proves

- Integrity: `ritma verify-proof --path <proofpack_dir>` recomputes hashes and checks the ProofPack is tamper-evident.
- Change detection: `ritma diff --a <ml_id> --b <ml_id> --index-db <...>` compares two windows (attack-graph + feature deltas).
- Runtime DNA: `ritma dna build/trace` chains commits of runtime behavior for the incident namespace.

## Troubleshooting

- If you see `ml_id not found` during diff, re-run the script; it expects each `demo` run to create one ML window in the IndexDB.
- If you have an older `ritma` in your `PATH`, make sure you’re running the demo via `cargo run -p ritma_cli -- ...` as shown above.
