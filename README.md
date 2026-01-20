# Ritma

Ritma is a **court-grade forensic security observability platform**.

It captures runtime activity, seals it into cryptographic evidence, and exports auditor-verifiable proofpacks.

## Quick start

### Install

If you’re installing from packages:

```bash
curl -fsSL https://raw.githubusercontent.com/GlobalSushrut/ritma-utl/main/scripts/setup-apt.sh | sudo bash
sudo apt install ritma
```

For development builds:

```bash
cargo build --release -p ritma_cli -p tracer_sidecar
```

### Run a demo proof (no live capture required)

```bash
ritma demo --namespace ns://demo/basic --window-secs 10
```

Verify the exported ProofPack:

```bash
ritma verify-proof --path <proofpack-folder>
```

### Capture real events (sidecar)

Run the sidecar (systemd is recommended for production):

```bash
sudo systemctl enable ritma-sidecar
sudo systemctl start ritma-sidecar
sudo systemctl status ritma-sidecar
```

Sanity-check capture:

```bash
ritma doctor --index-db /var/lib/ritma/index_db.sqlite --namespace ns://acme/prod/app
```

### Seal and export a ProofPack v2 (real data)

Seal a window:

```bash
ritma seal-window --namespace ns://acme/prod/app --start <unix_seconds> --end <unix_seconds> --strict
```

Export the forensic ProofPack v2 for that time range:

```bash
ritma export window --namespace ns://acme/prod/app --start <start> --end <end> --out ./proofpacks/window
ritma verify-proof --path ./proofpacks/window
```

## Documentation

- `docs/README.md`
- `docs/ARCHITECTURE.md`
- `docs/production_setup.md`
- `docs/CLI_REFERENCE.md`
- `docs/ritma_transparency_forensics.md`
- `docs/RTSL_SPEC.md`
- `docs/EEC_SPEC.md`

## SDKs

- `sdk/python/` (Python)
- `sdk/typescript/` (TypeScript/Node)

## Repository structure (high-level)

- `crates/tracer_sidecar` (capture)
- `crates/index_db` (local evidence store)
- `crates/bar_orchestrator` (seal/export pipeline)
- `crates/forensic_ml` (4-layer ML)
- `crates/ritma_cli` (the `ritma` CLI)
