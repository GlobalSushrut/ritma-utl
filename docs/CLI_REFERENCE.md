# Ritma CLI Reference

Truthful-by-default. This reference covers the **current `ritma` CLI** exposed by the repository.

## Conventions
- **Binary-first:** examples use `ritma ...` (matches `apt install ritma` and `target/release/ritma`).
- **Dev mode:** if you’re developing, replace `ritma` with `cargo run -p ritma_cli --`.
- **Global flag:** `--json` prints machine-readable output for supported commands.
- Paths are relative to current working directory unless otherwise noted.

## Commands

### Global help

```bash
ritma --help
ritma <command> --help
```

### demo-enhanced
Run the enhanced demo showcasing all 8 security phases.

```bash
ritma demo-enhanced
```

### attest
Generate a canonical attestation JSON for a repository/folder and print the receipt hash.

```bash
ritma attest --path . --namespace ns://demo/dev/hello/world
```

Flags:
- `--path <dir>`: folder to attest (default ".")
- `--namespace <id>`: namespace identifier
- `--out <dir>`: optional output directory (defaults to ./ritma-attest-out/<uuid>)

Output:
- Console: output path + `sha256`
- Files: `attestation.json` (canonical), `attestation.sha256`

### bar-run-observe-only
Read JSON events from stdin, evaluate with a no-op agent, and print decisions.

```bash
echo '{"namespace_id":"default","kind":"event","bar_decision":"deny"}' | \
  ritma bar-run-observe-only
```

### bar-health
Check connectivity to the BAR daemon and perform a simple round-trip test.

```bash
ritma bar-health --help
```

### export
Export artifacts from local evidence/index data.

```bash
ritma export --help
```

Subcommands:

- **`export report`**: auditor-readable report (when index DB is available)
- **`export window`**: export a forensic proofpack v2 for a window (by time range)
- **`export incident` / `export bundle` / `export proof`**: additional export flows (see `--help`)

Example (report):

```bash
ritma export report --help
```

### export-proof
Export a deterministic ProofPack (v0.1) for an ML window (when index DB is available).

```bash
ritma export-proof --ml-id <id> --out ./out \
  --index-db /data/index_db.sqlite
```

### export-incident
Build and (optionally) sign a compact incident manifest over a time range.

```bash
ritma export-incident \
  --tenant acme --time-start 1700000000 --time-end 1700003600 \
  --framework SOC2 --out manifest.json
```

Signing:
- Uses `node_keystore` if `RITMA_KEY_ID`/`RITMA_KEYSTORE_PATH` are configured
- Else uses env key `UTLD_PACKAGE_SIG_KEY` if present
- Else computes an unsigned package hash

### verify-proof
Verify an offline ProofPack folder.

```bash
ritma verify-proof --path ./proofpack
```

Notes:
- If you have a `.zip` ProofPack, unzip it first and then pass the folder path.

### investigate
Investigation workflows over commits/windows.

```bash
ritma investigate --help
```

### diff
Diff two ML windows and show attack-graph/feature deltas.

```bash
ritma diff --a <old_ml_id> --b <new_ml_id> \
  --index-db /data/index_db.sqlite
```

Shortcut for "diff the last two windows":

```bash
ritma diff --last \
  --namespace ns://demo/dev/hello/world
```

### blame
Find windows that introduced a needle (ip/proc/file).

```bash
ritma blame --namespace ns://demo/dev/hello/world \
  --needle 1.2.3.4 --limit 10 --index-db /data/index_db.sqlite
```

### tag-add / tag-list
Add and list tags for ML windows.

```bash
ritma tag-add --namespace ns://demo/dev/hello/world \
  --name incident/123 --ml-id <id>

ritma tag-list --namespace ns://demo/dev/hello/world
```

### commit-list / show-commit
List or show ML window commits.

```bash
ritma commit-list --namespace ns://demo/dev/hello/world --limit 5
ritma show-commit --ml-id <id>
```

### dna status / dna trace
Runtime DNA is a per-namespace, hash-chained commit log derived from windows and evidence hashes.

```bash
ritma dna status --namespace ns://demo/dev/hello/world
ritma dna trace --namespace ns://demo/dev/hello/world --since 10
```

### init / up (sidecar templates)
Generate and bring up local sidecar manifests (docker or k8s modes), for future live wiring.

```bash
ritma init --help
ritma up --help
```

### deploy
Generate deployment artifacts for common environments.

```bash
ritma deploy --help
```

Subcommands:

- **`deploy systemd`**
- **`deploy k8s`**
- **`deploy export`**
- **`deploy status`**

### doctor
Basic diagnostics over index DB and namespace context (scaffolding).

```bash
ritma doctor --index-db /data/index_db.sqlite --namespace ns://demo/dev/hello/world
```

### demo (legacy mini)
Simulate a tiny incident and produce a simple proof.

```bash
ritma demo --namespace ns://demo/dev/hello/world --window-secs 60
```

Tip: `demo` supports QR export and an embedded web server.

Notes:
- Some flows depend on other services or an index DB; commands will explain missing prerequisites.
