# Ritma CLI Reference

Truthful-by-default. This reference covers `ritma_cli` commands currently exposed in the repository.

## Conventions
- `--json` prints machine-readable output for some commands
- Paths are relative to current working directory unless otherwise noted

## Commands

### demo-enhanced
Run the grounded 8‑phase security demo; invokes real crate APIs and prints an Evidence Pack.

```bash
cargo run --bin ritma_cli -- demo-enhanced
```

### attest
Generate a canonical attestation JSON for a repository/folder and print the receipt hash.

```bash
cargo run --bin ritma_cli -- attest --path . --namespace ns://demo/dev/hello/world
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
  cargo run --bin ritma_cli -- bar-run-observe-only
```

### export-proof
Export a deterministic ProofPack (v0.1) for an ML window (when index DB is available).

```bash
cargo run --bin ritma_cli -- export-proof --ml-id <id> --out ./out \
  --index-db /data/index_db.sqlite
```

### export-incident
Build and (optionally) sign a compact incident manifest over a time range.

```bash
cargo run --bin ritma_cli -- export-incident \
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
cargo run --bin ritma_cli -- verify-proof --path ./proofpack
```

### diff
Diff two ML window commits and show attack-graph/feature deltas.

```bash
cargo run --bin ritma_cli -- diff --a <old_ml_id> --b <new_ml_id> \
  --index-db /data/index_db.sqlite
```

### blame
Find windows that introduced a needle (ip/proc/file).

```bash
cargo run --bin ritma_cli -- blame --namespace ns://demo/dev/hello/world \
  --needle 1.2.3.4 --limit 10 --index-db /data/index_db.sqlite
```

### tag-add / tag-list
Add and list tags for ML windows.

```bash
cargo run --bin ritma_cli -- tag-add --namespace ns://demo/dev/hello/world \
  --name incident/123 --ml-id <id>

cargo run --bin ritma_cli -- tag-list --namespace ns://demo/dev/hello/world
```

### commit-list / show-commit
List or show ML window commits.

```bash
cargo run --bin ritma_cli -- commit-list --namespace ns://demo/dev/hello/world --limit 5
cargo run --bin ritma_cli -- show-commit --ml-id <id>
```

### init / up (sidecar templates)
Generate and bring up local sidecar manifests (docker or k8s modes), for future live wiring.

```bash
cargo run --bin ritma_cli -- init --output ritma.sidecar.yml --namespace ns://demo/dev/hello/world --mode docker
cargo run --bin ritma_cli -- up --compose ritma.sidecar.yml --mode docker
```

### doctor
Basic diagnostics over index DB and namespace context (scaffolding).

```bash
cargo run --bin ritma_cli -- doctor --index-db /data/index_db.sqlite --namespace ns://demo/dev/hello/world
```

### demo (legacy mini)
Simulate a tiny incident and produce a simple proof.

```bash
cargo run --bin ritma_cli -- demo --namespace ns://demo/dev/hello/world --window-secs 60
```

Notes:
- Some flows depend on other services or an index DB; commands will explain missing prerequisites.
