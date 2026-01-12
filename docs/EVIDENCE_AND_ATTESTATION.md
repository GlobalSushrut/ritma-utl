# Evidence & Attestation (Spec)

Truthful-by-default. This spec describes the artifacts Ritma produces today and how to verify them.

## 1) Evidence Pack (demo-enhanced)

The grounded 8‑phase demo writes a minimal Evidence Pack JSON to disk.

- Location: printed at the end of the demo as `evidence_pack_path`
- Schema (current):

```json
{
  "namespace_id": "ns://demo/dev/hello/world",
  "window_id": "w-demo-<unix_timestamp>",
  "generated_at": "<RFC3339>",
  "notes": "demo evidence for verification"
}
```

- Receipt hash: `receipt_hash = sha256(file_contents)`
  - How to recompute:
    - `sha256sum <evidence_pack_path>/demo_evidence.json | cut -d' ' -f1`
  - Compare to the printed `receipt_hash` in the console.

- Attack graph hash (deterministic label used in the demo):
  - `attack_graph_hash = sha256(namespace_id | "|" | window_id)`
  - Recompute locally with any sha256 tool and compare with console output.

Notes:
- The demo’s Evidence Pack is intentionally simple; it’s a verifiability anchor for the console output.
- It does not claim chain-of-custody; it proves the printed values came from a specific JSON payload.

## 2) Attestation (ritma_cli attest)

Generates a canonical JSON attestation over a folder/repo, plus a receipt hash.

- Command:

```bash
cargo run -p ritma_cli -- attest --path . --namespace ns://demo/dev/hello/world
```

- Output:
  - Console: prints output directory and `sha256` receipt
  - Files written under an auto-created directory (e.g., `./ritma-attest-out/<uuid>/`):
    - `attestation.json`: canonicalized JSON
    - `attestation.sha256`: `<sha256>  attestation.json` (single line)

- Attestation JSON (current fields):
  - `version`: attestation schema version
  - `created_at`: RFC3339 timestamp
  - `namespace_id`: your supplied namespace
  - `subject`: canonicalized path + `tree_sha256` (hash of file tree)
  - `rbac`: optional actor/purpose (not exposed by the default CLI flags)
  - `git`: best-effort metadata (if `git` available for the path)

- Receipt hash:
  - `sha256(attestation.json)` is written to `attestation.sha256`
  - Console also prints the same value for quick copy/paste

Notes:
- This command does not sign the attestation by default; it produces canonical JSON + a receipt hash.
- Advanced options (QR/serve/actor/purpose) exist in code but aren’t exposed by the minimal CLI flags.

## 3) Runtime DNA (ritma_cli dna)

Runtime DNA is a per-namespace, hash-chained commit log derived from ML windows and evidence hashes.

- It is **non-custodial**: commits store hashes, not raw event payloads.
- It is **verifiable**: each commit’s `chain_hash` is derived from (`namespace_id`, `ml_id`, `start_ts`, `end_ts`, `prev_chain_hash`, `payload_hash`).

Commands:

```bash
cargo run -p ritma_cli -- dna status --namespace ns://demo/dev/hello/world
cargo run -p ritma_cli -- dna trace --namespace ns://demo/dev/hello/world --since 10
```

## 4) Incident Packaging (separate export path)

The incident packaging/signing lives in the `evidence_package` crate and related CLI flows (e.g., export-incident in other binaries). That path supports:

- Building a manifest over a time range
- Signing with `node_keystore` or an env key (fallback), or computing an unsigned package hash

This is distinct from the `attest` command, which focuses on canonical JSON + receipt hashing.

## 5) Evidence discipline (append-only semantics)

Ritma has two storage classes:

- **Hot store (mutable):** `INDEX_DB_PATH` (SQLite). This is an operational database and may be compacted/updated; it is not the evidence vault.
- **Evidence vault (append-only, local-first):** `RITMA_OUT_DIR` (Output Container v2 layout). This is the intended long-term, tamper-evident artifact area.

Append-only semantics (for `RITMA_OUT_DIR`):

- **No in-place edits for sealed artifacts.** Once a micro-window/hour/day artifact is considered “closed”, it must not be modified.
- **Writes are additive.** New micro-windows are new files under `windows/YYYY/MM/DD/HH/micro/` and catalogs/time-jump indices are appended as framed records.
- **Deletions are not part of the normal write path.** Retention/rotation is a separate policy concern and must respect future case-freeze semantics.

Current enforcement mechanisms (today):

- **Single-writer locks:** `tracer_sidecar` and `bar_orchestrator` take an `flock()` on a host-shared lock file under `RITMA_SIDECAR_LOCK_DIR` (default `/run/ritma/locks`). This prevents concurrent writers from racing and producing conflicting artifacts.
- **Directory/layout initialization:** writers call `StorageContract::ensure_base_dir()` and `StorageContract::ensure_out_layout()` so the expected `RITMA_OUT_DIR` structure exists before any artifacts are emitted.
- **Append-style indices/catalogs:** the current v0 implementations append framed records to:
  - `catalog/YYYY/MM/DD/day.cbor.zst`
  - `windows/.../index/timejump.cbor`

Notes on “mutable while active” files:

- Some files may be rewritten while an hour/window is still in progress (e.g., rolling roots). Those files become immutable once the corresponding partition is closed. A future sealing step will formalize this boundary and add explicit “sealed” markers/signatures.
