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
cargo run --bin ritma_cli -- attest --path . --namespace ns://demo/dev/hello/world
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

## 3) Incident Packaging (separate export path)

The incident packaging/signing lives in the `evidence_package` crate and related CLI flows (e.g., export-incident in other binaries). That path supports:

- Building a manifest over a time range
- Signing with `node_keystore` or an env key (fallback), or computing an unsigned package hash

This is distinct from the `attest` command, which focuses on canonical JSON + receipt hashing.
