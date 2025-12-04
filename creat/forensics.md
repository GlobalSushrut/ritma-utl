# Forensic Storage Model for DigFiles

This document explains where DigFiles live today in the repo, and how they should be stored in a production "forensic vault" separate from application data.

---

## 1. Dev layout (this repo / your laptop)

In development, utld writes DigFiles to a local directory:

```text
./dig/
  root-<root_id>_file-<file_id>_<timestamp>.dig.json
```

Examples:

```text
dig/root-100_file-1596506..._1764632657.dig.json
dig/root-200_file-1211823..._1764632660.dig.json
dig/root-300_file-1389159..._1764638308.dig.json
```

Key points:

- Controlled via `UTLD_DIG_DIR` (defaults to `./dig`).
- Each file is a Merkle-sealed `DigFile` JSON with:
  - `file_id`
  - `time_range`
  - `dig_records[]`
  - `merkle_root`
- `utl_cli dig-inspect` reads directly from these files:

  ```bash
  cargo run -p utl_cli -- dig-inspect \
    --file dig/root-100_file-..._....dig.json \
    --tenant acme \
    --event-kind http_request
  ```

This is ideal for local debugging, demos, and unit tests.

---

## 2. Production layout (forensic vault)

In production, treat DigFiles as **evidence**, not just logs. They should live in a dedicated forensic store, isolated from app databases and normal log streams.

### 2.1 Raw DigFiles → object storage

Use an append-only, versioned object store (S3, GCS, MinIO, Backblaze, etc.). A recommended layout:

```text
forensics/
  <tenant_id>/
    <YYYY>/<MM>/<DD>/
      root-<root_id>_file-<file_id>_<timestamp>.dig.json
```

Example:

```text
forensics/
  acme/
    2025/12/01/
      root-100_file-1596506..._1764632657.dig.json
      root-300_file-1389159..._1764638308.dig.json
  globex/
    2025/12/01/
      root-200_file-1211823..._1764632660.dig.json
```

**Rules / guarantees:**

- **Per-tenant prefix**: isolates evidence by tenant and simplifies access control.
- **Append-only**:
  - Enable bucket versioning and retention (WORM-style if possible).
  - Never overwrite DigFiles in place; only add new files.
- **Encryption at rest**:
  - Use KMS-managed keys or tenant-specific keys where required.
- **UTLD_DIG_DIR mapping**:
  - In prod, `UTLD_DIG_DIR` can point to a local staging directory that is regularly synced to object storage by a background process, or
  - utld can write directly to a durable object store client.

`utl_cli dig-inspect` can then:

- Run where `forensics/` is mounted or synced locally, or
- Use a small wrapper/API to fetch a DigFile from object storage to a temp location before inspection.

### 2.2 Index metadata → database

To avoid scanning raw JSON blobs, maintain a small index of DigFiles in a database (Postgres, ClickHouse, etc.). A minimal schema:

```sql
CREATE TABLE dig_files (
  file_id        TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL,
  root_id        NUMERIC(39,0) NOT NULL,
  merkle_root    TEXT NOT NULL,
  time_start     BIGINT NOT NULL,
  time_end       BIGINT NOT NULL,
  record_count   INTEGER NOT NULL,
  policy_name    TEXT,
  policy_version TEXT,
  policy_decision TEXT,
  storage_path   TEXT NOT NULL,
  chain_anchor_id TEXT
);
```

Populate this index when a DigFile is sealed and persisted. Then you can answer queries like:

- "All DigFiles for `acme` in the last 24 hours"
- "All files where `policy_name = 'security_policy'` and `policy_decision = 'deny'`"
- "Find the file that covers a given timestamp `t`"

Once you have the `storage_path`, you fetch the JSON from object storage and can run `dig-inspect`-style analysis, or serve it via an API.

---

## 3. Optional: anchor Merkle roots

For higher assurance, periodically anchor batches of DigFile roots to an external ledger or blockchain.

### 3.1 Batch anchoring

Every N minutes or every N files:

1. Collect `merkle_root` from new DigFiles.
2. Build a batch Merkle tree over these roots.
3. Anchor the batch root into:
   - An internal BPI / ledger, or
   - A public blockchain (for external verifiability).

Track anchors in a table:

```sql
CREATE TABLE dig_chain_anchors (
  anchor_id        TEXT PRIMARY KEY,
  batch_merkle_root TEXT NOT NULL,
  tx_hash          TEXT NOT NULL,
  block_id         TEXT,
  created_at       TIMESTAMPTZ NOT NULL,
  covered_file_ids TEXT[] NOT NULL
);
```

This lets you later prove:

- A particular DigFile was included in a batch (via its Merkle path), and
- That batch was anchored in block `X` at time `T`, so the file existed no later than `T`.

---

## 4. Ownership and responsibilities

To match the "tenants write the law, platform enforces and proves" story:

- **Tenants control**:
  - Which events are logged (via policies / lawbooks).
  - Retention policies above the platform minimums.
- **Platform controls**:
  - Storage topology and infrastructure (object store, DB, anchors).
  - That DigFiles are append-only, encrypted, and Merkle-consistent.
  - That evidence cannot be silently deleted or edited without detection.

Conceptually:

- **Lawbooks** live in a policy registry (JSON + CUE).
- **Evidence (DigFiles)** live in a dedicated forensic object store.
- **Ritma** sits in the middle, evaluating tenant and regulator lawbooks, enforcing decisions, and producing verifiable forensic artifacts.
