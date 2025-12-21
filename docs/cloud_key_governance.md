# Cloud Key Governance (R4.6)

This document describes the Cloud key governance features implemented in **R4.6** across
`ritma_cloud` and node-side components (`utl_http` and the node keystore).

The goals of R4.6 are:

- **Track key lifecycle metadata** (status, timestamps, rotation) centrally in `ritma_cloud`.
- **Expose governance APIs** for operators to inspect and update key state.
- **Optionally enforce governance** on nodes when signing evidence packages.

This feature is designed to be **backwards-compatible** with existing node behavior and
can be rolled out gradually.

---

## Data model and database schema

### `KeySummary` (control-plane model)

`ritma_cloud` tracks node keys using the `KeySummary` struct. R4.6 adds the following
governance fields:

- `status: String`
- `created_at: Option<u64>`
- `updated_at: Option<u64>`
- `last_seen_at: Option<u64>`
- `replaced_by_key_id: Option<String>`
- `governance_note: Option<String>`

These are returned in all `GET /keys` and `GET /keys/:key_id` responses. The `status`
field is a free-form string, but common values include:

- `active`
- `revoked`
- `compromised`
- `deprecated`

`created_at`, `updated_at`, and `last_seen_at` are UNIX timestamps in seconds.

### `keys` table

The PostgreSQL `keys` table in `ritma_cloud` is extended with matching columns:

- `status TEXT NOT NULL DEFAULT 'active'`
- `created_at BIGINT`
- `updated_at BIGINT`
- `last_seen_at BIGINT`
- `replaced_by_key_id TEXT`
- `governance_note TEXT`

Migrations are applied via `run_migrations` on startup using `CREATE TABLE IF NOT EXISTS`
and `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` to remain compatible with existing
installations.

### Population and updates

When a node POSTs key metadata to `ritma_cloud` via `/keys`:

- **New key**:
  - `status` is initialized to `"active"`.
  - `created_at`, `updated_at`, and `last_seen_at` are set to `now`.
  - `replaced_by_key_id` and `governance_note` start as `NULL`.
- **Existing key**:
  - `key_hash`, `org_id`, `node_id`, and `label` are updated.
  - `last_seen_at` and `updated_at` are bumped to `now`.
  - `status`, `replaced_by_key_id`, and `governance_note` are **not** changed by
    node telemetry.

All changes are persisted to the `keys` table and mirrored into the in-memory
`InMemoryState.keys` collection.

---

## Cloud governance APIs (`ritma_cloud`)

All routes below are served by the `ritma_cloud` binary and are typically protected by
an API key middleware.

### Register or update key metadata

- **Endpoint:** `POST /keys`
- **Purpose:** Node telemetry to register or refresh key metadata.
- **Body:** `KeySummary`-like structure sent by the node (no secret material).
- **Behavior:**
  - Inserts or updates the `keys` table and in-memory state.
  - Maintains governance timestamps as described above.

This endpoint is usually called by `utl_http` via `send_key_metadata_to_ritma_cloud`.

### List keys (with filters)

- **Endpoint:** `GET /keys`
- **Query parameters (all optional):**
  - `org_id`
  - `status`
  - `node_id` (normalized server-side)
- **Response:** `Vec<KeySummary>`

When no query parameters are provided, all known keys are returned (legacy behavior).
When query parameters are present, an in-memory filter is applied.

### Get a single key

- **Endpoint:** `GET /keys/:key_id`
- **Purpose:** Retrieve a single key's governance state.
- **Response:**
  - `200 OK` with `KeySummary` if `key_id` is known.
  - `404 NOT FOUND` otherwise.

This is the primary control-plane read API that nodes can use for governance
lookups.

### Update key governance metadata

- **Endpoint:** `PATCH /keys/:key_id`
- **Purpose:** Administrative updates to governance metadata.
- **Request body:**
  - `status: Option<String>`
  - `replaced_by_key_id: Option<String>`
  - `governance_note: Option<String>`
- **Behavior:**
  - Applies any provided fields to the in-memory `KeySummary`.
  - Sets `updated_at` to `now`.
  - Persists the updated governance state to the `keys` table.

Typical usages:

- Mark a key as `revoked` or `compromised`.
- Record rotation with `replaced_by_key_id`.
- Attach a free-form `governance_note` (e.g., incident or ticket reference).

### Org-level key summary

- **Endpoint:** `GET /orgs/:org_id/keys/summary`
- **Purpose:** Provide a compact view of key health for an org.
- **Response:**
  - `org_id: String`
  - `total_keys: u64`
  - `by_status: HashMap<String, u64>`

Example JSON:

```json
{
  "org_id": "acme",
  "total_keys": 5,
  "by_status": {
    "active": 3,
    "revoked": 1,
    "deprecated": 1
  }
}
```

This is useful for dashboards and health checks.

---

## Node behavior and governance enforcement

### Key metadata telemetry from nodes

Nodes send key metadata to `ritma_cloud` from `utl_http` using
`send_key_metadata_to_ritma_cloud`:

- Uses `RITMA_CLOUD_URL` and `RITMA_CLOUD_ORG_ID` to target the correct cloud instance.
- Uses `RITMA_NODE_ID` to identify the node.
- Preferentially derives `key_hash` and `label` from the node keystore via
  `NodeKeystore::from_env` and `metadata_for(&key_id)`.
- Falls back to `RITMA_KEY_HASH` / `RITMA_KEY_LABEL` if the keystore is not configured.

This keeps the `keys` table up to date with `last_seen_at` and other telemetry
without sending any key material.

### Optional governance enforcement on signing

`utl_http` can optionally enforce Cloud key governance during evidence signing.
This is controlled via environment variables and is **opt-in**.

#### Required environment variables

To enable enforcement for a node:

- `RITMA_CLOUD_URL` — base URL of the `ritma_cloud` service.
- `RITMA_CLOUD_ORG_ID` — org identifier for this node.
- `RITMA_KEY_ID` — key identifier used for signing and key metadata.
- `RITMA_ENFORCE_KEY_GOVERNANCE` — set to `1`, `true`, `yes`, etc. to enable.
- `RITMA_CLOUD_API_KEY` — optional API key; if set, sent as `x-ritma-api-key`.

If `RITMA_ENFORCE_KEY_GOVERNANCE` is not enabled, node behavior is unchanged and no
control-plane governance check is performed.

#### Enforcement flow

When a client requests a signed evidence package via `utl_http`:

1. The `securitykit_evidence_package` handler builds the manifest as before.
2. If `sign = true` and `RITMA_KEY_ID` is set, `utl_http`:
   - Calls `GET {RITMA_CLOUD_URL}/keys/{RITMA_KEY_ID}` with headers:
     - `x-ritma-org-id: {RITMA_CLOUD_ORG_ID}`
     - `x-ritma-api-key: {RITMA_CLOUD_API_KEY}` (if configured).
   - Parses the response and inspects the `status` field.
3. Decision logic:
   - If the Cloud lookup fails (network error, non-2xx status, parse error), the
     node **fails open** and continues to sign as before.
   - If the lookup succeeds and `status` is `revoked` or `compromised`
     (case-insensitive):
     - The request is rejected with HTTP `403 FORBIDDEN`.
     - The response body explains that the signing key is revoked/compromised
       according to Cloud governance.
   - For any other status (e.g. `active`, `deprecated`), signing proceeds normally.

After passing the governance check, the existing signing behavior applies:

- Primary path: sign using `NodeKeystore` and `RITMA_KEY_ID`.
- Fallback: sign using the legacy `UTLD_PACKAGE_SIG_KEY` environment variable if
  the keystore is not available or misconfigured.

This allows operators to gradually roll out governance enforcement without changing
clients or node interfaces.

---

## CLI helpers for Cloud key governance

R4.6 includes `utl_cli` helpers that call the `ritma_cloud` governance APIs.
These are intended for operators and automation rather than application traffic.

All commands respect:

- `RITMA_CLOUD_URL` — base URL for `ritma_cloud` (default `http://127.0.0.1:8088`).
- `RITMA_CLOUD_API_KEY` — optional API key, sent as `x-ritma-api-key`.
- `RITMA_CLOUD_ORG_ID` — default org and `x-ritma-org-id` header where needed.

### List keys

- **Command:** `utl cloud-keys-list`
- **Flags:**
  - `--org-id <ORG_ID>` (optional filter)
  - `--status <STATUS>` (e.g. `active`, `revoked`, `compromised`, `deprecated`)
  - `--node-id <NODE_ID>`
- **Behavior:** calls `GET /keys` with matching query parameters and prints a
  pretty-printed `Vec<KeySummary>`.

Example:

```bash
RITMA_CLOUD_URL=http://127.0.0.1:8088 \
RITMA_CLOUD_ORG_ID=acme \
RITMA_CLOUD_API_KEY=secret \
utl cloud-keys-list --status active
```

### Inspect a single key

- **Command:** `utl cloud-key-get --key-id <KEY_ID>`
- **Behavior:** calls `GET /keys/:key_id` and prints the `KeySummary` JSON.

Example:

```bash
utl cloud-key-get --key-id my-signing-key
```

### Update governance status

- **Command:** `utl cloud-key-set-status`
- **Flags:**
  - `--key-id <KEY_ID>`
  - `--status <STATUS>`
  - `--replaced-by-key-id <KEY_ID>` (optional; rotation target)
  - `--note <TEXT>` (optional; maps to `governance_note`)
- **Behavior:** calls `PATCH /keys/:key_id` with a governance update body and
  prints the updated `KeySummary`.

Example (revoke with rotation):

```bash
utl cloud-key-set-status \
  --key-id old-key \
  --status revoked \
  --replaced-by-key-id new-key \
  --note "Rotated due to scheduled key governance"
```

### Org-level summary

- **Command:** `utl cloud-keys-summary`
- **Flags:**
  - `--org-id <ORG_ID>` (optional; defaults to `RITMA_CLOUD_ORG_ID`)
- **Behavior:** calls `GET /orgs/:org_id/keys/summary` and prints the summary
  JSON (including `total_keys` and `by_status`).

Example:

```bash
RITMA_CLOUD_ORG_ID=acme \
utl cloud-keys-summary
```

---

## Quickstart: Enforcing Cloud key governance end-to-end

This example shows how to wire `ritma_cloud`, a node, and `utl_cli` together to
enforce Cloud key governance on signing.

### 1. Start `ritma_cloud`

Run the `ritma_cloud` binary (or Docker image) so it listens on the default
address:

```bash
RITMA_CLOUD_ADDR=0.0.0.0:8088 \
RITMA_CLOUD_API_KEY=secret \
ritma_cloud
```

Make sure the org you plan to use exists (e.g. `acme`).

### 2. Configure the node keystore and `utl_http`

On the node where `utl_http` runs, configure:

- `RITMA_KEYSTORE_PATH` — JSON keystore file containing your signing key.
- `RITMA_KEY_ID` — the key id to use for signing.
- `RITMA_CLOUD_URL` — URL of `ritma_cloud` (e.g. `http://127.0.0.1:8088`).
- `RITMA_CLOUD_ORG_ID` — org id (e.g. `acme`).
- `RITMA_CLOUD_API_KEY` — matches the key used by `ritma_cloud`.

Start `utl_http` with these variables set. On startup and during signing it
will POST `/keys` to register or refresh key metadata in `ritma_cloud`.

### 3. Verify the key in Cloud

From an operator workstation (or the node itself), use `utl_cli` to confirm
that the key has been registered:

```bash
RITMA_CLOUD_URL=http://127.0.0.1:8088 \
RITMA_CLOUD_ORG_ID=acme \
RITMA_CLOUD_API_KEY=secret \
utl cloud-keys-list --status active
```

You should see a `KeySummary` entry with your `key_id` and `status` set to
`"active"`.

### 4. Enable governance enforcement on the node

To make the node consult Cloud governance before signing, set:

```bash
export RITMA_ENFORCE_KEY_GOVERNANCE=true
```

and restart `utl_http`. With this set, `utl_http` will call `GET /keys/:key_id`
on `ritma_cloud` before signing.

### 5. Observe normal signing when key is active

Trigger an evidence signing request against `utl_http` (for example via an
existing client or test harness). With the key `active`, signing should
succeed as before.

### 6. Revoke the key in Cloud and see 403

Now revoke the key using the CLI helper:

```bash
utl cloud-key-set-status \
  --key-id my-signing-key \
  --status revoked \
  --note "Revoked for incident #INC-1234"
```

Confirm the status:

```bash
utl cloud-key-get --key-id my-signing-key
```

Then trigger the same signing request again. With governance enforcement
enabled, `utl_http` will:

- Call `GET /keys/my-signing-key` on `ritma_cloud`.
- See `status = "revoked"`.
- Return HTTP `403 FORBIDDEN` instead of signing.

This demonstrates the full R4.6 flow: Cloud-governed keys, operator control
over status, and node-side enforcement.

---

## Operational notes

- Governance updates are **control-plane only**. Nodes do not push governance
  status; they consume it from `ritma_cloud` when enforcement is enabled.
- The Cloud APIs are designed to be stable for external tooling and dashboards.
- No key material or secrets are ever stored in `ritma_cloud`; only hashed
  identifiers and metadata are tracked.

For more details on the node keystore format and configuration, see
`docs/node_keystore.md`.
