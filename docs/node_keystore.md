# Node Keystore (R4.5)

This document describes the **node keystore** used by Ritma components for
cryptographic signing and key metadata registration.

The keystore is **file‑backed**, intentionally simple, and designed so that
future cloud key governance (R4.6) can build on top without breaking nodes.

---

## 1. Overview

The node keystore is the **source of truth for node signing keys**.
It is used by:

- `utl_cli` – evidence package export & signing.
- `utl_http` – HTTP evidence API signing and key metadata telemetry.
- `security_kit` – helpers for building & signing evidence packages.
- `compliance_index` – signing compliance burns.
- `ritma_cloud` – **reads** key metadata posted by nodes, but does not
  directly load the keystore.

The keystore is loaded via:

- `RITMA_KEYSTORE_PATH` – path to keystore JSON (optional).
  - Default: `./node_keystore.json`.
- `RITMA_KEY_ID` – active key identifier within the keystore.

---

## 2. Keystore JSON format

The keystore file is a JSON array of key records:

```json
[
  {
    "key_id": "node-key-ed25519-1",
    "alg": "ed25519",
    "secret_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "label": "primary-ed25519"
  },
  {
    "key_id": "node-key-hmac-1",
    "alg": "hmac_sha256",
    "secret_hex": "aa55aa55aa55aa55aa55aa55aa55aa55",
    "label": "primary-hmac"
  }
]
```

Fields:

- `key_id` – **stable identifier** for this key within the node keystore.
- `alg` – algorithm for this key:
  - `"ed25519"` – Ed25519 signing key (32‑byte secret).
  - `"hmac"` / `"hmac_sha256"` – HMAC‑SHA256 secret key.
- `secret_hex` – hex‑encoded key material.
  - For `ed25519`, must be **32 bytes** (64 hex chars).
  - For HMAC, can be any non‑empty length.
- `label` – optional human‑readable label (e.g. "prod primary key").

### 2.1 Key hashes

Each record has a derived `key_hash` (not stored in JSON, computed at runtime):

- For `ed25519` keys: `SHA256(public_key_bytes)`.
- For HMAC keys: `SHA256(secret_key_bytes)`.

This `key_hash` is what nodes send to `ritma_cloud` in `/keys` so the cloud
never receives raw key material.

---

## 3. Environment variables

Core keystore variables:

- `RITMA_KEYSTORE_PATH` (optional)
  - Path to keystore JSON file.
  - Default: `./node_keystore.json`.

- `RITMA_KEY_ID` (recommended)
  - Active signing key ID to use from the keystore.
  - Used by `utl_cli`, `utl_http`, and `security_kit` helpers.

- `RITMA_KEY_LABEL` (optional)
  - Friendly label for the active key.
  - Used as a fallback label when keystore metadata is not available while
    reporting to `ritma_cloud`.

- `RITMA_KEY_HASH` (fallback only)
  - Fallback for key hash when keystore metadata lookup fails while sending
    key summaries to `ritma_cloud`.

Legacy signing env (still supported as fallback):

- `UTLD_PACKAGE_SIG_KEY`
  - Previous mechanism for package signing in `utl_cli` and `utl_http`.
  - Format documented in `docs/evidence_packaging.md`.
  - Now used **only as fallback** if keystore is unavailable / misconfigured.

Cloud telemetry variables:

- `RITMA_CLOUD_URL` – base URL for `ritma_cloud`.
- `RITMA_CLOUD_ORG_ID` – org identifier used when posting telemetry.
- Node ID – derived by `ritma_cloud_node_id()` and used when sending
  evidence/key metadata; usually tied to a host‑level env var.

---

## 4. Component behavior

### 4.1 `utl_cli` – evidence export

Command: `cmd_evidence_package_export`.

1. Builds an evidence package manifest.
2. Attempts to sign using node keystore:
   - Reads `RITMA_KEY_ID`.
   - Loads keystore via `RITMA_KEYSTORE_PATH` (or default).
   - Maps keystore key (`ed25519` or `hmac_sha256`) into
     `evidence_package::SigningKey`.
3. If keystore signing **fails** (missing key, bad file, etc.):
   - Logs a warning.
   - Falls back to `UTLD_PACKAGE_SIG_KEY` if set.
4. If neither keystore nor env key is configured:
   - Emits a warning.
   - Package is exported **unsigned**.

### 4.2 `utl_http` – evidence API

Handler: `securitykit_evidence_package`.

- For `req.sign == true`:
  1. Tries keystore signing using `RITMA_KEY_ID` / `RITMA_KEYSTORE_PATH`.
  2. On error, logs `tracing::warn!` and falls back to
     `UTLD_PACKAGE_SIG_KEY`.
  3. On final failure, returns `500` with a descriptive error.

This allows gradual migration: enabling the keystore automatically shifts
signing away from the legacy env key.

### 4.3 `utl_http` → `ritma_cloud` key metadata

Function: `send_key_metadata_to_ritma_cloud`.

- Reads:
  - `RITMA_CLOUD_URL`, `RITMA_CLOUD_ORG_ID`.
  - Node ID (via helper).
  - `RITMA_KEY_ID`.
- Computes `key_hash` / `label` as follows:
  1. Try keystore (`NodeKeystore::from_env().metadata_for(key_id)`).
  2. If that fails, fall back to `RITMA_KEY_HASH` and `RITMA_KEY_LABEL`.
- Sends `RitmaCloudKeySummary { org_id, node_id, key_id, key_hash, label }`
  to `POST {RITMA_CLOUD_URL}/keys`.

### 4.4 `compliance_index` – burn signing

`BurnProcess::sign_burn` now uses the keystore:

- Requires `BurnConfig.signing_key_id` to be `Some("...")`.
- Loads keystore from `RITMA_KEYSTORE_PATH` (or default).
- Calls `sign_bytes(key_id, burn.burn_hash.as_bytes())`.
- Stores `"sig_" + hex_signature` on the burn.

If `signing_key_id` is missing or keystore/signing fails, burn creation
returns an **error** instead of a fake stub signature.

### 4.5 `security_kit::EvidenceBuilder` helpers

`EvidenceBuilder` exposes new helpers to simplify keystore usage:

- `build_and_sign(self, signing_key: SigningKey)` – existing low‑level API.
- `build_and_sign_with_keystore_env(self)` – convenience wrapper:
  - Reads `RITMA_KEY_ID`.
  - Uses keystore to load the key.
  - Calls `build_and_sign`.
- `build_and_sign_with_keystore_key_id(self, key_id: &str)` – same as above
  but with an explicit key ID.

Future SecurityKit integrations should prefer these helpers rather than
manually wiring `UTLD_PACKAGE_SIG_KEY`.

---

## 5. Migration notes

- **New deployments** should:
  - Create a keystore JSON file.
  - Set `RITMA_KEYSTORE_PATH` and `RITMA_KEY_ID`.
  - Optionally set `RITMA_KEY_LABEL`.
- **Existing deployments** using `UTLD_PACKAGE_SIG_KEY` will continue to work:
  - When keystore is configured, signing automatically switches to it.
  - If keystore is misconfigured, legacy env‑based signing is used as
    a safety net where configured.

This completes the R4.5 node keystore integration without changing the
external APIs of `ritma_cloud` or the evidence packaging system.
