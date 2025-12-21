# Ritma Advanced Core Demo Pack

This pack is a **deep-dive, CLI-first** demonstration of Ritma as a whole system:

- Crypto and hash-chained data structures
- Git-like policy & evidence history (roots, burns, commits)
- TruthScript policies and the policy engine
- Decision events and SNARK / high-threat tracking
- Compliance controls and hash-chained compliance index
- Evidence packaging and dig index
- Node keystore / wallet behaviour
- Node-local introspection via Node Console (optional last step)

It is organized as **31 small, composable demos** you can run individually or as a story.

> All commands are run from the repo root: `~/Documents/connector/ritma`.

---

## 0. Prerequisites

- Rust toolchain installed.
- Node.js installed (only needed for the final Node Console step).
- Build core binaries once:

```bash
cargo build -p utld -p utl_cli -p node_controller_api
```

Set core envs (we reuse existing sample data when available):

```bash
cd ~/Documents/connector/ritma

export UTLD_DECISION_EVENTS="$(pwd)/decision_events.jsonl"
export UTLD_DIG_INDEX_DB="$(pwd)/dig_index.sqlite"
export UTLD_COMPLIANCE_INDEX="$(pwd)/compliance_index.jsonl"
export UTLD_DIG_INDEX="$(pwd)/dig_index.jsonl"
```

---

## 1. Crypto & Root Layer (USPs 1–4)

### 1.1 Generate and register a new StateOfTruth root (USP #1)

Demonstrates: UID generation, hashing, root registry.

```bash
ROOT_ID=123456
ROOT_HASH="$(echo -n 'demo-root-payload' | sha256sum | cut -d' ' -f1)"

cargo run -p utl_cli -- \
  root-register \
  --root-id "$ROOT_ID" \
  --root-hash "$ROOT_HASH" \
  --param env=demo --param purpose=advanced-pack
```

Verify:

```bash
cargo run -p utl_cli -- roots-list
```

### 1.2 Record a transition event (USP #2)

Demonstrates: signed transition log, address & hook hashes, params.

```bash
ENTITY_ID=42
SIG="$(printf 'sig-demo' | xxd -p)"
ADDR_HASH="$ROOT_HASH"  # reuse for demo
HOOK_HASH="$ROOT_HASH"  # reuse for demo

cargo run -p utl_cli -- \
  tx-record \
  --entity-id "$ENTITY_ID" \
  --root-id "$ROOT_ID" \
  --signature "$SIG" \
  --data '{"action":"demo_transition","env":"advanced"}' \
  --addr-heap-hash "$ADDR_HASH" \
  --hook-hash "$HOOK_HASH" \
  --logic-ref "demo.logic.v1" \
  --wall "demo-boundary" \
  --param tenant=tenant-a
```

### 1.3 Build a DigFile for that root (USP #3)

Demonstrates: DigFile creation, Merkle root, record counts.

```bash
FILE_ID=9001
NOW=$(date +%s)
START=$((NOW-60))
END=$NOW

cargo run -p utl_cli -- \
  dig-build \
  --root-id "$ROOT_ID" \
  --file-id "$FILE_ID" \
  --time-start "$START" \
  --time-end "$END"
```

### 1.4 Inspect the DigFile (USP #4)

```bash
# Replace with actual path printed by dig-build if different
DIG_PATH="dig/demo-${FILE_ID}.dig.json"

cargo run -p utl_cli -- \
  dig-inspect \
  --file "$DIG_PATH" \
  --limit 5
```

---

## 2. TruthScript & Policy Engine (USPs 5–8)

### 2.1 Validate a TruthScript policy (USP #5)

```bash
POLICY_JSON="demo/policies/access.demo.json"

# (Prepare a small policy JSON by hand in that file.)

cargo run -p utl_cli -- \
  policy-validate \
  --file "$POLICY_JSON"
```

### 2.2 Test the policy against synthetic events (USP #6)

```bash
cargo run -p utl_cli -- \
  policy-test \
  --file "$POLICY_JSON" \
  --kind access \
  --field tenant_id=tenant-a \
  --field resource=demo-resource \
  --field decision=allow
```

### 2.3 Burn the policy into the ledger (USP #7)

Demonstrates: policy burn, immutable policy commit.

```bash
cargo run -p utl_cli -- \
  policy-burn \
  --policy-id demo-policy \
  --version 1 \
  --policy-file "$POLICY_JSON"
```

### 2.4 List policy ledger entries (USP #8)

```bash
cargo run -p utl_cli -- \
  policy-ledger-list \
  --policy-id demo-policy \
  --limit 20
```

---

## 3. Decision Events & SNARK / High-Threat (USPs 9–11)

### 3.1 List raw decision events (USP #9)

```bash
cargo run -p utl_cli -- \
  decision-events-list \
  --limit 20
```

### 3.2 Filter by SNARK high-threat status (USP #10)

```bash
cargo run -p utl_cli -- \
  decision-events-list \
  --snark-status invalid \
  --limit 20
```

### 3.3 SOC incidents feed (USP #11)

```bash
cargo run -p utl_cli -- \
  soc-incidents \
  --tenant tenant-a \
  --limit 50
```

---

## 4. Compliance Engine & Hash-Chained Index (USPs 12–16)

### 4.1 Export built-in SOC2 controls (USP #12)

```bash
cargo run -p utl_cli -- \
  rulepack-export \
  --kind soc2 \
  --out demo/soc2.controls.json
```

### 4.2 Run compliance-check over decision events (USP #13)

```bash
cargo run -p utl_cli -- \
  compliance-check \
  --controls demo/soc2.controls.json \
  --limit 0
```

This writes `ControlEvalRecord`s into `UTLD_COMPLIANCE_INDEX` (`compliance_index.jsonl`), hash-chained by `prev_hash`/`record_hash`.

### 4.3 Inspect the compliance index chain (USP #14)

```bash
head compliance_index.jsonl
```

Look for `prev_hash` and `record_hash` fields to see the chain.

### 4.4 CISO summary (USP #15)

```bash
cargo run -p utl_cli -- \
  ciso-summary \
  --tenant tenant-a \
  --framework SOC2 \
  --limit 50
```

### 4.5 Compliance drift (USP #16)

Assuming you have at least one policy tag / commit pair:

```bash
cargo run -p utl_cli -- \
  compliance-drift \
  --baseline-tag baseline-demo \
  --current-commit demo-commit-1 \
  --framework SOC2
```

---

## 5. Dig Index & Evidence (USPs 17–21)

### 5.1 List DigFiles from local dig index (USP #17)

```bash
cargo run -p utl_cli -- \
  digs-list \
  --tenant tenant-a \
  --limit 20 \
  --show-path
```

### 5.2 Root SNARK status (USP #18)

Pick a `root_id` from above or from `decision_events.jsonl`:

```bash
ROOT_ID="<root-id>"

cargo run -p utl_cli -- \
  root-snark-status \
  --root-id "$ROOT_ID"
```

### 5.3 Search digs via HTTP-compatible query (USP #19)

```bash
cargo run -p utl_cli -- \
  search-digs \
  --tenant tenant-a \
  --limit 20
```

### 5.4 Evidence package export (USP #20)

**Note:** Evidence packages now support both JSONL chain mode and SQLite mode.  
When `UTLD_DIG_INDEX` is unset, the system automatically uses `UTLD_DIG_INDEX_DB` (SQLite)  
and computes chain heads from the database, eliminating the need for `.head` files.

```bash
cargo run -p utl_cli -- \
  evidence-package-export \
  --tenant acme \
  --scope-type time_range \
  --scope-id "<start>:<end>" \
  --out demo/evidence.package.json
```

### 5.5 Evidence package verify (USP #21)

```bash
cargo run -p utl_cli -- \
  evidence-package-verify \
  --manifest demo/evidence.package.json
```

---

## 6. Truth Snapshots & Git-Like Heads (USPs 22–24)

### 6.1 List truth snapshots (USP #22)

```bash
cargo run -p utl_cli -- \
  truth-snapshot-list \
  --limit 20
```

### 6.2 Verify truth snapshot heads (USP #23)

```bash
cargo run -p utl_cli -- \
  truth-snapshot-verify
```

### 6.3 Export truth snapshot payload (USP #24)

```bash
cargo run -p utl_cli -- \
  truth-snapshot-export
```

Use this JSON for external anchoring (blockchain, notary, etc.).

---

## 7. Usage Metering & Billing Signals (USPs 25–26)

### 7.1 Enable file-based usage events (USP #25)

```bash
export UTLD_USAGE_EVENTS="$(pwd)/usage_events.jsonl"

cargo run -p utld
```

Then drive some CLI operations that talk to `utld` (`roots-list`, `tx-record`, etc.), and inspect:

```bash
head usage_events.jsonl
```

### 7.2 Summarize usage events (USP #26)

```bash
cargo run -p utl_cli -- \
  usage-events-report \
  --tenant tenant-a
```

---

## 8. Node Keystore & Wallet (USPs 27–28)

### 8.1 Env-only wallet (USP #27)

```bash
export RITMA_KEY_ID="demo-node-key"
export RITMA_KEY_HASH="0123456789abcdef0123456789abcdef"
export RITMA_KEY_LABEL="Demo node key"

cargo run -p node_controller_api
# Then curl http://127.0.0.1:8093/api/wallet
```

### 8.2 Keystore-backed wallet (USP #28)

Once you have a real `node_keystore` initialized on disk, start `node_controller_api` without `RITMA_KEY_HASH` and observe that it pulls `key_hash` and `label` from the keystore metadata instead.

---

## 9. Node-Local Introspection & Node Console (USPs 29–31)

These are **optional UI demos** that showcase how all the above infra is visible on a single node.

### 9.1 Node controller wired to local artifacts (USP #29)

Reuse the demo env setup from `demo/README.md` to point `node_controller_api` at:

- `UTLD_SLO_EVENTS`
- `UTLD_DECISION_EVENTS`
- `UTLD_DIG_INDEX_DB`
- `NODE_LOG_PATHS`

### 9.2 Node Console SLO / Incidents / Evidence (USP #30)

Start Node Console UI (`ui/node_console`) and explore:

- `/slo` – SLO JSONL
- `/incidents` – SOC incidents
- `/evidence` – dig index DB

### 9.3 Node Console Wallet / Logs / Config (USP #31)

Visit:

- `/wallet` – wallet info (env/keystore)
- `/logs` – tail logs
- `/config` – show effective UTLD/decision/dig/log paths

---

This advanced pack is intentionally **modular**: each numbered item is a small USP demo you can run, inspect, and explain to someone else. The combination shows Ritma as a **crypto-backed, git-like, policy-driven evidence and compliance engine** with both CLI and node-local UI frontends.
