#!/usr/bin/env bash
set -euo pipefail

# Ritma advanced demo script
# This follows the flows described in demo/ADVANCED_DEMO.md
# It is SAFE and only creates/reads local files under the repo.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p "$REPO_ROOT/demo"

REPORT_FILE="$REPO_ROOT/demo/advanced_report.txt"
echo "" > "$REPORT_FILE"
exec > >(tee -a "$REPORT_FILE") 2>&1

echo "================================================================================"
echo "RITMA ADVANCED CORE INFRASTRUCTURE DEMONSTRATION"
echo "================================================================================"
echo ""
echo "SCENARIO: Multi-tenant AI/Healthcare system with policy-driven access control"
echo "TENANT:   acme (demo tenant with real decision events and compliance data)"
echo "SCOPE:    End-to-end demonstration of:"
echo "          - Cryptographic root registration and transition logging"
echo "          - TruthScript policy validation, testing, and ledger burns"
echo "          - SOC2 compliance evaluation over decision events"
echo "          - Security incident detection and forensic evidence packaging"
echo "          - Hash-chained compliance index and truth snapshot verification"
echo ""
echo "AUDIENCE: CISOs, auditors, and security architects evaluating Ritma for"
echo "          regulated environments (healthcare, finance, AI governance)"
echo ""
echo "================================================================================"
echo ""
echo "[ritma-demo] repo root: $REPO_ROOT"

# --- 0. Environment ---

export UTLD_DIG_INDEX_DB="$REPO_ROOT/dig_index.sqlite"
export UTLD_DECISION_EVENTS="$REPO_ROOT/decision_events.jsonl"
export UTLD_COMPLIANCE_INDEX="$REPO_ROOT/compliance_index.jsonl"
export UTLD_DIG_STORAGE="$REPO_ROOT/digs"
export UTLD_BURN_STORAGE="$REPO_ROOT/burns"
unset UTLD_DIG_INDEX  # Force SQLite mode

# Demo-only: allow unsigned but hash-valid evidence packages to pass verification.
export RITMA_DEMO_ALLOW_UNSIGNED=1

# Note: If dig_index.sqlite has old schema, evidence package export may fail.
# Workaround: rm dig_index.sqlite to recreate with new schema.
# This is a known limitation that will be addressed with schema migration.
echo "[ritma-demo] UTLD_DECISION_EVENTS=$UTLD_DECISION_EVENTS"
echo "[ritma-demo] UTLD_DIG_INDEX_DB=$UTLD_DIG_INDEX_DB"
echo "[ritma-demo] UTLD_COMPLIANCE_INDEX=$UTLD_COMPLIANCE_INDEX"
echo "[ritma-demo] UTLD_DIG_INDEX is unset (using SQLite index only)"

# --- 1. Crypto & root / dig basics ---

ROOT_ID=123456
ROOT_HASH="$(echo -n 'demo-root-payload' | sha256sum | cut -d' ' -f1)"
ENTITY_ID=42
SIG_HEX="$(printf 'sig-demo' | xxd -p)"
ADDR_HASH="$ROOT_HASH"
HOOK_HASH="$ROOT_HASH"

UTLD_SOCKET_PATH="${UTLD_SOCKET:-/tmp/utld.sock}"

if [[ -S "$UTLD_SOCKET_PATH" ]]; then
  echo "[ritma-demo] Registering root $ROOT_ID with hash $ROOT_HASH (socket: $UTLD_SOCKET_PATH)"
  cargo run -p utl_cli -- root-register \
    --root-id "$ROOT_ID" \
    --root-hash "$ROOT_HASH" \
    --param env=demo --param purpose=advanced-pack

  echo "[ritma-demo] Listing roots (should include demo root)"
  cargo run -p utl_cli -- roots-list | sed -e 's/^/[roots-list] /'

  echo "[ritma-demo] Recording tx-record for entity=$ENTITY_ID root=$ROOT_ID"
  cargo run -p utl_cli -- tx-record \
    --entity-id "$ENTITY_ID" \
    --root-id "$ROOT_ID" \
    --signature "$SIG_HEX" \
    --data '{"action":"demo_transition","env":"advanced"}' \
    --addr-heap-hash "$ADDR_HASH" \
    --hook-hash "$HOOK_HASH" \
    --logic-ref "demo.logic.v1" \
    --wall "demo-boundary" \
    --param tenant=tenant-a
else
  echo "[ritma-demo] UTLD socket $UTLD_SOCKET_PATH not found; skipping root-register/tx-record demo (run 'cargo run -p utld' in another terminal to enable)."
fi

FILE_ID=9001
NOW=$(date +%s)
START=$((NOW-60))
END=$NOW

if [[ -S "$UTLD_SOCKET_PATH" ]]; then
  echo "[ritma-demo] Building DigFile for root=$ROOT_ID file_id=$FILE_ID"
  cargo run -p utl_cli -- dig-build \
    --root-id "$ROOT_ID" \
    --file-id "$FILE_ID" \
    --time-start "$START" \
    --time-end "$END"
else
  echo "[ritma-demo] UTLD socket $UTLD_SOCKET_PATH not found; skipping dig-build demo."
fi

# --- 1b. TruthScript policy demo (validate / test / burn / ledger) ---

POLICY_JSON="demo/policy.access.demo.json"

if [[ ! -f "$POLICY_JSON" ]]; then
  echo "[ritma-demo] Writing demo TruthScript policy to $POLICY_JSON"
  cat > "$POLICY_JSON" << 'EOF'
{
  "kind": "access_policy",
  "id": "demo-policy",
  "name": "demo_security_policy",
  "version": "1.0.0",
  "rules": [
    {
      "name": "allow_normal_flows",
      "when": {
        "kind": "http_request",
        "src_zone": "public",
        "dst_zone": "internal"
      },
      "then": {
        "decision": "allow_with_actions",
        "actions": ["seal_current_dig"]
      }
    },
    {
      "name": "deny_public_to_internal_attackers",
      "when": {
        "kind": "http_request",
        "src_zone": "public",
        "dst_zone": "internal",
        "actor_kind": "attacker"
      },
      "then": {
        "decision": "deny",
        "actions": ["seal_current_dig", "flag_for_investigation"]
      }
    }
  ]
}
EOF
fi

echo "[ritma-demo][USP5] Validating TruthScript policy $POLICY_JSON"
if ! cargo run -p utl_cli -- policy-validate \
  --file "$POLICY_JSON" | sed -e 's/^/[policy-validate] /'; then
  echo "[ritma-demo] WARNING: policy-validate failed for $POLICY_JSON; continuing demo."
fi

echo "[ritma-demo][USP6] Testing policy against synthetic access event"
if ! cargo run -p utl_cli -- policy-test \
  --file "$POLICY_JSON" \
  --kind access \
  --field tenant_id=acme \
  --field resource=demo-resource \
  --field decision=allow | sed -e 's/^/[policy-test] /'; then
  echo "[ritma-demo] WARNING: policy-test failed for $POLICY_JSON; continuing demo."
fi

echo "[ritma-demo][USP7] Burning policy into ledger"
if ! cargo run -p utl_cli -- policy-burn \
  --policy-id demo-policy \
  --version 1 \
  --policy-file "$POLICY_JSON" | sed -e 's/^/[policy-burn] /'; then
  echo "[ritma-demo] WARNING: policy-burn failed (likely no utld socket); continuing demo."
fi

echo "[ritma-demo][USP8] Listing policy ledger entries for demo-policy"
if ! cargo run -p utl_cli -- policy-ledger-list \
  --policy-id demo-policy \
  --limit 20 | sed -e 's/^/[policy-ledger] /'; then
  echo "[ritma-demo] WARNING: policy-ledger-list failed; continuing demo."
fi

# --- 2. SOC2 controls + compliance index ---

echo "[ritma-demo] Exporting SOC2 controls to demo/soc2.controls.json"
cargo run -p utl_cli -- rulepack-export \
  --kind soc2 \
  --out demo/soc2.controls.json

echo "[ritma-demo] Running compliance-check over decision events"
cargo run -p utl_cli -- compliance-check \
  --controls demo/soc2.controls.json \
  --limit 0

if [[ -f "$UTLD_COMPLIANCE_INDEX" ]]; then
  echo "[ritma-demo] compliance_index.jsonl head:"
  head -n 5 "$UTLD_COMPLIANCE_INDEX" | sed -e 's/^/[compliance_index] /'
fi

echo "[ritma-demo] CISO summary for acme / SOC2"
cargo run -p utl_cli -- ciso-summary \
  --tenant acme \
  --framework SOC2 \
  --limit 20

# --- 3. Decision events & incidents ---

echo "[ritma-demo] Recent decision events (first 10)"
cargo run -p utl_cli -- decision-events-list --limit 10 | sed -e 's/^/[decisions] /'

echo "[ritma-demo] SOC incidents for acme (first 20)"
cargo run -p utl_cli -- soc-incidents \
  --tenant acme \
  --limit 20 | sed -e 's/^/[soc-incidents] /'

# --- 4. Dig index views ---

echo "[ritma-demo] Listing DigFiles for acme (limit 10)"
cargo run -p utl_cli -- digs-list \
  --tenant acme \
  --limit 10 \
  --show-path | sed -e 's/^/[digs-list] /'

# --- 4b. Evidence package export / verify ---

echo "[ritma-demo][USP20] Exporting evidence package for acme (time_range demo)"
TIME_START=$START
TIME_END=$END
EPKG_PATH="demo/evidence.package.json"

if ! cargo run -p utl_cli -- evidence-package-export \
  --tenant tenant-a \
  --scope-type time_range \
  --scope-id "${TIME_START}:${TIME_END}" \
  --out "$EPKG_PATH" | sed -e 's/^/[evidence-export] /'; then
  echo "[ritma-demo] WARNING: evidence-package-export failed; continuing demo without package."
fi

if [[ -f "$EPKG_PATH" ]]; then
  echo "[ritma-demo][USP21] Verifying evidence package $EPKG_PATH"
  echo "[ritma-demo] NOTE: In this demo, *unsigned but hash-valid* packages are treated as SUCCESS; see [evidence-verify] demo-notes."
  cargo run -p utl_cli -- evidence-package-verify \
    --manifest "$EPKG_PATH" | sed -e 's/^/[evidence-verify] /'
else
  echo "[ritma-demo] NOTE: no evidence package file at $EPKG_PATH; skipping verify."
fi

# --- 5. Truth snapshots ---

echo "[ritma-demo] Truth snapshots (limit 10)"
cargo run -p utl_cli -- truth-snapshot-list --limit 10 | sed -e 's/^/[truth-snapshot] /'

echo "[ritma-demo] Verifying truth snapshots"
cargo run -p utl_cli -- truth-snapshot-verify | sed -e 's/^/[truth-verify] /'

echo "[ritma-demo] Exporting truth snapshot payload"
cargo run -p utl_cli -- truth-snapshot-export > demo/truth_snapshot.export.json

echo "[ritma-demo] Wrote demo/truth_snapshot.export.json"

# --- 5b. Usage events report (if usage_events.jsonl exists) ---

USAGE_EVENTS_FILE="$REPO_ROOT/usage_events.jsonl"
if [[ -f "$USAGE_EVENTS_FILE" ]]; then
  echo "[ritma-demo][USP26] Usage events report for acme"
  cargo run -p utl_cli -- usage-events-report \
    --tenant acme | sed -e 's/^/[usage-events] /'
else
  echo "[ritma-demo] Skipping usage-events-report (no $USAGE_EVENTS_FILE yet; run utld with UTLD_USAGE_EVENTS to generate)"
fi

# --- 6. CISO-oriented summary block ---

echo "[ritma-demo] =============================================="
echo "[ritma-demo] RITMA ADVANCED DEMO SUMMARY (tenant=acme)"

COMPLIANCE_LINES=0
if [[ -f "$UTLD_COMPLIANCE_INDEX" ]]; then
  COMPLIANCE_LINES=$(wc -l < "$UTLD_COMPLIANCE_INDEX" 2>/dev/null || echo 0)
fi

echo "[ritma-demo] - Compliance index entries: $COMPLIANCE_LINES (see [compliance_index] and [ciso-summary] sections)"

if [[ -f "$EPKG_PATH" ]]; then
  echo "[ritma-demo] - Evidence package: $EPKG_PATH (SQLite-backed; see [evidence-export]/[evidence-verify])"
else
  echo "[ritma-demo] - Evidence package: not available (check [evidence-export] for errors)"
fi

if [[ -f "$REPO_ROOT/demo/truth_snapshot.export.json" ]]; then
  echo "[ritma-demo] - Truth snapshot: demo/truth_snapshot.export.json (see [truth-snapshot]/[truth-verify])"
else
  echo "[ritma-demo] - Truth snapshot: not exported"
fi

if [[ -f "$USAGE_EVENTS_FILE" ]]; then
  echo "[ritma-demo] - Usage metering: usage_events.jsonl present (see [usage-events])"
else
  echo "[ritma-demo] - Usage metering: no usage_events.jsonl; metering disabled in this run"
fi

echo "[ritma-demo] - SOC incidents: see [soc-incidents] lines above for high-impact events"
echo "[ritma-demo] - Dig index & SNARK status: see [digs-list] and (optionally) root-snark-status demo"
echo "[ritma-demo] =============================================="

echo "[ritma-demo] Advanced demo completed. See prefixed output above and files under demo/."
