#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
NS_ROOT="ns://demo/niche/artifact-first/$RUN_ID"
NS_BASE="$NS_ROOT/baseline"
NS_INC="$NS_ROOT/incident"
OUT_ROOT="./ritma-demo-out/artifact-first/$RUN_ID"
BASE_DIR="$OUT_ROOT/store"
IDX="$BASE_DIR/index_db.sqlite"

mkdir -p "$BASE_DIR"

export RITMA_BASE_DIR="$BASE_DIR"
export RITMA_OUT_ENABLE=1

RITMA=(cargo run -q -p ritma_cli --)

run_demo() {
  local label="$1"
  local ns="$2"
  local window_secs="$3"
  local log="$OUT_ROOT/${label}.log"

  mkdir -p "$OUT_ROOT"

  echo "== demo:$label (window_secs=$window_secs) =="
  "${RITMA[@]}" demo \
    --namespace "$ns" \
    --index-db "$IDX" \
    --window-secs "$window_secs" \
    2>&1 | tee "$log"

  local proof_dir
  proof_dir="$(grep -E 'Exported shareable ProofPack to ' "$log" | tail -n 1 | sed 's/.*Exported shareable ProofPack to //')"
  if [[ -z "${proof_dir}" ]]; then
    proof_dir="$(grep -E 'Exported ProofPack to ' "$log" | tail -n 1 | sed 's/.*Exported ProofPack to //')"
  fi

  if [[ -z "${proof_dir}" ]]; then
    echo "error: could not locate exported ProofPack directory in $log" >&2
    exit 1
  fi

  local dest_dir="$OUT_ROOT/proofpacks/$label"
  mkdir -p "$OUT_ROOT/proofpacks"
  mv "$proof_dir" "$dest_dir"
  proof_dir="$dest_dir"

  echo "$proof_dir"
}

read_latest_ml_id() {
  local ns="$1"
  if command -v jq >/dev/null 2>&1; then
    "${RITMA[@]}" --json investigate list \
      --namespace "$ns" \
      --limit 1 \
      --index-db "$IDX" | jq -r '.[0].ml_id'
    return 0
  fi

  "${RITMA[@]}" --json investigate list \
    --namespace "$ns" \
    --limit 1 \
    --index-db "$IDX" | sed -n 's/.*"ml_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

echo "namespace_base: $NS_BASE"
echo "namespace_incident: $NS_INC"
echo "out_root: $OUT_ROOT"
echo "index_db: $IDX"

BASELINE_PROOF_DIR="$(run_demo baseline "$NS_BASE" 60 | tail -n 1)"
INCIDENT_PROOF_DIR="$(run_demo incident "$NS_INC" 240 | tail -n 1)"

echo

echo "baseline_proof_dir: $BASELINE_PROOF_DIR"
echo "incident_proof_dir: $INCIDENT_PROOF_DIR"

echo

echo "== verify: baseline =="
"${RITMA[@]}" verify-proof --path "$BASELINE_PROOF_DIR"

echo "== verify: incident =="
"${RITMA[@]}" verify-proof --path "$INCIDENT_PROOF_DIR"

echo

echo "== window ids (ml_id) =="
BASELINE_ML_ID="$(read_latest_ml_id "$NS_BASE")"
INCIDENT_ML_ID="$(read_latest_ml_id "$NS_INC")"

if [[ -z "${BASELINE_ML_ID}" || -z "${INCIDENT_ML_ID}" ]]; then
  echo "error: could not resolve ml_id(s) from index_db" >&2
  exit 1
fi

echo "baseline_ml_id: $BASELINE_ML_ID"
echo "incident_ml_id: $INCIDENT_ML_ID"

echo

echo "== diff: older -> newer =="
"${RITMA[@]}" diff --a "$BASELINE_ML_ID" --b "$INCIDENT_ML_ID" --index-db "$IDX"

echo

echo "== runtime DNA: build + trace =="
END_TS="$(date +%s)"
START_TS="$((END_TS - 3600))"
"${RITMA[@]}" dna build --namespace "$NS_INC" --start "$START_TS" --end "$END_TS" --limit 200 --index-db "$IDX"
"${RITMA[@]}" dna trace --namespace "$NS_INC" --since 10 --limit 50 --index-db "$IDX"

echo

echo "Done. Open these in a browser:"
echo "  $BASELINE_PROOF_DIR/index.html"
echo "  $INCIDENT_PROOF_DIR/index.html"
