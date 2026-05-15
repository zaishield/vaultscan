#!/usr/bin/env bash
# run-baseline.sh — orchestrates the full k6 baseline against a target
# environment, aggregates summary JSON into a markdown report.
#
# Usage:   ./perf/run-baseline.sh [staging|production|local]
# Output:  perf/results/baseline-<timestamp>.md

set -euo pipefail

TARGET="${1:-local}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="$ROOT/results"
RUN_DIR="$RESULTS_DIR/$TS"
mkdir -p "$RUN_DIR"

case "$TARGET" in
  local)
    : "${VAULTSCAN_API_URL:=http://localhost:8080}"
    ;;
  staging)
    : "${VAULTSCAN_API_URL:=https://api.staging.vaultscan.zaishield.com}"
    ;;
  production)
    : "${VAULTSCAN_API_URL:=https://api.vaultscan.zaishield.com}"
    echo "REFUSING to load-test production by default. Set VAULTSCAN_FORCE_PRODUCTION=1 to override." >&2
    [ "${VAULTSCAN_FORCE_PRODUCTION:-}" = "1" ] || exit 2
    ;;
  *)
    echo "Unknown target: $TARGET" >&2
    exit 2
    ;;
esac

export VAULTSCAN_API_URL
echo "Target: $VAULTSCAN_API_URL"
echo "Results: $RUN_DIR"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 not installed. brew install k6 / apt-get install k6" >&2
  exit 1
fi

declare -a SCENARIOS=(
  "api_smoke"
  "api_steady"
  "api_spike"
  "scan_submit_burst"
  "findings_ingest_burst"
  "emergency_stop_sla"
)

for scenario in "${SCENARIOS[@]}"; do
  echo "=== Running $scenario ==="
  k6 run \
    --summary-export="$RUN_DIR/$scenario.json" \
    --out json="$RUN_DIR/$scenario.ndjson" \
    "$ROOT/scenarios/$scenario.js" \
    | tee "$RUN_DIR/$scenario.log" || true
done

# Aggregate into a Markdown report.
REPORT="$RESULTS_DIR/baseline-$TS.md"
{
  echo "# VAULTSCAN Performance Baseline · $TS"
  echo
  echo "**Target**: \`$VAULTSCAN_API_URL\`"
  echo
  echo "## SLO Punch List"
  echo
  echo "| Scenario | Threshold | Status | Median | P95 | P99 |"
  echo "|---|---|---|---|---|---|"
  for scenario in "${SCENARIOS[@]}"; do
    local_json="$RUN_DIR/$scenario.json"
    if [ ! -f "$local_json" ]; then
      echo "| $scenario | — | MISSING | — | — | — |"
      continue
    fi
    # Extract metrics with jq if available; otherwise grep-fallback.
    if command -v jq >/dev/null 2>&1; then
      median=$(jq -r '.metrics.http_req_duration.values["p(50)"] // "?"' "$local_json")
      p95=$(jq -r '.metrics.http_req_duration.values["p(95)"] // "?"' "$local_json")
      p99=$(jq -r '.metrics.http_req_duration.values["p(99)"] // "?"' "$local_json")
      passed=$(jq -r '[.metrics | to_entries[] | select(.value.thresholds) | .value.thresholds | to_entries[] | .value.ok] | all' "$local_json")
      status_col=$([[ "$passed" = "true" ]] && echo "✅ PASS" || echo "❌ FAIL")
    else
      median="? (jq missing)" ; p95="?" ; p99="?" ; status_col="?"
    fi
    printf "| %s | apiThresholds | %s | %.0f ms | %.0f ms | %.0f ms |\n" \
      "$scenario" "$status_col" "${median:-0}" "${p95:-0}" "${p99:-0}"
  done
  echo
  echo "## Per-scenario detail"
  for scenario in "${SCENARIOS[@]}"; do
    log="$RUN_DIR/$scenario.log"
    [ -f "$log" ] || continue
    echo
    echo "### $scenario"
    echo
    echo '```'
    tail -40 "$log"
    echo '```'
  done
} > "$REPORT"

echo
echo "Report written: $REPORT"
