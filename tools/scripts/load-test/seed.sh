#!/usr/bin/env bash
# Seed N tenants for the load-test harness. Idempotent — re-running
# tops up missing rows rather than failing on duplicates.
#
# Usage:
#   VAULTSCAN_TEST_TOKEN=... ./seed.sh [count]
#
# Default count is 500, matching the baseline scenario in
# docs/operations/capacity-planning.md.

set -euo pipefail

COUNT="${1:-500}"
BASE="${VAULTSCAN_API_URL:-http://localhost:8080}"
: "${VAULTSCAN_TEST_TOKEN:?VAULTSCAN_TEST_TOKEN required}"

echo "Seeding ${COUNT} tenants against ${BASE}…"

for i in $(seq 1 "${COUNT}"); do
  curl -fsS -X POST "${BASE}/api/v1/tenants" \
    -H "Authorization: Bearer ${VAULTSCAN_TEST_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"name":"loadtest-tenant-%04d","slug":"loadtest-%04d"}' "$i" "$i")" \
    > /dev/null || true
  if (( i % 50 == 0 )); then
    echo "  ${i}/${COUNT}"
  fi
done

echo "Seed complete."
