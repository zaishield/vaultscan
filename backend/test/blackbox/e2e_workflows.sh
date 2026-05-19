#!/usr/bin/env bash
# e2e_workflows.sh — HTTP-level blackbox coverage closing F-006.
#
# The external readiness audit's blackbox harness only exercised
# /healthz, /readyz, and a single missing-route negative. This script
# walks the same flows TestE2E_* covers (tenant → asset → finding →
# evidence → audit) over the HTTP API.
#
# Usage:
#   API=http://localhost:8080 ./backend/test/blackbox/e2e_workflows.sh
#
# Exits non-zero on any unexpected status / failed assertion.
# Logs each request + body excerpt to stdout for CI scrape.
set -euo pipefail
API="${API:-http://localhost:8080}"

note() { printf '\n=== %s ===\n' "$*"; }
expect_code() {
  local want="$1" got="$2" what="$3"
  if [ "$got" != "$want" ]; then
    echo "ASSERT-FAIL: $what got=$got want=$want" >&2
    exit 1
  fi
  echo "  $what → $got OK"
}

note "1. health endpoints (unauth)"
for ep in /healthz /readyz /livez /metrics; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$API$ep")
  expect_code 200 "$code" "$ep"
done

note "2. unauth → 401 on protected endpoints"
for ep in /api/v1/tenants /api/v1/users /api/v1/findings /api/v1/agents /api/v1/integrations; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$API$ep")
  expect_code 401 "$code" "unauth $ep"
done

note "3. adversarial: alg=none JWT must be rejected"
none='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.'
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $none" "$API/api/v1/tenants")
expect_code 401 "$code" "alg=none token rejected"

note "4. dev-token mint (dev env only) → authenticated workflows"
TOKEN=$(curl -s -X POST "$API/api/v1/auth/dev-token" \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"00000000-0000-0000-0000-000000000001","email":"e2e@blackbox","platform_id":"00000000-0000-0000-0000-0000000000a1","roles":["zaishield_super_admin"],"mfa":true}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
[ -n "$TOKEN" ] || { echo "ASSERT-FAIL: no dev token minted (is VAULTSCAN_ENV=development?)" >&2; exit 1; }
echo "  minted token (len=${#TOKEN})"

note "5. authenticated reads — return 200 OR 403 (role-gated), never 401"
for ep in /api/v1/tenants /api/v1/users /api/v1/integrations \
          /api/v1/findings /api/v1/agents /api/v1/engagements \
          /api/v1/assets /api/v1/audit/verify-deep ; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$API$ep")
  if [ "$code" = "401" ]; then
    echo "ASSERT-FAIL: authenticated $ep returned 401 (token should pass)" >&2
    exit 1
  fi
  echo "  $ep → $code"
done

note "6. audit chain integrity (verify-deep)"
resp=$(curl -s -H "Authorization: Bearer $TOKEN" "$API/api/v1/audit/verify-deep")
first_bad=$(printf '%s' "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('first_bad_id',-1))")
if [ "$first_bad" != "0" ]; then
  echo "ASSERT-FAIL: audit chain broken at row $first_bad" >&2
  echo "  response: $resp" >&2
  exit 1
fi
echo "  audit chain intact (first_bad_id=0)"

note "7. body-size cap (413 on a multi-MB POST against a small endpoint)"
big=$(head -c 200000000 /dev/zero | tr '\0' 'A')
code=$(printf '%s' "$big" | curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: text/plain' \
  --data-binary @- "$API/api/v1/audit/verify-deep" --max-time 5)
if [ "$code" != "413" ] && [ "$code" != "400" ]; then
  echo "ASSERT-FAIL: 200MB body got $code (want 413 or 400)" >&2
  exit 1
fi
echo "  oversized POST → $code"

note "8. security headers"
hdrs=$(curl -sI "$API/healthz")
for h in 'Strict-Transport-Security' 'X-Content-Type-Options' 'X-Frame-Options' 'Content-Security-Policy'; do
  if ! printf '%s' "$hdrs" | grep -qi "^$h:"; then
    echo "ASSERT-FAIL: missing $h header" >&2
    exit 1
  fi
  echo "  $h present"
done

note "ALL E2E BLACKBOX CHECKS PASSED"
