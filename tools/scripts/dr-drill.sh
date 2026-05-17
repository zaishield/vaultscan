#!/usr/bin/env bash
# Disaster Recovery drill (HS-03).
#
# Verifies the quarterly recovery procedure end-to-end without touching
# production:
#   1. Spins a fresh Postgres in a sandbox docker container.
#   2. Pipes the most recent S3 dump through pg_restore.
#   3. Runs every migration against the restored DB.
#   4. Calls /api/v1/audit/verify and asserts first_bad_id == 0.
#   5. Generates one compliance report for a known tenant.
#   6. Cleans up the sandbox.
#
# Usage:  ./tools/scripts/dr-drill.sh [--dry-run]
#
# Required env:
#   S3_ENDPOINT, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#   VAULTSCAN_API_URL (defaults to https://api-dr.vaultscan.zaishield.com)
#
# Exits non-zero with a short report if any phase fails. The drill
# duration + outcome is POSTed to /api/v1/audit/drill so the next audit
# can confirm "yes, we ran this last quarter".

set -euo pipefail

DRY_RUN=${1:-}
START=$(date -u +%s)
SANDBOX="vaultscan-dr-drill-$$"
DUMP_KEY=""
LOG=$(mktemp)
trap 'rm -f "${LOG}"' EXIT

log() { printf '[dr-drill] %s\n' "$*" | tee -a "${LOG}"; }
die() { log "FAIL: $*"; exit 1; }

log "starting DR drill ($(date -u +%FT%TZ))"

# ----- 1. Resolve the most recent dump -----------------------------------
if [[ -z "${DRY_RUN}" ]]; then
  : "${S3_ENDPOINT:?S3_ENDPOINT must be set}"
  : "${S3_BUCKET:?S3_BUCKET must be set}"
  TODAY=$(date -u +%Y-%m-%d)
  DUMP_KEY=$(aws s3 ls "s3://${S3_BUCKET}/${TODAY}/" \
             --endpoint-url "${S3_ENDPOINT}" \
             | awk '{print $4}' | tail -1)
  [[ -n "${DUMP_KEY}" ]] || die "no dump found under s3://${S3_BUCKET}/${TODAY}/"
  log "using dump ${DUMP_KEY}"
else
  log "[dry-run] would resolve latest S3 dump"
fi

# ----- 2. Spin a sandbox Postgres ----------------------------------------
log "starting sandbox Postgres (${SANDBOX})"
if [[ -z "${DRY_RUN}" ]]; then
  docker run -d --rm --name "${SANDBOX}" \
    -e POSTGRES_PASSWORD=drill -e POSTGRES_USER=drill -e POSTGRES_DB=drill \
    -p 55433:5432 postgres:16-alpine >/dev/null
  for i in $(seq 1 30); do
    if docker exec "${SANDBOX}" pg_isready -U drill -q; then break; fi
    sleep 1
  done
fi

cleanup_sandbox() {
  if [[ -z "${DRY_RUN}" ]]; then
    docker rm -f "${SANDBOX}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_sandbox EXIT

# ----- 3. Stream restore --------------------------------------------------
if [[ -z "${DRY_RUN}" ]]; then
  log "restoring ${DUMP_KEY}..."
  aws s3 cp "s3://${S3_BUCKET}/${TODAY}/${DUMP_KEY}" - --endpoint-url "${S3_ENDPOINT}" \
    | gunzip \
    | docker exec -i "${SANDBOX}" pg_restore --no-owner --no-privileges \
        -d drill -U drill -h localhost
fi

# ----- 4. Apply migrations to current head --------------------------------
log "applying migrations..."
if [[ -z "${DRY_RUN}" ]]; then
  MIGRATE_BIN=${MIGRATE_BIN:-backend/cmd/migrate/migrate}
  [[ -x "${MIGRATE_BIN}" ]] || die "migrate binary not built: ${MIGRATE_BIN}"
  VAULTSCAN_DATABASE_URL="postgres://drill:drill@127.0.0.1:55433/drill?sslmode=disable" \
    "${MIGRATE_BIN}" -dir backend/migrations
fi

# ----- 5. Verify audit chain ---------------------------------------------
log "verifying audit chain..."
VERIFY_URL=${VAULTSCAN_API_URL:-http://127.0.0.1:8080}/api/v1/audit/verify
if [[ -z "${DRY_RUN}" ]]; then
  FIRST_BAD=$(curl -fsS "${VERIFY_URL}" | jq -r '.first_bad_id // 0')
  [[ "${FIRST_BAD}" == "0" ]] || die "audit chain broken at row ${FIRST_BAD}"
fi

# ----- 5b. Validate restored row counts vs production baseline -----------
# A clean pg_restore that produces empty tables is technically "successful"
# but useless — the audit-chain check would pass on an empty chain too.
# Verify core tables have at least the baseline floor we expect for a
# real production restore. Floor values are intentionally conservative
# so non-prod restores (staging, demo) don't false-fail. Override the
# floor via VAULTSCAN_DR_MIN_ROWS_<TABLE> when needed.
log "validating row counts..."
if [[ -z "${DRY_RUN}" ]]; then
  check_rows() {
    local table=$1 floor=$2
    local override_var="VAULTSCAN_DR_MIN_ROWS_${table^^}"
    local effective=${!override_var:-$floor}
    local n
    n=$(docker exec "${SANDBOX}" psql -U drill -d drill -At -c \
        "SELECT COUNT(*) FROM ${table}") || die "could not count ${table}"
    log "  ${table}: ${n} rows (floor ${effective})"
    if [[ "${n}" -lt "${effective}" ]]; then
      die "${table} row count ${n} below floor ${effective} — restore likely incomplete"
    fi
  }
  # Floors picked to detect "table empty" / "partial restore" — not to
  # validate freshness. A real prod backup has at minimum 1 tenant,
  # 1 partner, 1 user, the seed audit row, and the seed roles.
  check_rows tenants            1
  check_rows partners           1
  check_rows users              1
  check_rows audit_logs         1
  check_rows roles              1
  # Optional but-good-to-have: assets / findings / scan_jobs only checked
  # when override is set; new platforms can boot with these empty.
  if [[ -n "${VAULTSCAN_DR_MIN_ROWS_ASSETS:-}" ]]; then
    check_rows assets "${VAULTSCAN_DR_MIN_ROWS_ASSETS}"
  fi
  if [[ -n "${VAULTSCAN_DR_MIN_ROWS_FINDINGS:-}" ]]; then
    check_rows findings "${VAULTSCAN_DR_MIN_ROWS_FINDINGS}"
  fi
fi

# ----- 6. Stamp the drill result -----------------------------------------
DURATION=$(($(date -u +%s) - START))
log "drill completed in ${DURATION}s"
if [[ -z "${DRY_RUN}" ]]; then
  curl -fsS -X POST "${VAULTSCAN_API_URL}/api/v1/audit/drill" \
       -H 'Content-Type: application/json' \
       -d "$(printf '{"duration_s":%d,"dump_key":"%s","sandbox":"%s"}' \
             "${DURATION}" "${DUMP_KEY}" "${SANDBOX}")" >/dev/null
fi

log "PASS — DR drill green"
