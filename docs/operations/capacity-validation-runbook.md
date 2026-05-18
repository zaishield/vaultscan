# Capacity validation runbook — running the k6 measurement

Procedure to validate the capacity numbers in
`capacity-planning.md` against a real cluster before signing
customer contracts. Run this once per environment shape (cloud +
region + tier), then keep the artifact for sales / compliance.

## When to run

| Trigger | Owner | Cadence |
| --- | --- | --- |
| First production deployment | platform eng | once, blocks GA |
| Cloud / instance-type change | platform eng | once per change |
| Tenant count crosses 2× target | platform eng | as it happens |
| SOC2 Type II annual control review | compliance | once a year |
| Customer-requested capacity attestation | sales eng | per request |

## Prereqs

```bash
# 1. k6 ≥ 0.50 installed on a load-generator host SEPARATE from
#    the target cluster (running k6 in-cluster distorts the result).
k6 version

# 2. Target environment is staging or a sized-down prod. Never run
#    against a tenant-bearing prod cluster.
export VAULTSCAN_API_URL=https://api-staging.vaultscan.zaishield.com

# 3. Operator JWT — issue one via the dev-token endpoint OR mint
#    via the admin SCIM flow. Must have `scan_submit` permission.
export VAULTSCAN_TEST_TOKEN=$(curl -s "$VAULTSCAN_API_URL/api/v1/auth/dev-token" \
  -d '{"email":"loadtest@example.com","roles":["operator"]}' | jq -r .token)

# 4. Prometheus reachable from the load-gen host.
export PROMETHEUS_URL=https://prometheus-staging.vaultscan.zaishield.com

# 5. Notebook to record results.
mkdir -p /var/lib/vaultscan-capacity/$(date +%F)
cd /var/lib/vaultscan-capacity/$(date +%F)
```

## Seed the target tenant count

```bash
cd /path/to/vaultscan/tools/scripts/load-test

# 100 tenants for a smoke (~15 min run).
# 500 tenants for the production-shape claim (~45 min run).
# 2000 tenants if you need to validate "platform" tier.
./seed.sh 500
# Records the seed manifest at out/seed-manifest.json so you can
# tear down after.
```

## Baseline snapshot

```bash
# Capture Prometheus baseline so you can compute deltas over the run.
QUERIES=(
  "vaultscan_db_pool_acquired"
  "vaultscan_db_pool_max"
  "vaultscan_request_total"
  "vaultscan_request_errors"
  "vaultscan:api_request_latency_p95:5m"
  "vaultscan:api_request_latency_p99:5m"
  "vaultscan:api_request_success_ratio:5m"
  "vaultscan_db_replica_lag_seconds"
  "vaultscan_audit_chain_breaks_total"
  "vaultscan_db_pool_acquire_canceled_total"
  "vaultscan_circuit_breaker_state"
)
for q in "${QUERIES[@]}"; do
  echo "=== $q ==="
  curl -fsS "$PROMETHEUS_URL/api/v1/query?query=$(jq -rn --arg q "$q" '$q|@uri')" \
    | jq -c .data.result
done | tee baseline.txt
```

## Run

```bash
# baseline.js is the canonical scenario:
#   - 100 concurrent VUs for 15 min steady-state
#   - mix: 60% dashboard reads, 20% finding triage, 15% scan submit,
#     5% report generate
k6 run baseline.js \
  --env API_URL="$VAULTSCAN_API_URL" \
  --env TOKEN="$VAULTSCAN_TEST_TOKEN" \
  --out json=run-$(date +%FT%H-%M).json \
  --summary-export=summary.json

# Open a second terminal during the run; record live Prometheus
# every 60s so you have a time series of the steady state.
while true; do
  date -Iseconds
  for q in "${QUERIES[@]}"; do
    printf "  %s = " "$q"
    curl -fsS "$PROMETHEUS_URL/api/v1/query?query=$(jq -rn --arg q "$q" '$q|@uri')" \
      | jq -c '.data.result[0].value[1]'
  done
  sleep 60
done | tee during.txt
```

## Acceptance criteria

The run is ACCEPTED only if EVERY criterion below holds:

| Metric | Target | Source |
| --- | --- | --- |
| `http_req_duration p95` | < 500 ms | k6 summary.json |
| `http_req_duration p99` | < 1500 ms | k6 summary.json |
| `http_req_failed rate` | < 0.001 (0.1%) | k6 summary.json |
| `iteration_duration p95` | < 30 s | k6 summary.json |
| `vaultscan_db_pool_acquired / max` steady-state | < 0.5 | Prometheus during.txt |
| `vaultscan_db_replica_lag_seconds` max | < 5 | Prometheus during.txt |
| `vaultscan_audit_chain_breaks_total` delta | 0 | Prometheus delta baseline vs final |
| `vaultscan_db_pool_acquire_canceled_total` delta | 0 | Prometheus delta |
| `vaultscan_circuit_breaker_state` for any breaker | 0 (closed) at run end | Prometheus during.txt last sample |

If ANY criterion fails, file an issue with:
- the seed count + cluster shape (instance types, node count, DB tier)
- the failing criterion + the actual value
- a link to `run-*.json` + `during.txt` + `baseline.txt`

Engineering investigates BEFORE the capacity claim ships.

## After the run

```bash
# 1. Capture the artifact bundle.
tar czvf capacity-run-$(date +%F).tgz \
  baseline.txt during.txt run-*.json summary.json
sha256sum capacity-run-*.tgz > capacity-run.sha256

# 2. Upload to the long-term evidence store (S3 / GCS bucket the
#    compliance team controls). DO NOT lose this — sales and
#    auditors will reference it.
aws s3 cp capacity-run-*.tgz \
  s3://vaultscan-compliance-evidence/capacity/$(date +%F)/

# 3. Update docs/operations/capacity-planning.md if the run produced
#    materially different numbers than the doc claims.

# 4. Tear down the seeded tenants.
cd /path/to/vaultscan/tools/scripts/load-test
./teardown.sh out/seed-manifest.json
```

## Sign-off

The capacity-validation artifact becomes part of the change log
that gates the next minor release. Engineering lead + product
sign-off required before customer-facing capacity numbers in the
website / data sheet / contract are updated.
