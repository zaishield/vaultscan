# HS-04 · Performance & Scale Testing

Benchmarks and SLO targets, reproducible via `tools/scripts/bench/`.

| Acceptance Criterion                                                    | Approach |
|-------------------------------------------------------------------------|----------|
| 500 concurrent API requests within SLA, no 5xx                          | `tools/scripts/bench/api-load.sh` (k6 / hey); target P99 < 500 ms |
| 10 simultaneous external scans without pod interference                  | `tools/scripts/bench/scanner-soak.sh` launches 10 scan jobs across 3 K8s scanner nodes |
| 50 agents maintain heartbeat under 30s                                   | `tools/scripts/bench/agent-fleet.sh` fakes 50 agent identities + heartbeats |
| 10 000 findings/hour ingestion without queue saturation                  | `tools/scripts/bench/ingest.sh` posts NDJSON of synthetic findings |
| PDF report for 1 000-finding engagement < 60s                            | `tools/scripts/bench/report-pdf.sh` measures end-to-end latency |
| 3 dashboards load < 3s with 100 concurrent users                          | `tools/scripts/bench/dashboard.sh` |

## Tuning levers

- `pgxpool.MaxConns`: 32 default in `backend/internal/db/db.go`; raise to 128 in prod
- API rate limit: `VAULTSCAN_RATE_LIMIT_RPS` per identity / IP
- OpenSearch: separate `analytics` index per tenant for fast aggregations
