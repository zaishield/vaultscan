# VAULTSCAN Performance Test Suite

k6-based load tests that exercise the production SLOs called out in
Blueprint §11 + §27.4:

| SLO                            | Target                          |
|--------------------------------|---------------------------------|
| API median latency             | ≤ 250 ms                        |
| API P95 latency                | ≤ 1.0 s                         |
| API P99 latency                | ≤ 2.5 s                         |
| API error rate                 | < 0.5 %                         |
| Concurrent scan submissions    | ≥ 100 RPS sustained             |
| Emergency-stop SLA             | ≤ 30 s end-to-end (§11.6)       |
| Findings ingest throughput     | ≥ 50 findings/sec sustained     |

## Layout

```
perf/
├── README.md                       — this file
├── scenarios/
│   ├── api_smoke.js                — 10 VUs × 30 s, all read endpoints
│   ├── api_steady.js               — 100 VUs × 5 min sustained mixed load
│   ├── api_spike.js                — 0 → 500 VUs in 30 s, holds for 1 min
│   ├── scan_submit_burst.js        — submits 1000 scans in 60 s
│   ├── findings_ingest_burst.js    — 50 findings/s sustained for 5 min
│   └── emergency_stop_sla.js       — measures end-to-end stop latency
├── lib/
│   ├── auth.js                     — token mint helper
│   ├── tenants.js                  — pulls a real tenant_id from /api
│   └── thresholds.js               — shared SLO thresholds
└── run-baseline.sh                 — orchestrates a full baseline run
```

## Running

Prereqs:

  brew install k6                            # macOS
  apt-get install k6                          # Debian/Ubuntu
  # or via the official Docker image:
  docker run --rm -i grafana/k6 run - < scenarios/api_steady.js

Local:

  export VAULTSCAN_API_URL=http://localhost:8080
  export VAULTSCAN_LOAD_TOKEN=<bearer JWT>     # mint via dev-token endpoint
  export VAULTSCAN_TENANT_ID=<uuid>
  k6 run perf/scenarios/api_steady.js

Full baseline (writes JSON summary + Markdown report under perf/results/):

  ./perf/run-baseline.sh staging

## Reading the results

Each scenario emits a per-stage `--summary-export` JSON file. The
runner script `run-baseline.sh` aggregates them into a single
`perf/results/baseline-<timestamp>.md` report with PASS/FAIL per
SLO, suitable for posting on the release ticket.

## Design notes

- All scenarios use a single shared bearer token issued via the
  dev-token endpoint. Production load tests should mint a
  short-lived RBAC-bound token via the standard /api/v1/auth/login
  flow + MFA.
- We deliberately don't hammer write endpoints in `api_steady` to
  avoid filling the DB during a 5-minute soak. Use
  `scan_submit_burst.js` + `findings_ingest_burst.js` for write-side
  baselines.
- Thresholds are encoded in `lib/thresholds.js` and reused by every
  scenario so a global SLO change is one edit.
