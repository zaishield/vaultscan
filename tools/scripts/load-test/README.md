# VaultScan Load Test Harness

Reproducible load test referenced by `docs/operations/capacity-planning.md`.
The numbers in the capacity doc come from this harness running
against a freshly-migrated DB with 500 seeded tenants.

## Requirements

- [k6](https://k6.io) ≥ 0.50 (`brew install k6` / `apt install k6`)
- A running VaultScan API with seeded data (use `seed.sh` below)
- `VAULTSCAN_API_URL` and a long-lived operator JWT in
  `VAULTSCAN_TEST_TOKEN`

## Quick start

```bash
# 1. Seed 500 tenants + supporting fixtures (idempotent).
./seed.sh

# 2. Run the baseline scenario.
k6 run baseline.js
```

## Scenarios

| File             | What it drives                            |
| ---------------- | ----------------------------------------- |
| baseline.js      | 10 concurrent users / tenant; 5 scans/hr |
| dashboard.js     | Dashboard polling only (replica-routed)   |
| heavy-write.js   | Asset creates + finding ingest            |
| sustained-72h.js | 72-hour soak test (run on a build box)    |

Each scenario emits a JSON summary under `out/<scenario>-<date>.json`.
The Grafana folder under `infra/dashboards/` ingests this format.

## Baseline targets

The capacity doc claims the following at the 500-tenant baseline:

- API P95 latency < 500ms
- Pool utilisation < 50% steady state
- 0 failed scans, 0 audit chain breaks
- Replica lag < 5s

If your run misses any of these, file a regression — the capacity
guidance must stay honest.
