# Capacity Planning

This document captures the per-component resource model that operators
use to size a VaultScan deployment. The numbers below come from
production-scale load tests + observed steady-state metrics from
multi-tenant deployments.

The platform is sized by **two primary inputs**:

1. **active tenants** (T) — directly drives users, audit rows, RLS
   evaluations, and per-tenant DEK cache size.
2. **concurrent scans** (S) — drives scanner-worker, evidence-storage
   throughput, and findings-ingest rate.

Most other dimensions (engagements, assets, partners) scale linearly
with T and are an order of magnitude cheaper, so they're not on the
critical path.

## Per-component sizing

### `api` (cmd/api)

| Driver               | Resource consumed     | Rule of thumb                |
| -------------------- | --------------------- | ---------------------------- |
| Concurrent requests  | CPU, pool connections | 1 vCPU per ~200 RPS sustained |
| Active tenants       | Memory (cache)        | ~5 MB/tenant in DEK + branding caches |
| Audit query patterns | DB primary load       | 1 read-replica per 500 active tenants |

**Pool size**: see `VAULTSCAN_PG_MAX_CONNS_API` (default 50).
At 80% utilisation sustained for 5 min the
`VaultScanDBPoolNearSaturation` alert fires.

**Replica routing**: when `VAULTSCAN_DATABASE_REPLICA_URL` is set the
heavy read endpoints (`/api/v1/findings`, `/api/v1/assets`,
`/api/v1/dashboards`, `/api/v1/audit`) route through the replica. The
primary's pool then handles writes + light reads only; expect a 60-70%
read reduction on the primary.

**Recommended replicas**: 3 minimum for HA, scale by RPS.

### `scanner-worker` (cmd/scanner-worker)

| Driver           | Resource consumed | Rule of thumb               |
| ---------------- | ----------------- | --------------------------- |
| Concurrent scans | CPU, RAM          | 1 vCPU / 2 GB per concurrent scan |
| Region pinning   | Replica count     | minimum 1 per region        |
| Tool execution   | Disk (ephemeral)  | 10 GB per worker (scratch + reports) |

**MaxConcurrent** per worker is hardcoded to 4 (see
`scanner.NewWorker`). To increase region throughput, add replicas — one
worker holds `MaxConcurrent` job claims and races other replicas via
`FOR UPDATE SKIP LOCKED`.

**Network egress**: budget 50-100 KB per finding ingested back to the
API.

### `agent-gateway` (cmd/agent-gateway)

| Driver             | Resource consumed   | Rule of thumb              |
| ------------------ | ------------------- | -------------------------- |
| Connected agents   | Memory, CPU         | ~1 MB / agent + heartbeat decoding |
| mTLS handshakes    | CPU                 | 1 vCPU per 200 concurrent reconnects |
| Job dispatch rate  | DB primary, pool    | counts against `VAULTSCAN_PG_MAX_CONNS_AGENT_GATEWAY` (default 20) |

**Recommended replicas**: 2 minimum (HA); scale by connected-agent
count.

### `analytics-worker` (cmd/analytics-worker)

| Driver                  | Resource consumed    | Rule of thumb               |
| ----------------------- | -------------------- | --------------------------- |
| Events indexed/sec      | OpenSearch bulk RAM  | ~100 events/sec per worker  |
| OpenSearch retention    | OS disk              | 1 KB per indexed event      |

**Pool**: 8 connections (analytics-worker default). The worker
rarely hits the primary directly — most state is in OpenSearch.

### `cron-runner` (cmd/cron-runner)

Single replica baseline; **leader-elected** at the per-job level via
Postgres advisory locks, so multi-replica is safe but unnecessary for
correctness. Bump to 2 replicas for HA-during-rolling-restart.

| Driver           | Resource consumed | Rule of thumb              |
| ---------------- | ----------------- | -------------------------- |
| Active tenants   | DB primary        | ~100ms per job-tick / 1000 tenants |
| Audit chain size | Verification cost | hourly VerifyDeep budgets 15 minutes |

### Postgres primary

The platform's authoritative store. Hot tables (audit_logs, findings,
scan_jobs, bus_events) are partitioned by month — see
`docs/operations/database-partitioning.md`.

**Sizing**:

- **8 vCPU / 32 GB RAM / NVMe SSD** for up to 500 active tenants and
  100k scans/month.
- **16 vCPU / 64 GB RAM** for 2,000 active tenants and 500k scans/month.
- Beyond that: shard by partner_id range with
  `tenant_pool_routing.dedicated_pool_dsn` for the top 10% noisy
  tenants and keep the long tail on the shared pool.

**Replica**: a single async streaming replica is enough for the
read-routing described above. Expect ~500ms lag at peak; the
read-replica handlers all tolerate it.

### OpenSearch

Storage cost scales linearly with audit + findings volume. Typical
deployments allocate **2-week hot, 90-day warm, 1-year cold** via
ILM. See `docs/operations/database-partitioning.md` for the analogous
Postgres cadence — keep them aligned.

## Saturation playbook

When `VaultScanDBPoolNearSaturation` fires:

1. Inspect `vaultscan_db_pool_acquire_wait_seconds_total` rate — if
   it climbs >0.5/sec, requests are queueing.
2. First lever: scale the affected component (more replicas).
3. Second lever: bump `VAULTSCAN_PG_MAX_CONNS_<COMPONENT>` and roll
   the deployment.
4. Third lever: if the primary itself is the bottleneck, route more
   read endpoints to the replica or add a second replica (then
   round-robin in pgbouncer).

When `VaultScanScannerJobsBacklog` fires:

1. Add scanner-worker replicas in the affected region.
2. Verify all tools (nuclei, zap, naabu) are healthy on the new
   replicas via the `/api/v1/scanner-health` endpoint.

## Reference load test

`tools/scripts/load-test/` (separate from the dev-stack) drives the
following baseline:

- 10 concurrent users per tenant
- 5 scans/hour/tenant
- 50 evidence uploads/hour/tenant
- Full report generation every 24 hours

A 500-tenant deployment under that load fits in a 4-replica `api` +
2-replica `agent-gateway` + 2-replica per-region `scanner-worker` +
the 8 vCPU primary above, with sustained pool utilisation around 40%.
