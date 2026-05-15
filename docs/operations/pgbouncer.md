# pgBouncer Operations

## Why

Each backend pod opens up to `VAULTSCAN_PG_MAX_CONNS` (default 32)
direct connections to Postgres. With 3 replicas of `api`,
`agent-gateway`, `scanner-worker`, `analytics-worker`, `cron-runner` =
**up to 480 simultaneous server connections** before any traffic.
Stock Postgres `max_connections` is 100; managed services typically
cap at 200-500.

PgBouncer multiplexes hundreds of client connections onto a small
fixed-size pool of server connections, so the upstream Postgres only
sees `defaultPoolSize` (default 25) at a time per (db, user) pair.

## Two pools, two endpoints

The chart deploys two pgBouncer instances because pool mode tradeoffs
matter:

| Mode | Tradeoff | Used by |
|---|---|---|
| transaction | Server conn returned to pool at COMMIT. Cannot use LISTEN/NOTIFY, prepared statements with non-default options, advisory locks across statements. Highest density. | `api`, `agent-gateway`, `scanner-worker`, `analytics-worker` |
| session | Server conn pinned to client for the entire client session. Required for `internal/leader.Run` (advisory locks). Lower density. | `cron-runner` |

Two distinct Service endpoints surface them:

```
vaultscan-pgbouncer-tx       :5432   →  pool-mode=transaction
vaultscan-pgbouncer-session  :5432   →  pool-mode=session
```

## Wiring the backend

Set `VAULTSCAN_DATABASE_URL` per-pod to point at the right pool:

```yaml
api:
  env:
    - name: VAULTSCAN_DATABASE_URL
      value: "postgres://vaultscan:****@vaultscan-pgbouncer-tx:5432/vaultscan?sslmode=require"

cronRunner:
  env:
    - name: VAULTSCAN_DATABASE_URL
      value: "postgres://vaultscan:****@vaultscan-pgbouncer-session:5432/vaultscan?sslmode=require"
```

Reduce per-pod `VAULTSCAN_PG_MAX_CONNS` from the default 32 to a
smaller number (e.g. 8) — pgBouncer is now the connection multiplier.

## SLOs

- p95 connection acquire latency (client side): **≤ 50ms**
- pgBouncer-side `MAX_CLIENT_CONN` saturation: alert at **>80%**
- upstream Postgres `pg_stat_activity` count: **≤ 200** sustained

## Tuning

- If `transaction.defaultPoolSize` saturates, raise it carefully —
  every increment is `replicaCount × n` more server conns.
- `RESERVE_POOL_SIZE` lets bursts steal from a small reserve before
  queuing.
- `SERVER_RESET_QUERY: DISCARD ALL` (set by chart) clears session
  state when a server conn is recycled — without this, prepared
  statements leak.

## Failure modes

- **pgBouncer pod dies**: clients reconnect, pool drains; recovers in
  seconds. Set `replicaCount >= 2` for transaction pool.
- **Upstream Postgres slow**: pgBouncer queues clients up to
  `MAX_CLIENT_CONN`; beyond that, new connections get a "too many
  client connections" error. Raise the limit OR scale out backend
  pods.
- **Long-running query holds a server conn**: blocks the pool. Set
  `query_timeout` upstream (Postgres `statement_timeout` GUC) and
  alert on connections held > 30s.

## Direct-to-Postgres path (escape hatch)

For migration runs (`backend/cmd/migrate`) and ad-hoc DDL, talk to
upstream Postgres directly — skip the pooler. DDL emits transaction
state pgBouncer can't reset cleanly. The migrations job in the chart
already wires this via `databases.external.postgresURL` rather than
the pooler service.
