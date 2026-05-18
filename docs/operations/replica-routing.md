# Read-Replica Routing Runbook

## Architecture

The API binary opens an optional read-only Postgres pool driven by
`VAULTSCAN_DATABASE_REPLICA_URL`. Heavy-read endpoints route through
it; writes always hit the primary.

```
            ┌──────────────────┐
            │   pgbouncer      │ (or direct)
  WRITES →  │  PRIMARY (RW)    │
            └──────────────────┘
                     │  streaming replication
                     ↓
            ┌──────────────────┐
            │   pgbouncer      │
  READS  →  │  REPLICA (RO)    │
            └──────────────────┘
```

## Reads that route through the replica

| Service method                  | Endpoint                       |
| ------------------------------- | ------------------------------ |
| dashboards.Executive            | GET /api/v1/dashboards         |
| dashboards.Technical            | GET /api/v1/dashboards         |
| dashboards.Partner              | GET /api/v1/dashboards/partner |
| dashboards.CriticalFindings     | drill-down                     |
| dashboards.SLABreaches          | drill-down                     |
| dashboards.RecentScans          | drill-down                     |

Endpoints not on this list still hit the primary. Adding more endpoints
to the replica list is a code change in `internal/dashboards/service.go`
(call `s.reader()` instead of `s.pool`) — straightforward, but verify
the data is OK to be slightly stale.

## Replica safety guarantees

1. `default_transaction_read_only = on` is set on every replica
   connection via AfterConnect — an accidental INSERT/UPDATE returns
   "cannot execute INSERT in a read-only transaction" rather than
   silently committing on a promoted ex-replica.

2. Reader() falls back to the primary when no replica is configured,
   so handlers never need to branch.

3. Replica lag is monitored via `vaultscan_db_replica_lag_seconds`.

## Lag alerts

| Alert                       | Condition                | Action            |
| --------------------------- | ------------------------ | ----------------- |
| VaultScanReplicaLagging     | lag > 60s for 5m         | investigate IO/WAL |
| VaultScanReplicaUnreachable | exporter can't reach     | check replica health |

## Promoting / failing over

When the primary fails or you need to swap nodes:

1. **Block writes**: scale the API + agent-gateway + scanner-worker
   to 0 (or set a feature flag).
2. **Confirm lag is 0**: `SELECT pg_last_xact_replay_timestamp()` on
   replica should be ≤ 1s old.
3. **Promote**: `SELECT pg_promote()` on the replica.
4. **Flip DSNs**:
   - Set `VAULTSCAN_DATABASE_URL` on all pods to the new primary.
   - Clear or update `VAULTSCAN_DATABASE_REPLICA_URL` (the old
     primary is now the read source once it catches up as a replica).
5. **Scale back up**.

The `default_transaction_read_only` setting will need to be cleared
on the new primary — `ALTER SYSTEM SET default_transaction_read_only
= off; SELECT pg_reload_conf();`.

## Disabling the replica

Clear `VAULTSCAN_DATABASE_REPLICA_URL`, roll the API deployment. All
reads route to the primary. `vaultscan_db_replica_lag_seconds` will
revert to -1 (sentinel "no replica monitored").

## Sizing

Replica defaults: 75 max conns, 30s statement timeout. Override via:

- `VAULTSCAN_PG_REPLICA_MAX_CONNS`
- `VAULTSCAN_PG_REPLICA_MIN_CONNS`
- `VAULTSCAN_PG_REPLICA_STATEMENT_TIMEOUT`

The replica statement timeout is longer than the primary's (30s vs
15s) because analytics aggregations on the replica can legitimately
scan large tables.
