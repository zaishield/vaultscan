# Multi-region deployment runbook

This document covers the application-layer primitives the platform
provides for multi-region deployment, and what's still needed at
the INFRASTRUCTURE layer that the code can't supply.

## What the application provides

### Replica-aware reads

`db.OpenReplica` opens a separate read-only pool against
`VAULTSCAN_DATABASE_REPLICA_URL`. All connections are pinned to
`default_transaction_read_only = on` so an accidental write fails
loud rather than corrupting state on a fail-over replica.

The convenience wrapper `db.Reader(primary, replica)` returns the
replica if configured, else the primary. Use it from read-only
handlers that tolerate sub-second replication lag (most dashboard
endpoints, list views, long-tail audit queries).

### Read-after-write fencing

The pattern: a user creates a finding, and their next page-load
must see it even if their browser hits a replica that hasn't
caught up. Without fencing, the finding "vanishes for a second."

Code primitives (in `backend/internal/db/replica_lag.go`):

* `db.CurrentLSN(ctx, primary)` — capture the primary's
  `pg_current_wal_lsn()` immediately after a writing transaction
  commits. Returns a `FreshnessToken` opaque to callers.

* `db.ReaderFresh(ctx, primary, replica, token)` — returns the
  replica IFF the replica has already applied `token`'s LSN
  (`pg_last_wal_replay_lsn() >= token`). Otherwise falls back to
  the primary. Same correctness either way; replica path is just
  faster and offloads the primary.

Wire pattern at the HTTP layer:

```go
// In a write handler:
finding, err := svc.CreateFinding(ctx, …)
if err != nil { …; return }
tok, _ := db.CurrentLSN(r.Context(), primary)
w.Header().Set("X-Vaultscan-Freshness", string(tok))   // pass to client
writeJSON(w, http.StatusCreated, finding)

// In a read handler:
tok := db.FreshnessToken(r.Header.Get("X-Vaultscan-Freshness"))
pool, route, _ := db.ReaderFresh(r.Context(), primary, replica, tok)
// Use `pool` for the read; observability counts `route`.
```

The client browser/SDK retains `X-Vaultscan-Freshness` for the
short window when the user expects to see their own writes
(typically the next 2-3 page loads), then drops it.

### Replica lag observability

`db.ReplicaLagTracker` + `db.PollReplicaLag(ctx, primary, replica,
tracker)` — runs a 1-second tick that measures lag in WAL bytes
(via `pg_wal_lsn_diff`) and updates an atomic counter for
Prometheus to scrape. Add the gauge in your `cmd/api` main:

```go
tracker := &db.ReplicaLagTracker{}
go db.PollReplicaLag(ctx, primary.Pool, replica, tracker)
prometheus.NewGaugeFunc(prometheus.GaugeOpts{
    Name: "vaultscan_pg_replica_lag_bytes",
}, func() float64 { return float64(tracker.LagBytes()) })
```

`ReaderFresh` returns a `ReadRoute` enum (`primary_only`,
`replica_caught_up`, `primary_due_to_lag`, etc.) — count each
value as a separate Prometheus counter so operators can see
"how often is the fence kicking in?"

## What the application CANNOT provide (infra-level)

These belong in your deployment overlay (Helm / Terraform), not
in this repo:

### Streaming-replication setup

The replica pool expects a Postgres replica configured via
`pg_basebackup` + `recovery_target_timeline = 'latest'` +
`primary_conninfo` pointing at the primary. The replica's
`hot_standby` must be `on`. Cloud-managed Postgres (AWS RDS,
Cloud SQL, Aurora) handles this for you; on-prem clusters need
explicit configuration.

### Geographic routing

Routing user traffic to the geographically-nearest region is the
job of your CDN / global load balancer (CloudFront with origin
groups, Cloudflare with regional balancing, GCP global LB). The
application's `VAULTSCAN_REGION` env var only tells THIS pod
which region it's serving; it doesn't affect routing.

### Cross-region failover

If the primary region's Postgres goes down, operators promote a
replica in another region via the Postgres operator's
`pg_promote()` (or RDS/Cloud-SQL UI). Application has no role.

What the application DOES require post-failover: every pod must
restart with the new primary's DSN. The pool reconnect logic is
not designed to follow a DNS change live.

### Tenant residency vs region

The application's `tenants.residency` field pins a tenant's
evidence + audit data to a specific region (enforced by
`evidence.ResidencyChecker` on every Record path). This is
ORTHOGONAL to multi-region availability:

* **Residency** = data stays in this region for compliance.
* **Multi-region** = active-active for availability.

A tenant pinned to `eu` MUST be served by an EU pod even when the
US pod is happy. Routing layer enforces this via the
`X-Vaultscan-Region` header that the API surface returns from
tenant lookups. Wiring this into the LB is operational.

## Verification

The application-level primitives are covered by:
- `backend/test/integration/replica_lag_test.go`:
  - `CurrentLSNCapturesWritePosition`: LSN advances after a real
    write through `audit.Record`. Proves the fence cursor works
    end-to-end against a real Postgres.
  - `ReaderFreshFallsBackWithNoReplica`: single-region deploy
    (no replica configured) routes everything to the primary.
  - `RouteStrings`: the operator-facing labels are stable
    (Prometheus dashboards depend on them).

Run them:
```bash
cd backend && VAULTSCAN_TEST_DATABASE_URL=... \
  go test -tags=integration -v -run TestReplicaLag \
  ./test/integration/...
```

A staging environment with a configured replica is the right
place to verify the full fence flow (`ReplicaCaughtUp` /
`PrimaryDueToLag` routes); the application code is ready,
the infra needs to be present.
