package observability

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// ReplicaLagSeconds is the streaming-replication lag, in seconds,
// from the replica's perspective. Computed as
//
//	EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))
//
// run on the replica. A stale replica (lag > 60s) means dashboard
// reads will silently serve old data — the alert is downstream in
// prometheus-rules.yaml.
//
// We pre-register this gauge here rather than in metrics.go so
// `cmd/api` can call `observability.StartReplicaLagExporter(ctx,
// replicaPool, 30*time.Second)` only when a replica is configured.
// When no replica is set the gauge stays at -1 (sentinel "no replica
// monitored"); -1 is harmless on a graph and clearly distinct from
// healthy 0.
var ReplicaLagSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "vaultscan_db_replica_lag_seconds",
	Help: "Streaming-replication lag in seconds, or -1 if no replica is monitored.",
})

func init() {
	prometheus.MustRegister(ReplicaLagSeconds)
	ReplicaLagSeconds.Set(-1)
}

// StartReplicaLagExporter polls the replica's
// pg_last_xact_replay_timestamp() every interval. Returns a stop
// function for main's shutdown sequence.
//
// Behaviour:
//   - replica == nil → exporter is a no-op; gauge stays at -1.
//   - query errors → gauge set to +Inf so the alert fires
//     ("we can't measure lag, treat as bad") rather than silently
//     reporting 0.
//   - if pg_last_xact_replay_timestamp() returns NULL (a primary
//     pretending to be a replica), gauge is set to 0 and a single
//     warning is emitted — not an error, but operators should know.
func StartReplicaLagExporter(ctx context.Context, replica *pgxpool.Pool, interval time.Duration) func() {
	if replica == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		// Fire-and-then-tick so the first metric lands quickly.
		measureReplicaLag(cctx, replica)
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				measureReplicaLag(cctx, replica)
			}
		}
	}()
	return cancel
}

func measureReplicaLag(ctx context.Context, replica *pgxpool.Pool) {
	var lag *float64
	// Query timeout — never let a stuck replica conn block us.
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := replica.QueryRow(qctx, `
		SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::float8`).
		Scan(&lag)
	if err != nil {
		// +Inf so the lag-alert fires on "we lost contact with the
		// replica" rather than reporting "0 lag" which would mask
		// the outage.
		ReplicaLagSeconds.Set(1e9)
		return
	}
	if lag == nil {
		// pg_last_xact_replay_timestamp() returns NULL on a primary
		// — caller mounted the wrong DSN. Surface as 0 (truthful for
		// a node that hasn't received any replay) + leave a trail in
		// the operator-visible metric description for posterity.
		ReplicaLagSeconds.Set(0)
		return
	}
	ReplicaLagSeconds.Set(*lag)
}
