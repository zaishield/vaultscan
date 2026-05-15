// Package leader implements per-job leader election via Postgres
// advisory locks.
//
// Multi-replica cron-runners would otherwise fire every job on every
// pod (e.g. running pg_dump twice, double-billing notifications). The
// classic Kubernetes pattern is the lease/lock-loop in
// k8s.io/client-go/tools/leaderelection — but that requires a
// kubeconfig + RBAC and only works inside Kubernetes. We already have
// Postgres everywhere, so we use pg_try_advisory_lock for the same
// outcome with one less dependency.
//
// Semantics:
//
//   pg_try_advisory_lock(key)  — non-blocking; returns true if THIS
//                                session got the lock, false if some
//                                other session holds it.
//   pg_advisory_unlock(key)    — releases. The lock auto-releases on
//                                connection close, so even a kill -9
//                                can't deadlock the next leader.
//
// Each cron job picks a stable int64 derived from its name (FNV-1a
// hashed). Multiple jobs (and multiple cron-runner pods) share the
// pool but only ONE pod's session per job key holds the lock at a
// time.
//
// Invariant: a job runs only when this pod holds the lock. The lock
// is held for the lifetime of one tick execution, then released so a
// surviving replica can take over for the next tick if the leader
// dies between ticks. (The brief unlocked window is acceptable for
// cron — we don't lose ticks because every replica still attempts to
// acquire on schedule.)

package leader

import (
	"context"
	"hash/fnv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// jobKey converts a stable job name to the int64 key pg_*_advisory_lock
// expects. FNV-1a 64-bit so different jobs essentially never collide
// (cosmically improbable for our < 100 job count).
func jobKey(name string) int64 {
	h := fnv.New64a()
	h.Write([]byte("vaultscan-cron-" + name))
	// pg_advisory_lock takes int64; reinterpret the uint64 hash.
	return int64(h.Sum64())
}

// TryAcquire attempts to grab the per-job advisory lock on a dedicated
// connection. Returns the connection (caller MUST release it via
// Release once the work is done) and true on success. On failure
// returns (nil, false, nil) — not an error, just lost the race.
//
// The connection MUST be held across the work; releasing it (even
// implicitly via pool reclaim) drops the lock.
func TryAcquire(ctx context.Context, pool *pgxpool.Pool, jobName string) (*pgxpool.Conn, bool, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx,
		`SELECT pg_try_advisory_lock($1)`, jobKey(jobName)).Scan(&got); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !got {
		conn.Release()
		return nil, false, nil
	}
	return conn, true, nil
}

// Release drops the lock and returns the connection to the pool.
// Always pair with a deferred call right after a successful TryAcquire.
func Release(ctx context.Context, conn *pgxpool.Conn, jobName string) {
	if conn == nil {
		return
	}
	// Best-effort; even if unlock fails, conn.Release will drop the
	// session lock since pg_advisory_lock is session-scoped.
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, jobKey(jobName))
	conn.Release()
}

// Run wraps fn with TryAcquire + Release. Returns (true, fn-err) when
// this pod was the leader for this tick, (false, nil) when another pod
// held the lock. The caller can use the bool to surface follower
// behaviour in metrics ("vaultscan_cron_followed_total{job=...}").
func Run(ctx context.Context, pool *pgxpool.Pool, jobName string, fn func(ctx context.Context) error) (wasLeader bool, err error) {
	conn, got, err := TryAcquire(ctx, pool, jobName)
	if err != nil {
		return false, err
	}
	if !got {
		return false, nil
	}
	defer Release(ctx, conn, jobName)
	return true, fn(ctx)
}
