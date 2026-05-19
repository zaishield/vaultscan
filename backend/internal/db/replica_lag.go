// replica_lag.go — replica-aware reads with read-after-write
// fencing. Closes the multi-region-readiness gap that previously
// said "the application has no awareness of replica lag, no read-
// after-write fencing on critical reads."
//
// The pattern this implements is the standard one for primary-
// follower Postgres:
//
//   1. Every WRITE captures the primary's `pg_current_wal_lsn()`
//      (server-generated 64-bit log-sequence number) into a token
//      we pass back to the caller.
//   2. The caller stamps that token on the request (as a header
//      or a context value) for the next ~few-second window when
//      the user expects to see their own write.
//   3. Every READ that carries the token routes to the replica
//      iff the replica has already applied that LSN — checked via
//      `pg_last_wal_replay_lsn() >= $token`. If not, the read
//      falls through to the primary.
//
// Without this, a user clicks "create finding" and the next page
// load might hit a replica that hasn't replicated yet — the
// finding appears to vanish for a second. With this, the post-
// create read is fenced to either the primary or a replica
// that's caught up. Same correctness in either case.
//
// Honest scope: the LSN tracking lives at the db layer; it's the
// HANDLER's job to capture the LSN on writes and pass the token
// through to reads. The wrapper here is the primitive that
// makes that possible; wiring it into every write handler is
// follow-up work that the OperationLog plumbing already does for
// the highest-traffic surfaces.

package db

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FreshnessToken is an opaque cursor that captures a primary
// write's position. Pass it to ReaderFresh to ensure subsequent
// reads see at least the writes that produced this token.
//
// The value is a Postgres LSN ("a/b" hex form) cast to a string.
// It's opaque to callers; only the db package interprets it.
type FreshnessToken string

// IsZero returns true for the empty cursor.
func (f FreshnessToken) IsZero() bool { return string(f) == "" }

// CurrentLSN queries the primary for the latest WAL position. Used
// by write paths immediately after the writing transaction commits;
// the returned token represents "everything up to and including the
// write you just did is now in this LSN."
//
// Cheap (returns a single int8); safe to call on every write.
func CurrentLSN(ctx context.Context, primary *pgxpool.Pool) (FreshnessToken, error) {
	var lsn string
	err := primary.QueryRow(ctx, `SELECT pg_current_wal_lsn()::text`).Scan(&lsn)
	if err != nil {
		// `pg_current_wal_lsn` requires a writable connection. If
		// the primary returned an error we should NOT silently
		// degrade to "no fence" — return empty + the error so the
		// caller knows to retry / log.
		return "", fmt.Errorf("db: read current LSN: %w", err)
	}
	return FreshnessToken(lsn), nil
}

// replicaCaughtUp reports whether the replica has applied at least
// `token`. Uses pg_last_wal_replay_lsn() — the position the replica
// has finished applying. If the replica hasn't seen `token` yet,
// the helper returns false and the caller falls back to the primary.
//
// The query itself is cheap (one int8 read); we add a connection
// timeout so a flapping replica doesn't pin the request.
func replicaCaughtUp(ctx context.Context, replica *pgxpool.Pool, token FreshnessToken) (bool, error) {
	if token.IsZero() {
		// No token = no freshness requirement, replica is always
		// "caught up enough."
		return true, nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	var ok bool
	err := replica.QueryRow(checkCtx,
		`SELECT pg_last_wal_replay_lsn() >= $1::pg_lsn`, string(token)).Scan(&ok)
	if err != nil {
		// Replica is down / lagging on the meta query itself —
		// fall back conservatively to NOT-caught-up so the caller
		// uses the primary. Surface the error so observability sees it.
		return false, err
	}
	return ok, nil
}

// ReplicaLagTracker is the optional observability hook. Production
// wires this to a Prometheus gauge so operators see the lag in
// real time. The application doesn't gate on it; it's purely
// informational. ReaderFresh uses the live `pg_last_wal_replay_lsn`
// check instead, which is authoritative.
type ReplicaLagTracker struct {
	bytes atomic.Int64
}

// SetLagBytes records the current observed lag in WAL bytes.
// Operator code that calls this typically does so on a 1s tick.
func (r *ReplicaLagTracker) SetLagBytes(n int64) { r.bytes.Store(n) }

// LagBytes returns the most recently observed lag.
func (r *ReplicaLagTracker) LagBytes() int64 { return r.bytes.Load() }

// PollReplicaLag is the background loop that keeps the tracker
// up to date. Operators run this in a goroutine; it terminates
// when ctx cancels. Safe to call without a replica configured —
// returns immediately.
func PollReplicaLag(ctx context.Context, primary *pgxpool.Pool, replica *ReplicaPool, tracker *ReplicaLagTracker) {
	if replica == nil || replica.Pool == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bytes, err := MeasureReplicaLagBytes(ctx, primary, replica.Pool)
			if err == nil {
				tracker.SetLagBytes(bytes)
			}
		}
	}
}

// MeasureReplicaLagBytes returns the byte-distance the replica is
// behind the primary. Single-query measurement used by the
// background poller.
func MeasureReplicaLagBytes(ctx context.Context, primary, replica *pgxpool.Pool) (int64, error) {
	var primaryLSN string
	if err := primary.QueryRow(ctx, `SELECT pg_current_wal_lsn()::text`).Scan(&primaryLSN); err != nil {
		return 0, err
	}
	// Compare on the replica using pg_wal_lsn_diff (returns numeric
	// bytes). pg_wal_lsn_diff(primary, replica_replay) >= 0 if
	// replica is behind or equal.
	var bytes int64
	checkCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	err := replica.QueryRow(checkCtx,
		`SELECT pg_wal_lsn_diff($1::pg_lsn, pg_last_wal_replay_lsn())::bigint`, primaryLSN).
		Scan(&bytes)
	if err != nil {
		return 0, err
	}
	if bytes < 0 {
		bytes = 0 // clamp clock-skew edge cases
	}
	return bytes, nil
}

// ReaderFresh is the read-after-write-aware Reader. Returns the
// replica pool IFF the replica has applied at least `token`'s LSN;
// otherwise returns the primary.
//
// Semantics:
//   * token.IsZero()       → returns replica (or primary if none).
//                            Equivalent to the existing Reader().
//   * replica==nil         → returns primary. Single-region deploy
//                            ignores the token entirely (writes are
//                            immediately visible to reads).
//   * replica caught up    → returns replica. Read is replica-lag-
//                            tolerant; lower latency + load.
//   * replica behind       → returns primary. Read is "fresh" — no
//                            stale data window.
//
// The bool return tells the caller WHICH route was taken so
// observability can count {fresh_primary_reads, fresh_replica_reads,
// fallback_primary_reads}. Most callers will ignore it.
func ReaderFresh(ctx context.Context, primary *pgxpool.Pool, replica *ReplicaPool, token FreshnessToken) (*pgxpool.Pool, ReadRoute, error) {
	if replica == nil || replica.Pool == nil {
		return primary, ReadRoutePrimaryOnly, nil
	}
	if token.IsZero() {
		return replica.Pool, ReadRouteReplicaUnfenced, nil
	}
	ok, err := replicaCaughtUp(ctx, replica.Pool, token)
	if err != nil {
		// Replica-side error — fall back to primary. Don't fail the
		// request; degraded performance is better than degraded
		// availability.
		return primary, ReadRouteFallbackOnReplicaError, err
	}
	if !ok {
		return primary, ReadRoutePrimaryDueToLag, nil
	}
	return replica.Pool, ReadRouteReplicaCaughtUp, nil
}

// ReadRoute is the categorical signal ReaderFresh returns alongside
// the pool. Operators wire each value to a separate Prometheus
// counter so they can see at a glance:
//
//   - How often the fence kicks in (PrimaryDueToLag)
//   - How often the replica errors (FallbackOnReplicaError)
//   - How often the happy-path replica is hit
//
// A sudden surge in PrimaryDueToLag means the replica is lagging
// badly — operators should investigate before that traffic starts
// hitting the primary's connection cap.
type ReadRoute int

const (
	ReadRoutePrimaryOnly             ReadRoute = iota // no replica configured
	ReadRouteReplicaUnfenced                          // no token → replica
	ReadRouteReplicaCaughtUp                          // token, replica caught up → replica
	ReadRoutePrimaryDueToLag                          // token, replica behind → primary
	ReadRouteFallbackOnReplicaError                   // replica meta-query failed → primary
)

func (r ReadRoute) String() string {
	switch r {
	case ReadRoutePrimaryOnly:
		return "primary_only"
	case ReadRouteReplicaUnfenced:
		return "replica_unfenced"
	case ReadRouteReplicaCaughtUp:
		return "replica_caught_up"
	case ReadRoutePrimaryDueToLag:
		return "primary_due_to_lag"
	case ReadRouteFallbackOnReplicaError:
		return "primary_replica_error"
	default:
		return "unknown"
	}
}

// ErrReplicaTokenStale is returned by callers that REFUSE to fall
// back to the primary on a stale token. Most callers DON'T do
// this — they tolerate the primary fallback. The exception is a
// caller that explicitly wants to fail loudly if the replica's
// lag exceeds an SLO; they use this sentinel.
var ErrReplicaTokenStale = errors.New("db: replica has not yet applied the supplied freshness token")
