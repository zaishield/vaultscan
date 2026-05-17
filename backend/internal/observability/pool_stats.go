package observability

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartPoolStatsExporter scrapes pgxpool.Stat every interval and
// updates the DB-pool gauges/counters. Returns a stop function the
// caller invokes from main's shutdown sequence.
//
// Why a background scraper rather than reading on every request:
// pool.Stat() locks the pool to read internal counters. We only
// need 10s resolution (Prometheus scrape interval) so doing it
// from a single goroutine keeps the request hot path lock-free.
func StartPoolStatsExporter(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) func() {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		var lastAcquireCount int64
		var lastAcquireDur time.Duration
		var lastCanceled int64
		// Seed with initial values so the first delta is zero, not
		// "whatever the pool already did before we started watching".
		s0 := pool.Stat()
		lastAcquireCount = s0.AcquireCount()
		lastAcquireDur = s0.AcquireDuration()
		lastCanceled = s0.CanceledAcquireCount()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				s := pool.Stat()
				DBPoolAcquired.Set(float64(s.AcquiredConns()))
				DBPoolIdle.Set(float64(s.IdleConns()))
				// EmptyAcquireCount is the count of times a caller had
				// to wait. Not a current gauge — we surface it via the
				// canceled/wait counters. Leave Waiting at 0 (pgx
				// doesn't expose live wait depth).
				DBPoolWaiting.Set(0)
				DBPoolMax.Set(float64(s.MaxConns()))
				if d := s.AcquireCount() - lastAcquireCount; d > 0 {
					DBPoolAcquireCount.Add(float64(d))
					lastAcquireCount = s.AcquireCount()
				}
				if d := s.AcquireDuration() - lastAcquireDur; d > 0 {
					DBPoolAcquireDuration.Add(d.Seconds())
					lastAcquireDur = s.AcquireDuration()
				}
				if d := s.CanceledAcquireCount() - lastCanceled; d > 0 {
					DBPoolCanceledAcquires.Add(float64(d))
					lastCanceled = s.CanceledAcquireCount()
				}
			}
		}
	}()
	return cancel
}
