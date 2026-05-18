//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// TestAuditChain_ConcurrentWritesStayIntact is the GA-grade
// concurrency stress test for the audit chain's advisory lock.
// It fires N parallel writers, each making M Record() calls, and
// then runs VerifyIncremental — the chain MUST be intact.
//
// Without pg_advisory_xact_lock guarding read-prev + insert, two
// concurrent Record calls each see the same `prev` and compute
// hashes that reference the same predecessor. After commit, Verify
// sees a forked chain (one of the two `chain_prev` bytes doesn't
// match the row's actual predecessor's `chain_hash`).
//
// 8 writers × 25 events = 200 audit rows written in parallel; the
// suite previously had NO test that exercised this path.
func TestAuditChain_ConcurrentWritesStayIntact(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	const (
		writers          = 8
		eventsPerWriter  = 25
		totalNew         = writers * eventsPerWriter
	)

	tenantID, _ := h.makeTenant(t, "audit-concur-"+uuid.NewString()[:6])

	// Baseline: how many audit rows currently exist? We expect the
	// post-test count to be baseline + totalNew (every Record() call
	// must successfully insert).
	var baseline int64
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&baseline); err != nil {
		t.Fatalf("baseline count: %v", err)
	}

	var wg sync.WaitGroup
	var failures atomic.Int64
	start := make(chan struct{}) // gate so writers all release at once

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-start
			for i := 0; i < eventsPerWriter; i++ {
				if err := h.audit.Record(ctx, audit.Entry{
					PlatformID: platformID,
					TenantID:   &tenantID,
					Event:      fmt.Sprintf("concur.write.w%d.i%d", workerID, i),
					ActorType:  "test",
					TargetType: "concurrency_probe",
					TargetID:   fmt.Sprintf("w%d-i%d", workerID, i),
					Payload: map[string]any{
						"worker": workerID, "seq": i,
						"nonce": uuid.NewString(),
					},
				}); err != nil {
					failures.Add(1)
					t.Logf("worker %d event %d failed: %v", workerID, i, err)
				}
			}
		}(w)
	}

	t0 := time.Now()
	close(start) // release the herd
	wg.Wait()
	elapsed := time.Since(t0)
	t.Logf("wrote %d audit rows across %d goroutines in %s (%.0f rows/sec)",
		totalNew, writers, elapsed, float64(totalNew)/elapsed.Seconds())

	if failed := failures.Load(); failed != 0 {
		t.Errorf("%d/%d Record calls failed under contention", failed, totalNew)
	}

	var after int64
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&after); err != nil {
		t.Fatalf("post count: %v", err)
	}
	if delta := after - baseline; delta < int64(totalNew) {
		t.Errorf("expected at least %d new rows; got delta=%d", totalNew, delta)
	}

	// The acid test: chain MUST verify clean after the parallel
	// hammering. A single mismatch = the advisory lock failed to
	// serialise read-prev + insert.
	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	}
	if res.FirstBadID != 0 {
		t.Fatalf("CHAIN BROKEN after concurrent writes: first_bad=%d last_good=%d detail=%s",
			res.FirstBadID, res.LastGoodID, res.Detail)
	}
	t.Logf("chain integrity: total=%d last_good=%d", res.Total, res.LastGoodID)
}

// TestAuditChain_HighContentionStress fires 16 writers × 50 events
// = 800 rows on a tighter inner-loop. Lower per-call overhead means
// more pure contention on the advisory lock. Anything that quietly
// degrades from "serialised" to "best-effort" under this load
// shows up as either a Record failure or a chain break.
//
// Tagged "stress" via a separate test so the everyday suite doesn't
// pay 5s on every run. Run with -run TestAuditChain_HighContention.
func TestAuditChain_HighContentionStress(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode; high-contention stress takes ~5s")
	}
	h := newHarness(t)
	ctx := context.Background()

	const (
		writers         = 16
		eventsPerWriter = 50
		totalNew        = writers * eventsPerWriter
	)

	tenantID, _ := h.makeTenant(t, "audit-stress-"+uuid.NewString()[:6])

	var wg sync.WaitGroup
	var failures atomic.Int64
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			<-start
			for i := 0; i < eventsPerWriter; i++ {
				if err := h.audit.Record(ctx, audit.Entry{
					PlatformID: platformID,
					TenantID:   &tenantID,
					Event:      "stress.write",
					ActorType:  "test",
					Payload:    map[string]any{"w": wid, "i": i, "nonce": uuid.NewString()},
				}); err != nil {
					failures.Add(1)
				}
			}
		}(w)
	}

	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)
	t.Logf("stress: %d rows / %d writers in %s = %.0f rows/sec; %d failures",
		totalNew, writers, elapsed, float64(totalNew)/elapsed.Seconds(), failures.Load())

	if failures.Load() != 0 {
		t.Errorf("%d Record calls failed under stress", failures.Load())
	}
	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.FirstBadID != 0 {
		t.Fatalf("chain broken under stress: first_bad=%d %s", res.FirstBadID, res.Detail)
	}
}
