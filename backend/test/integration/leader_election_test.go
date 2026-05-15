//go:build integration

// leader_election_test.go — proves that pg_advisory_lock-based leader
// election in internal/leader actually blocks concurrent execution
// across simulated replica goroutines.
//
// Models the cron-runner HA scenario: replicas A and B both try to
// run the same job at the same instant. Only ONE should succeed; the
// other should observe wasLeader=false.

package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/leader"
)

func TestLeader_OnlyOneReplicaExecutes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// 5 replicas race to run "test-job-A". Each blocks for 50ms inside
	// fn so the lock is held long enough to make the race meaningful.
	var executed atomic.Int32
	var followed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wasLeader, err := leader.Run(ctx, h.pool, "test-job-A", func(ctx context.Context) error {
				time.Sleep(50 * time.Millisecond)
				return nil
			})
			if err != nil {
				t.Errorf("run: %v", err)
				return
			}
			if wasLeader {
				executed.Add(1)
			} else {
				followed.Add(1)
			}
		}()
	}
	wg.Wait()

	if executed.Load() != 1 {
		t.Errorf("expected exactly 1 leader, got %d", executed.Load())
	}
	if followed.Load() != 4 {
		t.Errorf("expected 4 followers, got %d", followed.Load())
	}
}

func TestLeader_LockReleasesBetweenTicks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// First Run takes the lock and releases.
	gotA, err := leader.Run(ctx, h.pool, "test-job-B", func(ctx context.Context) error {
		return nil
	})
	if err != nil || !gotA {
		t.Fatalf("first Run: leader=%v err=%v", gotA, err)
	}
	// Immediately afterwards, a fresh Run can also acquire (the
	// previous tick released the lock).
	gotB, err := leader.Run(ctx, h.pool, "test-job-B", func(ctx context.Context) error {
		return nil
	})
	if err != nil || !gotB {
		t.Fatalf("second Run: leader=%v err=%v", gotB, err)
	}
}

func TestLeader_DifferentJobsDoNotBlockEachOther(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Hold lock on job-X then concurrently run job-Y — should succeed.
	connX, gotX, err := leader.TryAcquire(ctx, h.pool, "test-job-X")
	if err != nil || !gotX {
		t.Fatalf("X: %v %v", gotX, err)
	}
	defer leader.Release(ctx, connX, "test-job-X")

	gotY, err := leader.Run(ctx, h.pool, "test-job-Y", func(ctx context.Context) error {
		return nil
	})
	if err != nil || !gotY {
		t.Fatalf("Y should succeed even with X locked: leader=%v err=%v", gotY, err)
	}
}
