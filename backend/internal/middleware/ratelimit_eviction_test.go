package middleware

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// In-memory rate-limiter bucket-eviction property: with > 64 keys
// added and bucketTTL exceeded, the map shrinks back to active
// keys only. Prevents the previous unbounded-growth bug.
func TestInMemoryLimiter_EvictsDormantBuckets(t *testing.T) {
	t.Parallel()
	l := NewInMemoryLimiter()
	// Tiny TTL + tiny sweep window so the test runs fast.
	l.bucketTTL = 50 * time.Millisecond
	l.sweepInterval = 10 * time.Millisecond

	ctx := context.Background()
	// Seed 100 distinct keys so we exceed the 64-key sweep gate.
	for i := 0; i < 100; i++ {
		if _, err := l.Allow(ctx, "k-"+strconv.Itoa(i), 10, 60); err != nil {
			t.Fatal(err)
		}
	}
	if l.Size() != 100 {
		t.Fatalf("Size=%d, want 100 after seeding", l.Size())
	}

	// Sleep so every bucket is dormant past the TTL.
	time.Sleep(150 * time.Millisecond)

	// Touch one key — the eviction sweep runs on this Allow().
	if _, err := l.Allow(ctx, "live-key", 10, 60); err != nil {
		t.Fatal(err)
	}
	// The 100 dormant keys must be gone; only "live-key" remains.
	if got := l.Size(); got != 1 {
		t.Errorf("Size=%d, want 1 (only live-key); dormant buckets not evicted", got)
	}
}

// Negative case: with the map under 64 entries, no sweep happens
// even if buckets age out — small processes shouldn't pay the
// iteration cost.
func TestInMemoryLimiter_SmallMapSkipsSweep(t *testing.T) {
	t.Parallel()
	l := NewInMemoryLimiter()
	l.bucketTTL = 10 * time.Millisecond
	l.sweepInterval = 1 * time.Millisecond
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, _ = l.Allow(ctx, "k-"+strconv.Itoa(i), 10, 60)
	}
	time.Sleep(50 * time.Millisecond)
	_, _ = l.Allow(ctx, "trigger", 10, 60)
	if got := l.Size(); got < 10 {
		t.Errorf("Size=%d, want >=10 — small map should NOT sweep", got)
	}
}
