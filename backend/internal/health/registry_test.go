package health

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshot_AggregatesAndCappsPerCheck(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	var ranSlow int32
	r.Register("fast", func(ctx context.Context) (Status, string) {
		return StatusOK, ""
	}, false)
	r.Register("slow", func(ctx context.Context) (Status, string) {
		atomic.AddInt32(&ranSlow, 1)
		select {
		case <-ctx.Done():
			return StatusDown, "timed out"
		case <-time.After(time.Second):
			return StatusOK, ""
		}
	}, false)

	start := time.Now()
	res := r.Snapshot(context.Background(), 50*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("Snapshot ran %s — perCheckTimeout didn't bound the slow check", elapsed)
	}
	if res.Status != StatusDegraded {
		t.Errorf("aggregate=%s want degraded (one slow check timed out)", res.Status)
	}
	if atomic.LoadInt32(&ranSlow) != 1 {
		t.Errorf("slow check fired %d times, want 1", ranSlow)
	}
}

func TestSnapshot_OptionalDownDoesNotDegrade(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register("db", func(ctx context.Context) (Status, string) {
		return StatusOK, ""
	}, false)
	r.Register("siem", func(ctx context.Context) (Status, string) {
		return StatusDown, "forwarder offline"
	}, true) // optional

	res := r.Snapshot(context.Background(), time.Second)
	if res.Status != StatusOK {
		t.Errorf("aggregate=%s want ok (optional component down)", res.Status)
	}
}

func TestHTTPStatusFor(t *testing.T) {
	t.Parallel()
	if got := (Result{Status: StatusOK}).HTTPStatusFor(); got != 200 {
		t.Errorf("ok → %d want 200", got)
	}
	if got := (Result{Status: StatusDegraded}).HTTPStatusFor(); got != 503 {
		t.Errorf("degraded → %d want 503", got)
	}
	if got := (Result{Status: StatusDown}).HTTPStatusFor(); got != 503 {
		t.Errorf("down → %d want 503", got)
	}
}
