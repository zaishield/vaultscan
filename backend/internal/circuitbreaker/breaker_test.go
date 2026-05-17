package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Closed-state breaker passes calls through.
func TestClosed_PassesThrough(t *testing.T) {
	t.Parallel()
	b := New(Config{Name: "test"})
	called := 0
	for i := 0; i < 10; i++ {
		err := b.Call(func() error { called++; return nil })
		if err != nil {
			t.Fatalf("call %d err: %v", i, err)
		}
	}
	if called != 10 {
		t.Errorf("expected 10 calls, got %d", called)
	}
}

// MaxFailures consecutive failures → state flips to open.
func TestFailuresFlipOpen(t *testing.T) {
	t.Parallel()
	b := New(Config{Name: "t", MaxFailures: 3})
	upstreamErr := errors.New("upstream down")
	for i := 0; i < 3; i++ {
		err := b.Call(func() error { return upstreamErr })
		if err != upstreamErr {
			t.Fatalf("expected upstream err, got %v", err)
		}
	}
	if b.State() != StateOpen {
		t.Errorf("expected open, got %s", b.State())
	}
	// Next call returns ErrBreakerOpen without invoking fn.
	called := false
	err := b.Call(func() error { called = true; return nil })
	if err != ErrBreakerOpen {
		t.Errorf("expected ErrBreakerOpen, got %v", err)
	}
	if called {
		t.Error("upstream should not be called when breaker is open")
	}
}

// A successful call resets the failure counter.
func TestSuccessResetsFailures(t *testing.T) {
	t.Parallel()
	b := New(Config{Name: "t", MaxFailures: 3})
	upstreamErr := errors.New("flake")
	// 2 failures, then a success, then 2 more failures — should
	// still be closed because the counter was reset.
	_ = b.Call(func() error { return upstreamErr })
	_ = b.Call(func() error { return upstreamErr })
	_ = b.Call(func() error { return nil })
	_ = b.Call(func() error { return upstreamErr })
	_ = b.Call(func() error { return upstreamErr })
	if b.State() != StateClosed {
		t.Errorf("expected closed (counter was reset), got %s", b.State())
	}
}

// After cooldown elapses, a probe call is allowed. Success closes
// the breaker.
func TestHalfOpenProbe_SuccessCloses(t *testing.T) {
	t.Parallel()
	now := atomic.Int64{}
	now.Store(time.Now().UnixNano())
	b := New(Config{
		Name: "t", MaxFailures: 1, Cooldown: time.Second,
		Now: func() time.Time { return time.Unix(0, now.Load()) },
	})
	_ = b.Call(func() error { return errors.New("x") })
	if b.State() != StateOpen {
		t.Fatal("expected open after first failure")
	}
	// Advance time past cooldown.
	now.Add(2 * int64(time.Second))
	// Next call is the probe — succeeds → closed.
	err := b.Call(func() error { return nil })
	if err != nil {
		t.Errorf("probe error: %v", err)
	}
	if b.State() != StateClosed {
		t.Errorf("expected closed after successful probe, got %s", b.State())
	}
}

// Half-open probe failure → reopens with the cooldown clock restarted.
func TestHalfOpenProbe_FailureReopens(t *testing.T) {
	t.Parallel()
	now := atomic.Int64{}
	now.Store(time.Now().UnixNano())
	b := New(Config{
		Name: "t", MaxFailures: 1, Cooldown: time.Second,
		Now: func() time.Time { return time.Unix(0, now.Load()) },
	})
	_ = b.Call(func() error { return errors.New("x") })
	now.Add(2 * int64(time.Second))
	upstream := errors.New("still down")
	err := b.Call(func() error { return upstream })
	if err != upstream {
		t.Errorf("got %v, want upstream error", err)
	}
	if b.State() != StateOpen {
		t.Errorf("expected open after probe failure, got %s", b.State())
	}
}

// Concurrent half-open: only ONE goroutine gets the probe slot;
// others get ErrBreakerOpen.
func TestHalfOpen_OnlyOneProbeAtATime(t *testing.T) {
	t.Parallel()
	now := atomic.Int64{}
	now.Store(time.Now().UnixNano())
	b := New(Config{
		Name: "t", MaxFailures: 1, Cooldown: time.Millisecond,
		Now: func() time.Time { return time.Unix(0, now.Load()) },
	})
	_ = b.Call(func() error { return errors.New("x") })
	now.Add(int64(10 * time.Millisecond))

	// 10 goroutines all try at once; the upstream blocks the probe
	// long enough that others race and should see ErrBreakerOpen.
	gate := make(chan struct{})
	var probeCount int32
	var openCount int32
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			err := b.Call(func() error {
				atomic.AddInt32(&probeCount, 1)
				<-gate // hold the probe slot
				return nil
			})
			if errors.Is(err, ErrBreakerOpen) {
				atomic.AddInt32(&openCount, 1)
			}
		}()
	}
	// Let probe finish.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	if atomic.LoadInt32(&probeCount) != 1 {
		t.Errorf("probeCount=%d want 1", probeCount)
	}
	if atomic.LoadInt32(&openCount) != 9 {
		t.Errorf("openCount=%d want 9 (others rejected)", openCount)
	}
}

// Reset force-closes regardless of failure history.
func TestReset(t *testing.T) {
	t.Parallel()
	b := New(Config{Name: "t", MaxFailures: 1, Cooldown: time.Hour})
	_ = b.Call(func() error { return errors.New("x") })
	if b.State() != StateOpen {
		t.Fatal("expected open")
	}
	b.Reset()
	if b.State() != StateClosed {
		t.Errorf("expected closed after reset, got %s", b.State())
	}
}

// MetricSink hook fires on state transitions.
func TestMetricSink_FiresOnTransitions(t *testing.T) {
	transitions := []string{}
	var mu sync.Mutex
	SetMetricSink(func(name, transition string) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, name+":"+transition)
	})
	t.Cleanup(func() { SetMetricSink(nil) })

	b := New(Config{Name: "x", MaxFailures: 1, Cooldown: time.Millisecond,
		Now: time.Now})
	_ = b.Call(func() error { return errors.New("e") }) // open
	time.Sleep(5 * time.Millisecond)
	_ = b.Call(func() error { return nil }) // close
	mu.Lock()
	defer mu.Unlock()
	if len(transitions) < 2 {
		t.Errorf("expected at least 2 transitions, got %v", transitions)
	}
}

// State.String maps every value.
func TestStateString(t *testing.T) {
	t.Parallel()
	if StateClosed.String() != "closed" {
		t.Error("closed string")
	}
	if StateOpen.String() != "open" {
		t.Error("open string")
	}
	if StateHalfOpen.String() != "half-open" {
		t.Error("half-open string")
	}
	if State(99).String() != "unknown" {
		t.Error("unknown sentinel")
	}
}
