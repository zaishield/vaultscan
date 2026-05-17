package scanner

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func noopLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

// Worker.Shutdown must block until inflight goroutines complete OR
// the deadline elapses. Either path is acceptable; what's NOT
// acceptable is returning immediately while inflight goroutines
// keep running (the previous time.Sleep(500ms) "drain" pattern).
//
// This is a pure unit test against the WaitGroup semantics — we
// don't need a real claimed job, just a goroutine that holds the
// inflight wait until we let it go.

func TestShutdown_BlocksUntilInflightDrains(t *testing.T) {
	t.Parallel()
	w := &Worker{}
	// Simulate two in-flight execute() calls.
	release := make(chan struct{})
	for i := 0; i < 2; i++ {
		w.inflight.Add(1)
		go func() {
			defer w.inflight.Done()
			<-release
		}()
	}

	done := make(chan struct{})
	go func() {
		w.Shutdown(5 * time.Second)
		close(done)
	}()

	// Shutdown must NOT return before we release the goroutines.
	select {
	case <-done:
		t.Fatal("Shutdown returned before inflight drained")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
		// Shutdown returned within a tick — good.
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown didn't return after inflight drained")
	}
}

// TestShutdown_RespectsDeadline: if the deadline elapses with
// inflight goroutines still running, Shutdown returns rather than
// blocking forever.
func TestShutdown_RespectsDeadline(t *testing.T) {
	t.Parallel()
	w := &Worker{
		log: noopLogger(),
	}
	var wg sync.WaitGroup
	wg.Add(1)
	w.inflight.Add(1) // never released
	defer w.inflight.Done()

	start := time.Now()
	w.Shutdown(150 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Errorf("Shutdown returned too early: %s", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Shutdown waited past deadline: %s", elapsed)
	}
	wg.Done()
}
