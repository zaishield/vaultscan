package emergency

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// Trigger() must cancel a context that exec.CommandContext is using
// so the in-flight subprocess receives SIGKILL within the 30s SLA.
// This test starts `sleep 60`, fires Trigger after 100ms, and
// asserts the process died within 5s.
func TestListener_TriggerKillsRunningSubprocess(t *testing.T) {
	t.Parallel()
	l := New()
	ctx, cancel := l.WithContext(context.Background())
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, "sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep binary unavailable on this platform: %v", err)
	}

	// Fire emergency stop after a short delay.
	go func() {
		time.Sleep(100 * time.Millisecond)
		l.Trigger()
	}()

	waitErr := cmd.Wait()
	took := time.Since(start)
	if took > 5*time.Second {
		t.Errorf("subprocess kept running %v after Trigger; SLA violated", took)
	}
	if waitErr == nil {
		t.Error("expected non-nil err (process killed), got nil")
	}
}

// Reset() must rebuild the cancel root so a SECOND scan can run.
// Without Reset(), the listener stays in stopped state forever and
// every subsequent WithContext returns a pre-cancelled ctx.
func TestListener_ResetRestoresFreshContext(t *testing.T) {
	t.Parallel()
	l := New()
	l.Trigger()
	if !l.Stopped() {
		t.Fatal("expected stopped after Trigger")
	}
	l.Reset()
	if l.Stopped() {
		t.Fatal("expected NOT stopped after Reset")
	}
	// New WithContext should NOT be pre-cancelled.
	ctx, cancel := l.WithContext(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		t.Error("post-Reset WithContext returned a pre-cancelled ctx")
	case <-time.After(50 * time.Millisecond):
	}
}

// Concurrent WithContext + Trigger doesn't race or deadlock. Spawn
// 50 goroutines that each derive a ctx + wait for it to be cancelled,
// then fire Trigger and assert all of them return promptly.
func TestListener_ConcurrentDerivedContexts(t *testing.T) {
	t.Parallel()
	l := New()
	const N = 50
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			ctx, cancel := l.WithContext(context.Background())
			defer cancel()
			<-ctx.Done()
			done <- struct{}{}
		}()
	}
	// give all goroutines time to register their contexts
	time.Sleep(50 * time.Millisecond)
	l.Trigger()
	deadline := time.After(5 * time.Second)
	for i := 0; i < N; i++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("only %d/%d derived contexts cancelled in 5s", i, N)
		}
	}
}
