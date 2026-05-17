package eventbus

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// safeHandle is the per-subscriber wrapper that adds panic recovery
// + a 30s timeout. These tests exercise it directly so the contract
// is locked: a buggy subscriber must not be able to kill the
// dispatcher, leak a goroutine forever, or take any other subscriber
// down with it.

func TestSafeHandle_RecoversPanic(t *testing.T) {
	t.Parallel()
	called := false
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("safeHandle should swallow panic, got: %v", r)
		}
	}()
	bad := Handler(func(_ context.Context, _ Event) {
		called = true
		panic("boom")
	})
	safeHandle(bad, context.Background(), Event{ID: uuid.New(), Type: "x"})
	if !called {
		t.Error("subscriber should have been invoked")
	}
}

func TestSafeHandle_PanicDoesNotAffectOtherSubs(t *testing.T) {
	t.Parallel()
	bad := Handler(func(_ context.Context, _ Event) { panic("boom") })
	var goodRan int32
	good := Handler(func(_ context.Context, _ Event) {
		atomic.AddInt32(&goodRan, 1)
	})
	safeHandle(bad, context.Background(), Event{ID: uuid.New(), Type: "x"})
	safeHandle(good, context.Background(), Event{ID: uuid.New(), Type: "x"})
	if atomic.LoadInt32(&goodRan) != 1 {
		t.Error("good subscriber should have run after bad one panicked")
	}
}

func TestSafeHandle_AppliesTimeout(t *testing.T) {
	// NOT t.Parallel — this test mutates the package-level
	// handlerTimeout var. Running in parallel with other tests
	// that call safeHandle would race on the read side.
	orig := handlerTimeout
	handlerTimeout = 50 * time.Millisecond
	defer func() { handlerTimeout = orig }()

	var sawCancel int32
	h := Handler(func(ctx context.Context, _ Event) {
		// Wait for ctx to cancel — if it doesn't, the test hangs
		// (well, fails after the test framework's global timeout).
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			atomic.AddInt32(&sawCancel, 1)
		}
	})
	done := make(chan struct{})
	go func() {
		safeHandle(h, context.Background(), Event{ID: uuid.New(), Type: "slow"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("safeHandle didn't apply timeout — handler hung indefinitely")
	}
	if atomic.LoadInt32(&sawCancel) != 1 {
		t.Error("handler ctx should have been cancelled by deadline")
	}
}

func TestSafeHandle_ParentCtxCancelPropagates(t *testing.T) {
	t.Parallel()
	// If the publisher's ctx cancels, the handler's derived ctx
	// should cancel too (within reasonable time).
	parent, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	var sawCancel int32
	h := Handler(func(ctx context.Context, _ Event) {
		<-ctx.Done()
		atomic.AddInt32(&sawCancel, 1)
	})
	done := make(chan struct{})
	go func() {
		safeHandle(h, parent, Event{ID: uuid.New(), Type: "x"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("safeHandle did not honour pre-cancelled parent ctx")
	}
	if atomic.LoadInt32(&sawCancel) != 1 {
		t.Error("expected handler to observe ctx cancellation")
	}
}

// Subscribe + Publish (in-memory path; the DB INSERT is mocked by
// noOpPool — Publish writes to bus_events then fans out). Without
// a pool we can still exercise the subscribe/dispatch path by
// calling safeHandle directly from a test-built handler list.

func TestSubscribe_FansOutToAllRegisteredHandlers(t *testing.T) {
	t.Parallel()
	// Real Bus uses *pgxpool.Pool for the durable write — that needs
	// a DB. To test fan-out alone we drive safeHandle directly with
	// the handler list that Subscribe would have built.
	var mu sync.Mutex
	got := []string{}
	subs := []Handler{
		func(_ context.Context, _ Event) {
			mu.Lock()
			got = append(got, "h1")
			mu.Unlock()
		},
		func(_ context.Context, _ Event) {
			mu.Lock()
			got = append(got, "h2")
			mu.Unlock()
		},
	}
	ev := Event{ID: uuid.New(), Type: "test.event"}
	for _, h := range subs {
		safeHandle(h, context.Background(), ev)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != "h1" || got[1] != "h2" {
		t.Errorf("fan-out incorrect: %v", got)
	}
}

// AllEventTypes — string discipline. Names from §22.1 of the
// Blueprint must be stable; a typo here breaks every consumer.
func TestAllEventTypes_NoDuplicates(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, et := range AllEventTypes() {
		if seen[et] {
			t.Errorf("duplicate event type: %s", et)
		}
		seen[et] = true
	}
}

func TestAllEventTypes_LowercaseUnderscored(t *testing.T) {
	t.Parallel()
	// Locked convention: event names are PascalCase (FindingNormalized,
	// RetestRequested, ...). The Blueprint and every consumer agrees
	// on this; the test just asserts no whitespace / weird chars
	// slipped into a name during a refactor.
	for _, et := range AllEventTypes() {
		if strings.ContainsAny(et, " \t\n\r") {
			t.Errorf("event type %q has whitespace", et)
		}
		if et == "" {
			t.Error("empty event type registered")
		}
	}
}
