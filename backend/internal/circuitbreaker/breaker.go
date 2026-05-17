// Package circuitbreaker is a minimal three-state breaker for
// outbound HTTP calls and other failure-prone upstream operations.
//
// States:
//
//	closed   — calls flow through; failures + successes counted
//	open     — calls fail-fast with ErrBreakerOpen; after the cool-
//	           down elapses we transition to half-open
//	half-open — exactly ONE probe call is allowed; success → closed,
//	           failure → open (cooldown restarts)
//
// Why this and not a dependency: the production callers we have
// (integrations / notify / cosign-Rekor / email / cloudposture) all
// need the same shape and the standard Go circuit-breaker libs
// (sony/gobreaker) bring in extras we don't use. ~150 LOC here is
// cheaper than another module dependency, and the tests below pin
// the semantics so nobody has to wonder how it behaves.
//
// Concurrency: state transitions take the mutex; the hot
// "ok-to-call?" check that returns from the closed state is a
// single atomic load so the common path doesn't serialise.
//
// Per-upstream metrics: callers wire a hook into the package-level
// MetricSink so opens / half-opens / probe-result events are
// observable in Prometheus without the package importing the
// observability one (would form a cycle).
package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// State enumerates the three states.
type State int32

const (
	StateClosed   State = 0
	StateOpen     State = 1
	StateHalfOpen State = 2
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// ErrBreakerOpen is returned by Call when the breaker refuses the
// request without trying the upstream.
var ErrBreakerOpen = errors.New("circuitbreaker: breaker is open")

// Config tunes one breaker.
type Config struct {
	// Name is included in metric labels + log lines. Pick the
	// upstream's stable identifier (e.g. "jira", "rekor").
	Name string

	// MaxFailures is the count of consecutive failures that flips
	// the breaker open. Default 5.
	MaxFailures int

	// Cooldown is how long the breaker stays open before allowing
	// a half-open probe. Default 30s.
	Cooldown time.Duration

	// Now is overridable for tests. Defaults to time.Now.
	Now func() time.Time
}

// Breaker is one circuit for one upstream. Reusable across goroutines.
type Breaker struct {
	cfg Config

	state    atomic.Int32 // State
	mu       sync.Mutex
	failures int
	openedAt time.Time
}

// New builds a breaker with defaults filled in.
func New(cfg Config) *Breaker {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Name == "" {
		cfg.Name = "unnamed"
	}
	return &Breaker{cfg: cfg}
}

// State returns the current state (atomic read, no lock).
func (b *Breaker) State() State {
	return State(b.state.Load())
}

// Call invokes fn while the breaker permits it. When the breaker is
// open it returns ErrBreakerOpen without calling fn. When half-open
// only the first concurrent caller is allowed through; subsequent
// callers get ErrBreakerOpen until the probe completes.
//
// The fn's return value is recorded as success/failure based on
// whether err is nil. Callers wanting a different rule
// (e.g. "treat 5xx as failure but 4xx as success") should map their
// own result to nil/non-nil before calling Call.
func (b *Breaker) Call(fn func() error) error {
	// Fast path: closed state. Atomic load only.
	if b.State() == StateClosed {
		err := fn()
		b.recordOutcome(err)
		return err
	}
	// Slower path: open or half-open. Take the mutex to evaluate
	// the cooldown transition + reserve the probe slot.
	b.mu.Lock()
	switch b.State() {
	case StateOpen:
		if b.cfg.Now().Sub(b.openedAt) >= b.cfg.Cooldown {
			// Cooldown elapsed → reserve the probe slot.
			b.state.Store(int32(StateHalfOpen))
			b.mu.Unlock()
			err := fn()
			b.recordOutcome(err)
			return err
		}
		b.mu.Unlock()
		return ErrBreakerOpen
	case StateHalfOpen:
		// Another goroutine is already probing.
		b.mu.Unlock()
		return ErrBreakerOpen
	default:
		// Race: state was closed when we checked above but flipped
		// before we took the lock. Just retry the fast path.
		b.mu.Unlock()
		return b.Call(fn)
	}
}

// recordOutcome updates failure count + state transitions based on
// fn's result.
func (b *Breaker) recordOutcome(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		// Success: reset failures + close the breaker.
		prev := State(b.state.Load())
		b.failures = 0
		if prev != StateClosed {
			b.state.Store(int32(StateClosed))
			if MetricSink != nil {
				MetricSink(b.cfg.Name, "close")
			}
		}
		return
	}
	// Failure: bump counter; flip open if we crossed the
	// threshold OR if we were probing in half-open state.
	b.failures++
	prev := State(b.state.Load())
	if prev == StateHalfOpen || b.failures >= b.cfg.MaxFailures {
		b.state.Store(int32(StateOpen))
		b.openedAt = b.cfg.Now()
		if MetricSink != nil {
			MetricSink(b.cfg.Name, "open")
		}
	}
}

// Reset force-closes the breaker. Used by ops tooling ("we fixed
// the upstream, stop short-circuiting").
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	if State(b.state.Load()) != StateClosed {
		b.state.Store(int32(StateClosed))
		if MetricSink != nil {
			MetricSink(b.cfg.Name, "reset")
		}
	}
}

// MetricSink is wired by cmd/api at startup to a Prometheus
// counter labelled by (name, transition). Nil = no metric, the
// breaker still works. Defined here so the circuit package doesn't
// import observability (would form a cycle via integrations →
// observability → integrations).
var MetricSink func(name, transition string)

// SetMetricSink installs the metric hook.
func SetMetricSink(f func(name, transition string)) { MetricSink = f }
