// Package emergency listens for the cloud-side emergency-stop signal
// (Blueprint §28.2). When triggered, the agent halts all running tools
// within the SLA (default 30s) and refuses to start new ones.
//
// Implementation: a single context that callers can attach derived
// contexts to (via WithContext). When Trigger() fires, ALL derived
// contexts cancel — including the ctx that exec.CommandContext is
// using to wait on the running subprocess, which causes Go's stdlib
// to SIGKILL the process. This is what actually enforces the 30s SLA.
package emergency

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Listener struct {
	stopped int32
	since   atomic.Value // time.Time

	mu     sync.Mutex
	root   context.Context
	cancel context.CancelFunc
}

func New() *Listener {
	l := &Listener{}
	l.root, l.cancel = context.WithCancel(context.Background())
	return l
}

// Trigger sets the stopped flag AND cancels every derived context
// produced by WithContext. Stops running subprocesses launched via
// exec.CommandContext within the typical 1-2s SIGKILL window.
func (l *Listener) Trigger() {
	atomic.StoreInt32(&l.stopped, 1)
	l.since.Store(time.Now())
	l.mu.Lock()
	if l.cancel != nil {
		l.cancel()
	}
	l.mu.Unlock()
}

// Reset clears the stopped flag AND rebuilds the cancel root so
// subsequent WithContext-derived contexts are once again live.
// Used by the cloud-side reset flow when an emergency stop is lifted.
func (l *Listener) Reset() {
	atomic.StoreInt32(&l.stopped, 0)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.root, l.cancel = context.WithCancel(context.Background())
}

func (l *Listener) Stopped() bool { return atomic.LoadInt32(&l.stopped) == 1 }

func (l *Listener) Since() time.Time {
	v := l.since.Load()
	if t, ok := v.(time.Time); ok {
		return t
	}
	return time.Time{}
}

// WithContext returns a derived context that cancels when EITHER
// parent cancels OR Trigger() is called. Use from any code path that
// wants its in-flight work to be interruptible by an emergency stop
// — most importantly, runner.Execute when it shells out to a long-
// running scanner tool.
func (l *Listener) WithContext(parent context.Context) (context.Context, context.CancelFunc) {
	l.mu.Lock()
	root := l.root
	l.mu.Unlock()
	// Bridge: cancel the returned ctx when either parent OR root
	// cancels. The select goroutine self-terminates when ctx is
	// done (via either path) so we don't leak.
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-root.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
