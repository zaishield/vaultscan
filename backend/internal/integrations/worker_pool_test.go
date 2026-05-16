package integrations

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// To unit-test the pool without standing up a Service, we replace the
// deliver step with a hook. The pool is generic enough that we can
// substitute a no-op service + a counted side effect.

func TestWorkerPool_OverflowCountStartsAtZero(t *testing.T) {
	t.Parallel()
	p := newCountingPool(t, 1, 4, nil)
	defer p.Shutdown(time.Second)
	if got := p.OverflowCount(); got != 0 {
		t.Errorf("OverflowCount() = %d, want 0", got)
	}
}

func TestWorkerPool_AcceptsJobsUpToCapacity(t *testing.T) {
	t.Parallel()
	delivered := atomic.Int32{}
	block := make(chan struct{})
	p := newCountingPool(t, 1, 2, func() {
		<-block
		delivered.Add(1)
	})
	defer p.Shutdown(2 * time.Second)

	job := DeliveryJob{
		IntegrationID: uuid.New(), Type: "webhook", Name: "n",
		Config: map[string]any{"url": "http://x"},
		Event:  eventbus.Event{Type: "test"},
	}
	// Submit 6 jobs into a pool with 1 worker + 2-slot queue (3 slots
	// total: 1 in-flight + 2 queued). The first 3 succeed, the rest
	// drop into overflow.
	accepted := 0
	for i := 0; i < 6; i++ {
		if p.Submit(job) {
			accepted++
		}
	}
	close(block)
	// 1 worker + 2-slot buffered queue: up to 3 in flight (1 reading,
	// 2 queued) once the scheduler has caught up. Submission timing is
	// racy with the worker's first read, so we accept ≥2 with the
	// strict invariant being "some submits dropped → overflow > 0".
	if accepted < 2 {
		t.Errorf("accepted=%d, want >=2", accepted)
	}
	if p.OverflowCount() == 0 {
		t.Error("expected overflow > 0")
	}
}

func TestWorkerPool_ShutdownDrainsInFlight(t *testing.T) {
	t.Parallel()
	delivered := atomic.Int32{}
	p := newCountingPool(t, 4, 8, func() {
		time.Sleep(10 * time.Millisecond)
		delivered.Add(1)
	})

	job := DeliveryJob{
		IntegrationID: uuid.New(), Type: "webhook", Name: "n",
		Config: map[string]any{"url": "http://x"},
		Event:  eventbus.Event{Type: "test"},
	}
	for i := 0; i < 8; i++ {
		_ = p.Submit(job)
	}
	// Generous grace so all in-flight have a chance to finish.
	p.Shutdown(time.Second)
	if got := delivered.Load(); got < 4 {
		t.Errorf("delivered=%d, want >=4 after drain", got)
	}
}

func TestWorkerPool_ShutdownCancelsStuckWorkers(t *testing.T) {
	t.Parallel()
	// Stuck-forever delivery — shutdown should still return after
	// the grace period.
	p := newCountingPool(t, 2, 4, func() {
		select {} // block forever
	})
	job := DeliveryJob{
		IntegrationID: uuid.New(), Type: "webhook", Name: "n",
		Config: map[string]any{"url": "http://x"},
		Event:  eventbus.Event{Type: "test"},
	}
	_ = p.Submit(job)
	_ = p.Submit(job)

	start := time.Now()
	p.Shutdown(200 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("shutdown took %v — should have given up at ~200ms", elapsed)
	}
}

// newCountingPool creates a WorkerPool whose deliver step is replaced
// by `onDeliver`. We do this by composing a Service whose `client` is
// nil (so the real deliver short-circuits) and post-processing via
// the pool's own runWorker hook... actually we can't substitute the
// deliver method directly. Instead we wire a tiny Service variant.
//
// Approach: monkey-patch by reaching into the pool's svc field: we
// install a Service whose deliver path is no-op via a custom struct.
func newCountingPool(t *testing.T, workers, queue int, onDeliver func()) *WorkerPool {
	t.Helper()
	svc := &Service{}
	// We can't replace svc.deliver, but we CAN install a custom
	// runWorker via the same shape as NewWorkerPool — duplicate the
	// constructor here so the test owns the worker loop.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := &WorkerPool{
		svc:       svc,
		workers:   workers,
		queueSize: queue,
		jobs:      make(chan DeliveryJob, queue),
		ctx:       ctx,
		cancel:    cancel,
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-p.ctx.Done():
					return
				case _, ok := <-p.jobs:
					if !ok {
						return
					}
					if onDeliver != nil {
						// Honour pool ctx cancellation by shadowing onDeliver
						// with a select against ctx.Done.
						doneCh := make(chan struct{})
						go func() {
							onDeliver()
							close(doneCh)
						}()
						select {
						case <-doneCh:
						case <-p.ctx.Done():
							return
						}
					}
				}
			}
		}()
	}
	return p
}
