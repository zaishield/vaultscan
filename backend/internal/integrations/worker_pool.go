// worker_pool.go — bounded worker pool for outbound delivery.
//
// Before this file: Service.fanout fired `go s.deliver(context.Background(), ...)`
// per matching integration per event. Problems:
//   1. Unbounded goroutine count — a flood of events could spawn
//      thousands of concurrent HTTP calls.
//   2. context.Background() — on SIGTERM the http.Server.Shutdown
//      would drain the API server but these goroutines would be killed
//      mid-call, losing in-flight DLQ writes.
//
// After this file: a fixed pool of N workers consumes a buffered job
// queue. Shutdown drains pending jobs (up to a deadline) then cancels
// any still in flight. The pool's context is derived from a parent
// supplied by main, so cancelling that context propagates everywhere.

package integrations

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// DeliveryJob is one queued outbound webhook/integration call.
type DeliveryJob struct {
	IntegrationID uuid.UUID
	Type          string
	Name          string
	Config        map[string]any
	Event         eventbus.Event
}

// WorkerPool is a bounded pool of goroutines that consume DeliveryJobs.
// Created at service init, closed on shutdown.
type WorkerPool struct {
	svc        *Service
	workers    int
	queueSize  int
	jobs       chan DeliveryJob
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	overflowed int
	overMu     sync.Mutex
}

// NewWorkerPool starts `workers` goroutines that read from a buffered
// channel of `queueSize` jobs. Cancel parentCtx to begin shutdown.
func NewWorkerPool(parentCtx context.Context, svc *Service, workers, queueSize int) *WorkerPool {
	if workers <= 0 {
		workers = 8
	}
	if queueSize <= 0 {
		queueSize = workers * 16
	}
	ctx, cancel := context.WithCancel(parentCtx)
	p := &WorkerPool{
		svc:       svc,
		workers:   workers,
		queueSize: queueSize,
		jobs:      make(chan DeliveryJob, queueSize),
		ctx:       ctx,
		cancel:    cancel,
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.runWorker()
	}
	return p
}

func (p *WorkerPool) runWorker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			// Each delivery gets a fresh per-job timeout derived from
			// the pool ctx. If the pool is cancelled mid-delivery, the
			// HTTP client honours that cancellation and exits the call.
			jobCtx, cancel := context.WithTimeout(p.ctx, 60*time.Second)
			p.svc.deliver(jobCtx, job.IntegrationID, job.Type, job.Name, job.Config, job.Event)
			cancel()
		}
	}
}

// Submit enqueues a job. Returns false if the queue is full — caller
// should fall back to in-line delivery or DLQ. We never block on
// submit (would risk the API hot path).
func (p *WorkerPool) Submit(job DeliveryJob) bool {
	select {
	case p.jobs <- job:
		return true
	default:
		p.overMu.Lock()
		p.overflowed++
		p.overMu.Unlock()
		return false
	}
}

// OverflowCount returns how many submits have been dropped due to
// queue saturation. Surfaced via a Prometheus gauge by the cron-runner
// so ops can alert on chronic backpressure.
func (p *WorkerPool) OverflowCount() int {
	p.overMu.Lock()
	defer p.overMu.Unlock()
	return p.overflowed
}

// Shutdown closes the input channel (blocks new submits) and waits up
// to `gracePeriod` for in-flight workers to finish. Any work still
// running after the deadline is cancelled via the pool ctx.
func (p *WorkerPool) Shutdown(gracePeriod time.Duration) {
	close(p.jobs)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Clean shutdown.
	case <-time.After(gracePeriod):
		// Workers stuck — cancel pool ctx; per-job ctxs derived from
		// it will cancel too.
		p.cancel()
		<-done  // now they will exit
	}
}
