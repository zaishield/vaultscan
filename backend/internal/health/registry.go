// Package health builds the component-level health snapshot served
// at /api/v1/health (authenticated) and /readyz (anonymous). Each
// check runs with a tight timeout; the aggregate goes degraded
// when any non-optional component is failing.
package health

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Status is the per-component health verdict.
type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
)

// CheckFunc returns ok/down + a short, operator-readable detail.
// The string is shown in the aggregate response so ops can triage
// without opening a SRE notebook.
type CheckFunc func(ctx context.Context) (Status, string)

// Component describes one health check. Optional checks (e.g.
// external SIEM forwarder) don't fail the aggregate when down.
type Component struct {
	Name     string
	Check    CheckFunc
	Optional bool
}

// Registry collects checks and answers Snapshot calls.
type Registry struct {
	mu    sync.RWMutex
	comps []Component
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(name string, check CheckFunc, optional bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.comps = append(r.comps, Component{Name: name, Check: check, Optional: optional})
}

// Snapshot runs every check in parallel with a per-check timeout
// and returns the aggregated result. ctx caps the whole call.
func (r *Registry) Snapshot(ctx context.Context, perCheckTimeout time.Duration) Result {
	r.mu.RLock()
	comps := make([]Component, len(r.comps))
	copy(comps, r.comps)
	r.mu.RUnlock()

	type pair struct {
		name   string
		status Status
		detail string
		opt    bool
	}
	out := make([]pair, len(comps))
	var wg sync.WaitGroup
	for i, c := range comps {
		i, c := i, c
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, perCheckTimeout)
			defer cancel()
			st, det := c.Check(cctx)
			out[i] = pair{c.Name, st, det, c.Optional}
		}()
	}
	wg.Wait()

	res := Result{
		Status:     StatusOK,
		Components: make([]ComponentResult, len(out)),
	}
	for i, p := range out {
		res.Components[i] = ComponentResult{
			Name: p.name, Status: p.status, Detail: p.detail, Optional: p.opt,
		}
		if p.status == StatusDown && !p.opt {
			res.Status = StatusDegraded
		}
	}
	return res
}

// Result is the aggregate view returned by Snapshot.
type Result struct {
	Status     Status            `json:"status"`
	Components []ComponentResult `json:"components"`
	Timestamp  time.Time         `json:"timestamp"`
}

// ComponentResult is one slice of the aggregate.
type ComponentResult struct {
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

// HTTPStatusFor maps a Result to the canonical HTTP code. Used by
// /readyz so kubelet's readiness probe flips the pod out of service
// when anything mandatory is down.
func (r Result) HTTPStatusFor() int {
	if r.Status == StatusOK {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}
