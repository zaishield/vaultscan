//go:build integration

// Extended chaos tests — failure-injection scenarios beyond the three
// SEV-3 polishes. Each test simulates one of the realistic failure
// modes ops engineers worry about and confirms the system stays in a
// recoverable state.

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
)

// TestChaos_IntegrationWebhookFlaps simulates a customer webhook
// receiver that returns 502/503/504 intermittently. Test() should
// surface the failure as a non-OK result with a recorded status,
// not panic or hang.
func TestChaos_IntegrationWebhookFlaps(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "chaos-flap-"+uuid.NewString()[:6])

	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := n.Add(1)
		switch i % 4 {
		case 0:
			w.WriteHeader(200)
		case 1:
			w.WriteHeader(502)
		case 2:
			w.WriteHeader(503)
		case 3:
			w.WriteHeader(504)
		}
	}))
	defer srv.Close()

	svc := integrations.New(h.pool, h.bus, h.audit)
	id, err := svc.Create(context.Background(), integrations.CreateInput{
		TenantID: &tenantID, PartnerID: &directID,
		Type: "webhook", Name: "flap-" + uuid.NewString()[:6],
		Config: map[string]any{"url": srv.URL}, CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fire Test() five times; record outcomes. None should panic
	// and at least some should report non-OK status.
	var okCount, failCount int
	for i := 0; i < 5; i++ {
		res, err := svc.Test(context.Background(), id)
		if err != nil {
			t.Fatalf("iteration %d errored: %v", i, err)
		}
		if res.OK {
			okCount++
		} else {
			failCount++
		}
	}
	if failCount == 0 {
		t.Errorf("expected at least one flap to surface as non-OK; got all OK (%d)", okCount)
	}
}

// TestChaos_DBPoolExhaustionRecovery — fires many concurrent
// integrations.Test calls; even when the pool saturates, every call
// should return (no goroutine leak, no deadlock).
func TestChaos_DBPoolExhaustionRecovery(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "chaos-pool-"+uuid.NewString()[:6])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// slow response to keep DB pool contention up
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	svc := integrations.New(h.pool, h.bus, h.audit)
	id, err := svc.Create(context.Background(), integrations.CreateInput{
		TenantID: &tenantID, PartnerID: &directID,
		Type: "webhook", Name: "pool-" + uuid.NewString()[:6],
		Config: map[string]any{"url": srv.URL}, CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	const N = 32
	var wg sync.WaitGroup
	errs := make(chan error, N)
	start := time.Now()
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Test(context.Background(), id)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Test errored: %v", err)
		}
	}
	// Smoke: must not take impossibly long (deadlock surrogate).
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("32 parallel Tests took %v — possible deadlock", took)
	}
}

// TestChaos_EventBusSubscriberPanicRecovered — an outbound integration
// adapter that panics during fanout must not poison the entire bus.
func TestChaos_EventBusSubscriberPanicRecovered(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "chaos-panic-"+uuid.NewString()[:6])

	var ok atomic.Int32
	var panicHit atomic.Int32
	// Subscriber A: well-behaved.
	h.bus.Subscribe("finding.created", func(_ context.Context, _ eventbus.Event) {
		ok.Add(1)
	})
	// Subscriber B: panics on every call.
	h.bus.Subscribe("finding.created", func(_ context.Context, _ eventbus.Event) {
		panicHit.Add(1)
		panic("simulated subscriber panic")
	})

	err := h.bus.Publish(context.Background(), eventbus.Event{
		ID: uuid.New(), Type: "finding.created", TenantID: &tenantID,
		PartnerID: &directID, Payload: map[string]any{"severity": "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Give subscribers a tick — eventbus runs them in goroutines.
	time.Sleep(100 * time.Millisecond)
	if ok.Load() == 0 {
		t.Error("well-behaved subscriber never ran — bus poisoned by panic")
	}
}

// TestChaos_ContextCancellationDuringIntegrationTest — caller's
// context is cancelled mid-call. Test() should return promptly with
// either the context error or a record of the cancellation, not
// hang or leak the HTTP request.
func TestChaos_ContextCancellationDuringIntegrationTest(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "chaos-cancel-"+uuid.NewString()[:6])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	svc := integrations.New(h.pool, h.bus, h.audit)
	id, err := svc.Create(context.Background(), integrations.CreateInput{
		TenantID: &tenantID, PartnerID: &directID,
		Type: "webhook", Name: "cancel-" + uuid.NewString()[:6],
		Config: map[string]any{"url": srv.URL}, CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = svc.Test(ctx, id)
	took := time.Since(start)
	// Either error or a non-OK result is acceptable; what is NOT
	// acceptable is taking >1s when the ctx expired at 100ms.
	if took > time.Second {
		t.Errorf("Test ignored context cancellation; took %v", took)
	}
	_ = errors.Is // silence import on some build paths
}
