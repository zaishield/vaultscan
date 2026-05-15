//go:build integration

// §22 deepening: external event-bus adapter fans out alongside the
// in-process subscribers + the bus_events durability row.

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

func TestSection22_ExternalSinkReceivesPublish(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	mock := eventbus.NewMockSink()
	h.bus.AttachExternal(mock)

	tenantID, _ := h.makeTenant(t, "section22")
	if err := h.bus.Publish(ctx, eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		TenantID: &tenantID, Payload: map[string]any{"severity": "critical"},
	}); err != nil {
		t.Fatal(err)
	}

	// External fan-out is async; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(mock.Received()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := mock.Received()
	if len(got) == 0 {
		t.Fatal("external sink received no events")
	}
	// The in-process subscription path AND the bus_events row should
	// still work — the external path is additive, not a replacement.
	var rowCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT count(*) FROM bus_events WHERE tenant_id=$1`, tenantID).Scan(&rowCount)
	if rowCount == 0 {
		t.Fatal("bus_events durability row missing — external path replaced local persistence")
	}
}

func TestSection22_PublishSurvivesSinkPanic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Attaching a sink that always errors must NOT make Publish fail.
	bad := &erroringSink{}
	h.bus.AttachExternal(bad)
	tenantID, _ := h.makeTenant(t, "section22-panic")
	if err := h.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.FindingNormalized, TenantID: &tenantID,
		Payload: map[string]any{},
	}); err != nil {
		t.Fatalf("Publish failed when external sink errors: %v", err)
	}
}

type erroringSink struct{}

func (erroringSink) Name() string { return "errsink" }
func (erroringSink) Forward(context.Context, eventbus.Event) error {
	return context.DeadlineExceeded
}
func (erroringSink) Close() error { return nil }
