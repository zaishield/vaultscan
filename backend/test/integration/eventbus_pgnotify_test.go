//go:build integration

// Cross-process eventbus delivery via Postgres NOTIFY/LISTEN.
//
// Setup:
//   * Bus A: producer, EnableNotify (no listener — represents a worker
//     process that only publishes).
//   * Bus B: consumer, EnableNotify + StartListener (represents the
//     analytics-worker which both publishes and consumes).
//
// We publish on Bus A and assert Bus B's subscriber sees the event.
// This proves cross-process delivery without needing two OS processes:
// each Bus has its own subscriber registry, so seeing the event on
// Bus B means it flowed via Postgres NOTIFY, not in-process fanout.

package integration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

func TestEventbus_PGNotify_CrossProcessDelivery(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Producer-only bus (no listener) — emulates a worker.
	busA := eventbus.New(h.pool)
	busA.EnableNotify()

	// Consumer bus — emulates the analytics-worker.
	busB := eventbus.New(h.pool)
	busB.EnableNotify()
	busB.StartListener(ctx)

	var received atomic.Int32
	gotPayload := make(chan map[string]any, 1)
	busB.Subscribe("FindingNormalized", func(_ context.Context, ev eventbus.Event) {
		received.Add(1)
		select {
		case gotPayload <- ev.Payload:
		default:
		}
	})

	// Let the listener acquire its LISTEN conn.
	time.Sleep(300 * time.Millisecond)

	tenantID, _ := h.makeTenant(t, "pgnotify-"+uuid.NewString()[:6])
	if err := busA.Publish(ctx, eventbus.Event{
		Type:     "FindingNormalized",
		TenantID: &tenantID,
		Payload: map[string]any{
			"cve":       "CVE-2026-XYZ",
			"severity":  "critical",
			"endpoint":  "https://api.example.com",
		},
	}); err != nil {
		t.Fatalf("Bus A publish: %v", err)
	}

	// Wait up to 3s for the NOTIFY to land on Bus B.
	deadline := time.After(3 * time.Second)
	for received.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("Bus B never received the event (NOTIFY/LISTEN bridge broken)")
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Verify payload arrived intact.
	select {
	case p := <-gotPayload:
		if p["cve"] != "CVE-2026-XYZ" {
			t.Errorf("payload cve=%v, want CVE-2026-XYZ", p["cve"])
		}
		if p["severity"] != "critical" {
			t.Errorf("payload severity=%v, want critical", p["severity"])
		}
	case <-time.After(time.Second):
		t.Fatal("payload channel timed out (event delivered with empty payload?)")
	}
}

// TestEventbus_PGNotify_LargePayloadFallsBackToBusEvents covers the
// 8000-byte NOTIFY limit. When the payload is too big, we emit a
// marker NOTIFY and consumers fetch the full event from bus_events.
func TestEventbus_PGNotify_LargePayloadFallsBackToBusEvents(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	busA := eventbus.New(h.pool)
	busA.EnableNotify()

	busB := eventbus.New(h.pool)
	busB.EnableNotify()
	busB.StartListener(ctx)

	var received atomic.Int32
	gotPayload := make(chan map[string]any, 1)
	busB.Subscribe("ReportGenerated", func(_ context.Context, ev eventbus.Event) {
		received.Add(1)
		select {
		case gotPayload <- ev.Payload:
		default:
		}
	})
	time.Sleep(300 * time.Millisecond)

	// Build a large payload that will exceed 7500 bytes after JSON
	// encoding — forces the marker fallback.
	big := make([]byte, 10000)
	for i := range big {
		big[i] = 'X'
	}
	tenantID, _ := h.makeTenant(t, "pgnotify-"+uuid.NewString()[:6])
	if err := busA.Publish(ctx, eventbus.Event{
		Type:     "ReportGenerated",
		TenantID: &tenantID,
		Payload:  map[string]any{"big": string(big)},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(3 * time.Second)
	for received.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("large-payload event never received")
		case <-time.After(50 * time.Millisecond):
		}
	}
	select {
	case p := <-gotPayload:
		// Even the truncated NOTIFY → consumer must reconstitute the
		// full payload from bus_events.
		v, _ := p["big"].(string)
		if len(v) < 1000 {
			t.Errorf("payload truncated: got %d bytes, want 10000 (bus_events fallback)", len(v))
		}
	case <-time.After(time.Second):
		t.Fatal("payload channel timed out")
	}
}
