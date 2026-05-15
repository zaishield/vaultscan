//go:build integration

// §23 Notification engine: queue → dispatch → retry with backoff.

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/notify"
)

// fakeTransport collects sent messages + can be flipped to fail.
type fakeTransport struct {
	kind   string
	fail   atomic.Bool
	sent   atomic.Int32
	lastTo string
}

func (f *fakeTransport) Kind() string { return f.kind }
func (f *fakeTransport) Send(_ context.Context, cfg notify.ChannelConfig, msg notify.Message) (string, error) {
	if to, ok := cfg.Config["to"].(string); ok {
		f.lastTo = to
	}
	if f.fail.Load() {
		return "", errors.New("simulated transport failure")
	}
	f.sent.Add(1)
	return "ok-id-" + msg.Subject, nil
}

func TestNotify_QueueDispatchDelivered(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "notify-ok")

	svc := notify.New(h.pool)
	ft := &fakeTransport{kind: "email"}
	svc.RegisterTransport(ft)

	chID, err := svc.CreateChannel(ctx, notify.ChannelConfig{
		TenantID: tenantID, Kind: "email", Label: "soc-on-call",
		Config: map[string]any{"to": "soc@globex.example"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Enqueue(ctx, notify.EnqueueInput{
		ChannelID: chID, Subject: "CRITICAL finding", Body: "go look",
		Priority: "urgent",
		Payload:  map[string]any{"finding_id": uuid.New().String()},
	}); err != nil {
		t.Fatal(err)
	}

	processed, err := svc.DispatchOne(ctx)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !processed {
		t.Fatal("expected DispatchOne to return processed=true on a queued message")
	}
	if ft.sent.Load() != 1 {
		t.Fatalf("expected 1 send, got %d", ft.sent.Load())
	}
	if ft.lastTo != "soc@globex.example" {
		t.Fatalf("transport didn't receive the 'to' from config: %q", ft.lastTo)
	}

	// State row = delivered.
	var state string
	_ = h.pool.QueryRow(ctx,
		`SELECT state FROM notification_queue WHERE channel_id=$1
		  ORDER BY created_at DESC LIMIT 1`, chID).Scan(&state)
	if state != "delivered" {
		t.Fatalf("expected delivered, got %s", state)
	}
}

func TestNotify_FailureBackoffThenQuarantine(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "notify-fail")

	svc := notify.New(h.pool)
	ft := &fakeTransport{kind: "sms"}
	ft.fail.Store(true)
	svc.RegisterTransport(ft)

	chID, _ := svc.CreateChannel(ctx, notify.ChannelConfig{
		TenantID: tenantID, Kind: "sms", Label: "ciso-direct",
		Config: map[string]any{"to": "+15551234567"},
	})
	msgID, _ := svc.Enqueue(ctx, notify.EnqueueInput{
		ChannelID: chID, Subject: "urgent", Body: "fix it",
		Priority: "urgent",
	})

	// Hammer the queue. Each dispatch fails; next_attempt_at moves
	// into the future via the backoff, so we manually pull it back to
	// "now" between iterations to exercise the state machine quickly.
	for i := 0; i < 6; i++ {
		_, _ = svc.DispatchOne(ctx)
		_, _ = h.pool.Exec(ctx,
			`UPDATE notification_queue SET next_attempt_at = now() WHERE id=$1`, msgID)
	}

	var state string
	var attempt int
	_ = h.pool.QueryRow(ctx,
		`SELECT state, attempt FROM notification_queue WHERE id=$1`, msgID).
		Scan(&state, &attempt)
	if state != "quarantined" {
		t.Fatalf("expected quarantined after 6 attempts, got %s (attempt=%d)", state, attempt)
	}
}

func TestNotify_PagerDutyPayloadShape(t *testing.T) {
	// Bypass the DB queue — just exercise the transport's request body.
	tr := &notify.PagerDutyTransport{}
	cfg := notify.ChannelConfig{
		Kind: "pagerduty", Label: "p1",
		Config: map[string]any{"routing_key": "TEST-KEY"},
	}
	// We don't want a real HTTP call here. Use a small in-process
	// roundtripper.
	srv := newCapturedHTTP(t, func(body []byte) {
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if doc["routing_key"] != "TEST-KEY" {
			t.Fatalf("routing_key missing/wrong: %v", doc["routing_key"])
		}
		payload, _ := doc["payload"].(map[string]any)
		if payload["severity"] != "critical" {
			t.Fatalf("urgent priority should map to severity=critical, got %v",
				payload["severity"])
		}
	})
	tr.HTTP = srv.client
	_, _ = tr.Send(context.Background(), cfg, notify.Message{
		Subject: "Audit chain break", Priority: "urgent",
		Payload: map[string]any{"finding_id": "abc"},
	})
	srv.close()
}
