//go:build integration

package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
)

// Outbound webhook contract tests:
//   * Slack-shaped POST against a fake httptest receiver
//   * Webhook with HMAC X-Vaultscan-Signature header — verified by
//     recomputing on the receiver side
//   * Test() against an integration row — happy path + 500 path
//
// These cover the full deliver / test stack: DB → buildPayload →
// HTTP POST → HMAC sign → response parsing → integration_deliveries
// insert.

type recvState struct {
	mu       sync.Mutex
	requests []recvReq
	hits     atomic.Int32
}
type recvReq struct {
	Method, Path string
	Headers      http.Header
	Body         []byte
}

func newRecv(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *recvState) {
	t.Helper()
	st := &recvState{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		st.mu.Lock()
		st.requests = append(st.requests, recvReq{
			Method: r.Method, Path: r.URL.Path,
			Headers: r.Header.Clone(), Body: body,
		})
		st.mu.Unlock()
		st.hits.Add(1)
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, st
}

func createIntegration(t *testing.T, h *harness, tenantID uuid.UUID, itype, name string, config map[string]any) uuid.UUID {
	t.Helper()
	svc := integrations.New(h.pool, h.bus, h.audit)
	id, err := svc.Create(context.Background(), integrations.CreateInput{
		TenantID: &tenantID, PartnerID: &directID,
		Type: itype, Name: name, Config: config,
		EventFilter: []string{"finding.created"},
		CreatedBy:   &adminID,
	})
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	return id
}

func TestOutbound_TestEndpoint_HappyPath(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-test-"+uuid.NewString()[:6])
	recv, st := newRecv(t, nil)
	id := createIntegration(t, h, tenantID, "webhook", "test-"+uuid.NewString()[:6], map[string]any{
		"url": recv.URL + "/inbound",
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	res, err := svc.Test(context.Background(), id)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !res.OK || res.StatusCode != 200 {
		t.Errorf("test result not OK: %+v", res)
	}
	if st.hits.Load() != 1 {
		t.Errorf("receiver hits=%d want 1", st.hits.Load())
	}
	got := st.requests[0]
	if got.Method != "POST" || got.Path != "/inbound" {
		t.Errorf("request %s %s, want POST /inbound", got.Method, got.Path)
	}
	if ct := got.Headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type=%q want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(got.Body, &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["event_type"] != "vaultscan.test" {
		t.Errorf("event_type=%v want vaultscan.test", body["event_type"])
	}
}

func TestOutbound_TestEndpoint_NoURLConfigured(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-nourl-"+uuid.NewString()[:6])
	id := createIntegration(t, h, tenantID, "webhook", "nourl-"+uuid.NewString()[:6], map[string]any{
		// deliberately no url
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	res, err := svc.Test(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error == "" {
		t.Errorf("expected error for missing url, got %+v", res)
	}
}

func TestOutbound_TestEndpoint_Receiver500(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-500-"+uuid.NewString()[:6])
	recv, _ := newRecv(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	})
	id := createIntegration(t, h, tenantID, "webhook", "500-"+uuid.NewString()[:6], map[string]any{
		"url": recv.URL,
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	res, err := svc.Test(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.StatusCode != 500 {
		t.Errorf("test result for 500 = %+v", res)
	}
}

func TestOutbound_HMACSignatureRoundTrip(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-hmac-"+uuid.NewString()[:6])

	secret := "shh-very-secret-" + uuid.NewString()
	var verified atomic.Bool
	recv, _ := newRecv(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-Vaultscan-Signature")
		if sig == "" {
			http.Error(w, "missing signature", 400)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(want)) {
			http.Error(w, "bad signature", 400)
			return
		}
		verified.Store(true)
		w.WriteHeader(204)
	})

	id := createIntegration(t, h, tenantID, "webhook", "hmac-"+uuid.NewString()[:6], map[string]any{
		"url":         recv.URL,
		"hmac_secret": secret,
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	res, err := svc.Test(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("HMAC verification failed at receiver: %+v", res)
	}
	if !verified.Load() {
		t.Error("receiver never recorded a verified signature")
	}
}

func TestOutbound_BuildSlackPayload_RoundTrip(t *testing.T) {
	// Build* helpers are pure but the slack/teams branches live inside
	// buildPayload (unexported). Exercise them through Test() with a
	// fake slack receiver.
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-slack-"+uuid.NewString()[:6])
	recv, st := newRecv(t, nil)
	id := createIntegration(t, h, tenantID, "slack", "slack-"+uuid.NewString()[:6], map[string]any{
		"url": recv.URL,
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	if _, err := svc.Test(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if st.hits.Load() == 0 {
		t.Fatal("slack receiver never hit")
	}
}

func TestOutbound_DeadLetterEnqueueAndResolve(t *testing.T) {
	h := newHarness(t)
	tenantID, _ := h.makeTenant(t, "outbound-dlq-"+uuid.NewString()[:6])
	id := createIntegration(t, h, tenantID, "webhook", "dlq-"+uuid.NewString()[:6], map[string]any{
		"url": "http://127.0.0.1:1", // unreachable
	})
	svc := integrations.New(h.pool, h.bus, h.audit)
	ev := eventbus.Event{
		ID: uuid.New(), Type: "finding.created",
		TenantID: &tenantID, PartnerID: &directID,
		Payload: map[string]any{"severity": "high", "title": "x"},
	}
	dlqID, err := svc.EnqueueDeadLetter(context.Background(), id, ev, 5, "max attempts reached", 0)
	if err != nil {
		t.Fatalf("EnqueueDeadLetter: %v", err)
	}
	list, err := svc.ListDeadLetters(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range list {
		if d.ID == dlqID {
			found = true
			if d.Attempts != 5 {
				t.Errorf("attempts=%d want 5", d.Attempts)
			}
		}
	}
	if !found {
		t.Errorf("DLQ entry not in list")
	}
	if err := svc.MarkDeadLetterResolved(context.Background(), dlqID, "dropped"); err != nil {
		t.Fatal(err)
	}
	// Bad resolution must error
	if err := svc.MarkDeadLetterResolved(context.Background(), dlqID, "garbage"); err == nil {
		t.Error("bad resolution should error")
	}
}
