//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
)

// Helper: spin a httptest webhook that returns the given status code +
// counts requests.
func httpEcho(status int) (*httptest.Server, *int32) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
	}))
	return srv, &count
}

// TestVS11_DeadLetterOnFailure: a webhook integration pointing at a
// 500-always endpoint exhausts retries and the event lands in DLQ.
func TestVS11_DeadLetterOnFailure(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs11-dlq")
	svc := integrations.New(h.pool, h.bus, h.audit)
	svc.MaxAttempts = 2
	svc.InitialBackoff = 50 * time.Millisecond

	srv, _ := httpEcho(http.StatusInternalServerError)
	t.Cleanup(srv.Close)

	id, err := svc.Create(ctx, integrations.CreateInput{
		TenantID: &tenantID, Type: "webhook", Name: "vs11-dlq-hook",
		Config:    map[string]any{"url": srv.URL},
		EventFilter: []string{eventbus.FindingNormalized},
		CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}

	ev := eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		TenantID: &tenantID, Payload: map[string]any{
			"finding_id": uuid.New(), "severity": "high", "cve": "CVE-2020-9999",
		},
	}
	// Call Fanout via the bus (will invoke deliver internally).
	svc.Wire(h.bus)
	if err := h.bus.Publish(ctx, ev); err != nil {
		t.Fatal(err)
	}

	// Bus fanout is async; the integration service uses Subscribe with a
	// goroutine. Poll the DB briefly.
	if !awaitNonEmpty(t, func() bool {
		list, _ := svc.ListDeadLetters(ctx, id)
		return len(list) > 0
	}) {
		t.Fatal("no dead-letter recorded after retries on failing webhook")
	}
	list, _ := svc.ListDeadLetters(ctx, id)
	if list[0].Attempts < svc.MaxAttempts {
		t.Fatalf("expected %d attempts before DLQ, got %d", svc.MaxAttempts, list[0].Attempts)
	}
}

// TestVS11_ReplayFromDLQ: replay a DLQ entry against a now-200 server
// transitions outcome=delivered and DLQ row resolved.
func TestVS11_ReplayFromDLQ(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs11-replay")
	svc := integrations.New(h.pool, h.bus, h.audit)

	// Use a counter-server we can flip from 500 → 200.
	var failing int32 = 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&failing) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	id, err := svc.Create(ctx, integrations.CreateInput{
		TenantID: &tenantID, Type: "webhook", Name: "vs11-replay-hook",
		Config: map[string]any{"url": srv.URL}, CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Manually enqueue a DLQ row (bypass the bus to keep the test fast).
	ev := eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		TenantID: &tenantID, Payload: map[string]any{"severity": "high"},
	}
	dlqID, err := svc.EnqueueDeadLetter(ctx, id, ev, 5, "boom", 500)
	if err != nil {
		t.Fatal(err)
	}

	// Flip the server to success + replay.
	atomic.StoreInt32(&failing, 0)
	if err := svc.Replay(ctx, dlqID, &adminID); err != nil {
		t.Fatalf("replay: %v", err)
	}
	var resolution string
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(resolution,'') FROM integration_dead_letters WHERE id=$1`,
		dlqID).Scan(&resolution)
	if resolution != "replayed" {
		t.Fatalf("expected resolution=replayed, got %q", resolution)
	}
	var outcome string
	_ = h.pool.QueryRow(ctx,
		`SELECT outcome FROM integration_replays WHERE dead_letter_id=$1`, dlqID).Scan(&outcome)
	if outcome != "delivered" {
		t.Fatalf("expected outcome=delivered, got %q", outcome)
	}
}

// TestVS11_JiraPayload: BuildJiraIssue produces the right Jira REST shape.
func TestVS11_JiraPayload(t *testing.T) {
	body, err := integrations.BuildJiraIssue(eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		Payload: map[string]any{
			"title": "TLS 1.0 enabled", "severity": "critical",
			"cve": "CVE-2024-1234", "cvss_score": 9.1,
		},
	}, map[string]any{
		"project_key": "SEC",
		"custom_fields": map[string]any{
			"cve":  "customfield_10001",
			"cvss": "customfield_10002",
		},
	}, "Vulnerability")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	fields := got["fields"].(map[string]any)
	if proj, ok := fields["project"].(map[string]any); !ok || proj["key"] != "SEC" {
		t.Fatalf("project_key not set: %v", fields["project"])
	}
	if it, ok := fields["issuetype"].(map[string]any); !ok || it["name"] != "Vulnerability" {
		t.Fatalf("issuetype not Vulnerability: %v", fields["issuetype"])
	}
	if pr, ok := fields["priority"].(map[string]any); !ok || pr["name"] != "Highest" {
		t.Fatalf("priority must map critical→Highest, got: %v", fields["priority"])
	}
	if fields["customfield_10001"] != "CVE-2024-1234" {
		t.Fatalf("CVE custom field missing: %v", fields["customfield_10001"])
	}
	if fields["customfield_10002"] != 9.1 {
		t.Fatalf("CVSS custom field wrong: %v", fields["customfield_10002"])
	}
}

// TestVS11_ServiceNowIncident: BuildServiceNowIncident maps severity →
// urgency correctly + sets caller_id from config.
func TestVS11_ServiceNowIncident(t *testing.T) {
	body, _ := integrations.BuildServiceNowIncident(eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		Payload: map[string]any{
			"title": "SQL injection in /login", "severity": "high",
		},
	}, map[string]any{"caller_id": "vaultscan-bot"})
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["urgency"].(float64) != 2 {
		t.Fatalf("expected urgency=2 (high), got %v", got["urgency"])
	}
	if got["caller_id"] != "vaultscan-bot" {
		t.Fatalf("caller_id missing: %v", got["caller_id"])
	}
}

// TestVS11_CEFFormat: BuildCEF emits a properly formatted CEF 0 line.
func TestVS11_CEFFormat(t *testing.T) {
	tenantID := uuid.New()
	line := integrations.BuildCEF(eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized, TenantID: &tenantID,
		Payload: map[string]any{
			"title": "Weak TLS", "severity": "high",
			"cve": "CVE-2020-12345", "cvss_score": 8.5,
		},
	})
	if !strings.HasPrefix(line, "CEF:0|ZAISHIELD|VAULTSCAN|1.0|FindingNormalized|Weak TLS|8|") {
		t.Fatalf("CEF header wrong:\n%s", line)
	}
	if !strings.Contains(line, "cs2Label=cve") || !strings.Contains(line, "cs2=CVE-2020-12345") {
		t.Fatalf("CEF missing cve extensions:\n%s", line)
	}
	if !strings.Contains(line, "cn1=8.5") {
		t.Fatalf("CEF missing cvss:\n%s", line)
	}
}

// TestVS11_LEEFFormat: BuildLEEF emits the LEEF 2.0 line.
func TestVS11_LEEFFormat(t *testing.T) {
	line := integrations.BuildLEEF(eventbus.Event{
		ID: uuid.New(), Type: eventbus.FindingNormalized,
		Payload: map[string]any{"severity": "medium", "title": "Open Port"},
	})
	if !strings.HasPrefix(line, "LEEF:2.0|ZAISHIELD|VAULTSCAN|1.0|FindingNormalized|^|") {
		t.Fatalf("LEEF header wrong:\n%s", line)
	}
	if !strings.Contains(line, "severity=medium") {
		t.Fatalf("LEEF missing severity:\n%s", line)
	}
}

// awaitNonEmpty polls cond — used while the integration service's
// async retry loop is in flight.
func awaitNonEmpty(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
