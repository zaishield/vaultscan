//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// TestFindings_DedupAndLifecycle asserts the 9-field dedup key in the live
// database and the 11-state lifecycle machine.
func TestFindings_DedupAndLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := adminID

	tenantID, engagementID := h.makeTenant(t, "findings-dedup")

	in := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		Title:           "X-Frame-Options missing",
		Severity:        "low",
		Confidence:      "high",
		Scanner:         "zap",
		ScanType:        "web",
		AffectedEndpoint: "https://api.example.com",
		Port:            443,
		Protocol:        "tcp",
		CWE:             "1021",
	}

	f1, isNew, err := h.findings.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !isNew {
		t.Fatalf("first upsert should be new")
	}

	// Second identical ingest must dedupe.
	f2, isNew2, err := h.findings.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if isNew2 || f2.ID != f1.ID {
		t.Fatalf("expected dedup; got isNew=%v, ids %s vs %s", isNew2, f1.ID, f2.ID)
	}

	// Different endpoint must produce a new finding.
	in2 := in
	in2.AffectedEndpoint = "https://other.example.com"
	f3, isNew3, err := h.findings.Upsert(ctx, in2)
	if err != nil {
		t.Fatalf("different endpoint upsert: %v", err)
	}
	if !isNew3 || f3.ID == f1.ID {
		t.Fatalf("expected distinct finding; got isNew=%v, id=%s", isNew3, f3.ID)
	}

	// Lifecycle: open -> triaged -> assigned -> in_progress -> remediated -> retest_requested -> retest_passed -> closed
	steps := []string{"triaged", "assigned", "in_progress", "remediated", "retest_requested", "retest_passed", "closed"}
	for _, s := range steps {
		if err := h.findings.Transition(ctx, &actor, f1.ID, s, "test"); err != nil {
			t.Fatalf("transition %s: %v", s, err)
		}
	}

	// Invalid transition must be rejected.
	if err := h.findings.Transition(ctx, &actor, f1.ID, "in_progress", ""); err == nil {
		t.Fatalf("expected invalid transition closed -> in_progress to fail")
	}

	// status_history rows recorded.
	var hist int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM finding_status_history WHERE finding_id=$1`, f1.ID).
		Scan(&hist); err != nil {
		t.Fatalf("history count: %v", err)
	}
	if hist < len(steps)+1 { // +1 for the initial-ingest entry
		t.Fatalf("expected >= %d history rows, got %d", len(steps)+1, hist)
	}
}
