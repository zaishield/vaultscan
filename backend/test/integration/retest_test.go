//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
)

// TestRetest_LaunchScan: a remediated finding's retest request, when
// launched, materialises a targeted scan job that reuses the original
// endpoint and a matching profile.
func TestRetest_LaunchScan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "retest-launch")

	// Approve a scope target that covers the endpoint we'll retest.
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"domain", "globex.example", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	// Create a finding then mark it remediated (the only state from which
	// retest_requested is reachable in the lifecycle machine).
	f, _, err := h.findings.Upsert(ctx, findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		Title: "X-Frame-Options missing", Severity: "medium",
		Scanner: "zap", ScanType: "web",
		AffectedEndpoint: "https://globex.example/admin",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	for _, s := range []string{"triaged", "assigned", "in_progress", "remediated"} {
		if err := h.findings.Transition(ctx, &adminID, f.ID, s, "test"); err != nil {
			t.Fatalf("transition %s: %v", s, err)
		}
	}

	retestSvc := retesting.New(h.pool, h.audit, h.bus, h.findings, h.scanorch)
	retestID, err := retestSvc.Request(ctx, retesting.RequestInput{
		FindingID: f.ID, RequestedBy: &adminID, Note: "fix verified",
	})
	if err != nil {
		t.Fatalf("request retest: %v", err)
	}

	jobID, err := retestSvc.LaunchScan(ctx, retestID, &adminID)
	if err != nil {
		t.Fatalf("launch scan: %v", err)
	}

	var targetsJSON []byte
	var linkedJobID string
	if err := h.pool.QueryRow(ctx, `
		SELECT j.targets, r.scan_job_id::text
		  FROM retest_requests r
		  JOIN scan_jobs j ON j.id = r.scan_job_id
		 WHERE r.id = $1`, retestID).Scan(&targetsJSON, &linkedJobID); err != nil {
		t.Fatalf("verify link: %v", err)
	}
	if linkedJobID != jobID.String() {
		t.Fatalf("retest_requests.scan_job_id %s != %s", linkedJobID, jobID)
	}
	if string(targetsJSON) != `["https://globex.example/admin"]` {
		t.Fatalf("retest scan must target the original endpoint, got %s", string(targetsJSON))
	}

	var status string
	_ = h.pool.QueryRow(ctx, `SELECT status FROM retest_requests WHERE id=$1`, retestID).
		Scan(&status)
	if status != "in_progress" {
		t.Fatalf("expected status=in_progress, got %s", status)
	}
}
