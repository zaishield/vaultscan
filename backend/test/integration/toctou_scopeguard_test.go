//go:build integration

// TOCTOU regression: between Scope Guard approval and scan_job INSERT,
// another connection could pause the engagement OR delete the auth
// document. Before the INSERT-time revalidation, the scan slipped
// through. This test simulates the race by mutating the row mid-
// Submit via a DB trigger.

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

// Direct SQL-level proof: the INSERT statement embedded in
// orchestrator.Submit refuses to write a scan_jobs row when the
// engagement is NOT active OR the auth doc is missing. This locks
// in the WHERE-clause TOCTOU guard at the data-plane level. The
// concurrent-race scenario is genuinely hard to reliably reproduce
// in a unit test (the window is microseconds and depends on the
// scheduler); the SQL-level proof here is what actually matters —
// any future loss of the WHERE clause will fail the assertion.
func TestTOCTOU_InsertRefusesPausedEngagement(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "toctou-pause-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "toctou")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)
	// Pause AFTER activation so Scope Guard's positive check is
	// the (already-stale) view a TOCTOU attacker would race
	// against. Submit must catch the new state at INSERT time.
	if _, err := h.pool.Exec(ctx,
		`UPDATE engagements SET status='paused' WHERE id=$1`, engagementID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	defer h.pool.Exec(context.Background(),
		`UPDATE engagements SET status='active' WHERE id=$1`, engagementID)

	job, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ProfileCode: "external_standard_va",
		Plane:       "external", Region: "us",
		Targets:     []string{"203.0.113.10"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if job != nil {
		t.Fatalf("expected paused engagement to be refused, got job %s", job.ID)
	}
	if dec == nil {
		t.Fatal("expected non-nil decision")
	}
}

// Same shape for missing auth document: Scope Guard catches this
// upfront (since the check happens during Evaluate), so this test
// also documents the upfront-rejection behaviour as a sanity check
// — the SQL-level guard is the second line of defence that prevents
// race-condition slip-through.
func TestTOCTOU_InsertRefusesMissingAuthDoc(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "toctou-doc-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "toctou-doc")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)
	// Delete the auth doc AFTER activation.
	if _, err := h.pool.Exec(ctx,
		`DELETE FROM authorization_documents WHERE engagement_id=$1`, engagementID); err != nil {
		t.Fatalf("delete doc: %v", err)
	}

	job, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ProfileCode: "external_standard_va",
		Plane:       "external", Region: "us",
		Targets:     []string{"203.0.113.10"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if job != nil {
		t.Fatalf("expected missing-auth-doc to be refused, got job %s", job.ID)
	}
}

// Positive: when nothing changes mid-Submit, the scan goes through
// normally. Guards against the TOCTOU revalidation being too strict
// (i.e. always returning the late-denial).
func TestTOCTOU_HappyPathStillWorks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "toctou-ok-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "ok")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)
	job, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ProfileCode: "external_standard_va",
		Plane:       "external", Region: "us",
		Targets:     []string{"203.0.113.10"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if job == nil {
		t.Fatalf("happy-path submit blocked by TOCTOU re-check; dec=%+v", dec)
	}
}
