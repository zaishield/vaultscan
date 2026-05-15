//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
)

// TestVS03_PauseBlocksScans: a paused engagement causes Scope Guard to
// reject every scan with blocked_expired_engagement.
func TestVS03_PauseBlocksScans(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "vs03-pause")

	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"domain", "globex.example", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	d, err := h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "globex.example", Plane: "external", RequestedBy: &adminID,
	})
	if err != nil || d.Code != scopeguard.DecisionApproved {
		t.Fatalf("baseline must be approved, got %s (%s)", d.Code, d.Reason)
	}

	if err := h.engagements.Pause(ctx, engagementID, &adminID, "customer holiday"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	d, _ = h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "globex.example", Plane: "external", RequestedBy: &adminID,
	})
	if d.Code != scopeguard.DecisionBlockedExpired {
		t.Fatalf("paused engagement must block scans, got %s (%s)", d.Code, d.Reason)
	}

	if err := h.engagements.Resume(ctx, engagementID, &adminID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	d, _ = h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "globex.example", Plane: "external", RequestedBy: &adminID,
	})
	if d.Code != scopeguard.DecisionApproved {
		t.Fatalf("after resume must approve, got %s (%s)", d.Code, d.Reason)
	}
}

// TestVS03_IntensityCap: an engagement with max_intensity='light' must
// refuse the external_standard_va profile (standard > light).
func TestVS03_IntensityCap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "vs03-intensity")

	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"domain", "globex.example", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	// Force intensity = light.
	if _, err := h.pool.Exec(ctx,
		`UPDATE engagements SET intensity='light' WHERE id=$1`, engagementID); err != nil {
		t.Fatalf("set light: %v", err)
	}
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	d, err := h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", // standard
		TargetType:  "domain", TargetValue: "globex.example",
		Plane: "external", RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Code != scopeguard.DecisionBlockedOutOfScope {
		t.Fatalf("standard profile under light engagement must block, got %s (%s)", d.Code, d.Reason)
	}

	// Light profile should pass.
	d, _ = h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_discovery", // light
		TargetType:  "domain", TargetValue: "globex.example",
		Plane: "external", RequestedBy: &adminID,
	})
	if d.Code != scopeguard.DecisionApproved {
		t.Fatalf("light profile under light engagement must approve, got %s (%s)", d.Code, d.Reason)
	}
}

// TestVS03_ScopeCSVImport: bulk-loads scope targets from a CSV.
func TestVS03_ScopeCSVImport(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, engagementID := h.makeTenant(t, "vs03-csv")

	csv := strings.NewReader(`target_type,target_value,plane,notes
domain,one.example,external,first
domain,two.example,external,second
cidr,10.0.0.0/16,internal,private
`)
	added, err := h.engagements.ImportScopeCSV(ctx, &adminID, engagementID, csv)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if added != 3 {
		t.Fatalf("expected 3 rows imported, got %d", added)
	}
	rows, err := h.engagements.ListScope(ctx, engagementID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 scope rows, got %d", len(rows))
	}
}

// TestVS03_PerEngagementRateLimit: setting an engagement-level cap of 2
// blocks the third scan submission.
func TestVS03_PerEngagementRateLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "vs03-engratelim")
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"domain", "globex.example", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	if err := h.engagements.SetRateLimit(ctx, engagementID, &adminID, 2); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}

	// Insert two scan_jobs directly to simulate prior load.
	for i := 0; i < 2; i++ {
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO scan_jobs(platform_id, partner_id, tenant_id, engagement_id,
			    profile_id, plane, status, target_summary, targets, job_signature, signing_key_id)
			VALUES ($1, $2, $3, $4,
			    (SELECT id FROM scan_profiles WHERE code='external_standard_va'),
			    'external', 'dispatched', 'pre-load',
			    '["x.example"]'::jsonb, '', '')`,
			platformID, directID, tenantID, engagementID); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	d, err := h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "globex.example", Plane: "external", RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Code != scopeguard.DecisionBlockedRateLimit {
		t.Fatalf("expected blocked_rate_limit at 2/2, got %s (%s)", d.Code, d.Reason)
	}
}
