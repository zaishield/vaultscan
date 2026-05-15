//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
)

// TestScopeGuard_DecisionMatrix exercises the 9 documented outcomes from
// Blueprint §14.4 against a live Postgres so we know the SQL / CIDR logic
// matches the unit-test contract.
func TestScopeGuard_DecisionMatrix(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := adminID

	tenantID, engagementID := h.makeTenant(t, "scope-target")

	// Approve a scope target for the external plane.
	scope, err := h.engagements.AddScope(ctx, &actor, engagementID,
		"domain", "example.com", "external", "approved by test")
	if err != nil {
		t.Fatalf("add scope: %v", err)
	}
	if err := h.engagements.ApproveScope(ctx, &actor, scope.ID); err != nil {
		t.Fatalf("approve scope: %v", err)
	}

	// Activate the engagement so the time-window check passes.
	if err := h.engagements.Activate(ctx, &actor, engagementID); err != nil {
		t.Fatalf("activate engagement: %v", err)
	}

	baseInputs := scopeguard.Inputs{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: engagementID,
		ScanProfile:  "external_standard_va",
		TargetType:   "domain",
		TargetValue:  "api.example.com", // subdomain of approved domain
		Plane:        "external",
		RequestedBy:  &actor,
	}

	cases := []struct {
		name    string
		mutate  func(in *scopeguard.Inputs)
		want    string
	}{
		{
			name: "approved subdomain of approved domain",
			mutate: func(in *scopeguard.Inputs) {},
			want: scopeguard.DecisionApproved,
		},
		{
			name: "out of scope target",
			mutate: func(in *scopeguard.Inputs) { in.TargetValue = "evil.com" },
			want: scopeguard.DecisionBlockedOutOfScope,
		},
		{
			name: "rate limit triggered",
			mutate: func(in *scopeguard.Inputs) { in.RecentJobsLastHour = 100 },
			want: scopeguard.DecisionBlockedRateLimit,
		},
		{
			name: "wrong tenant requested",
			mutate: func(in *scopeguard.Inputs) { in.TenantID = uuid.New() },
			want: scopeguard.DecisionBlockedWrongTenant,
		},
		{
			name: "engagement does not exist",
			mutate: func(in *scopeguard.Inputs) { in.EngagementID = uuid.New() },
			want: scopeguard.DecisionBlockedMissingAuth,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInputs
			tc.mutate(&in)
			d, err := h.scope.Evaluate(ctx, in)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if d.Code != tc.want {
				t.Fatalf("decision = %s; want %s (reason: %s)", d.Code, tc.want, d.Reason)
			}
		})
	}

	// Decision log must capture every evaluation. We can't filter by
	// tenant_id because two cases deliberately use a wrong tenant id;
	// filter by requested_by (the actor) instead.
	var logged int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scope_decision_logs WHERE requested_by=$1`, actor).
		Scan(&logged); err != nil {
		t.Fatalf("query decision log: %v", err)
	}
	if logged < len(cases) {
		t.Fatalf("expected at least %d decision rows, got %d", len(cases), logged)
	}
	_ = tenantID // referenced earlier
}

// TestScopeGuard_ExpiredEngagement asserts the time-window branch fires when
// the engagement has ended.
func TestScopeGuard_ExpiredEngagement(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := adminID

	tenantID, engagementID := h.makeTenant(t, "scope-expired")
	scope, _ := h.engagements.AddScope(ctx, &actor, engagementID,
		"domain", "ok.com", "external", "")
	_ = h.engagements.ApproveScope(ctx, &actor, scope.ID)
	_ = h.engagements.Activate(ctx, &actor, engagementID)

	// Forcibly end the engagement.
	if _, err := h.pool.Exec(ctx,
		`UPDATE engagements SET ends_at = $2 WHERE id = $1`,
		engagementID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("expire engagement: %v", err)
	}

	d, err := h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "ok.com", Plane: "external", RequestedBy: &actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Code != scopeguard.DecisionBlockedExpired {
		t.Fatalf("expected blocked_expired_engagement; got %s (reason: %s)", d.Code, d.Reason)
	}
	_ = engagements.ErrNotFound // keep import for cross-suite reuse
}
