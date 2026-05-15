//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/guardrails"
)

// TestHS05_MaintenanceMode: maintenance blocks writes unless the actor
// carries the override permission.
func TestHS05_MaintenanceMode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := guardrails.New(h.pool, h.audit)

	// Baseline: writes allowed when maintenance off.
	allowed, _, err := svc.IsWriteAllowed(ctx, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("baseline: writes must be allowed")
	}

	if err := svc.SetMaintenance(ctx, &adminID, true, "DR drill", nil, net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("enable: %v", err)
	}
	t.Cleanup(func() {
		_ = svc.SetMaintenance(context.Background(), &adminID, false, "", nil, nil)
	})

	allowed, st, _ := svc.IsWriteAllowed(ctx, map[string]bool{})
	if allowed {
		t.Fatal("maintenance on: writes must be blocked")
	}
	if !st.Enabled || st.Reason != "DR drill" {
		t.Fatalf("unexpected state: %+v", st)
	}

	allowed, _, _ = svc.IsWriteAllowed(ctx, map[string]bool{"maintenance.override": true})
	if !allowed {
		t.Fatal("override permission must bypass maintenance gate")
	}

	if err := svc.SetMaintenance(ctx, &adminID, true, "", nil, nil); err == nil {
		t.Fatal("enabling maintenance without a reason must be rejected")
	}
}

// TestHS05_BreakGlassLifecycle: issue → redeem → re-redeem fails.
func TestHS05_BreakGlassLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := guardrails.New(h.pool, h.audit)

	tok, raw, err := svc.IssueBreakGlass(ctx, adminID,
		"reports.export_legal_bundle",
		"compliance auditor request 2026-Q2",
		15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok.ID == uuid.Nil || raw == "" {
		t.Fatal("issuer returned empty token")
	}

	perm, issuer, err := svc.RedeemBreakGlass(ctx, raw, &adminID, net.ParseIP("10.1.0.5"))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if perm != "reports.export_legal_bundle" || issuer != adminID {
		t.Fatalf("unexpected redeem result: perm=%s issuer=%s", perm, issuer)
	}

	// Second redemption fails.
	if _, _, err := svc.RedeemBreakGlass(ctx, raw, &adminID, nil); err == nil {
		t.Fatal("second redemption must fail (one-time tokens)")
	}

	// Bad raw fails too.
	if _, _, err := svc.RedeemBreakGlass(ctx, "garbage", &adminID, nil); err == nil {
		t.Fatal("garbage token must fail")
	}

	// TTL guard.
	if _, _, err := svc.IssueBreakGlass(ctx, adminID, "x", "y", 5*time.Hour); err == nil {
		t.Fatal("TTL > 4h must be rejected")
	}
}

// TestHS05_PolicyEvaluate: seeded never_allow rule fires on out-of-scope;
// seeded always_require fires when authorization_documents is missing.
func TestHS05_PolicyEvaluate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := guardrails.New(h.pool, h.audit)

	// never_allow: out-of-scope = true. Include an actor_id so the
	// "anonymous scan" rule (also a never_allow) doesn't match first.
	d, err := svc.Evaluate(ctx, "scan", map[string]any{
		"actor_id":     "u1",
		"out_of_scope": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatalf("out-of-scope scan must be denied: %+v", d)
	}
	if d.Rule != "never_allow_out_of_scope" {
		t.Fatalf("expected never_allow_out_of_scope rule, got %s", d.Rule)
	}

	// never_allow: anonymous (actor_id null).
	d, _ = svc.Evaluate(ctx, "scan", map[string]any{
		"actor_id": nil, "authorization_documents": "yes", "signed_manifest": "y",
	})
	if d.Allowed {
		t.Fatalf("anonymous scan must be denied: %+v", d)
	}

	// always_require: missing authorization_documents → denied.
	d, _ = svc.Evaluate(ctx, "scan", map[string]any{
		"actor_id": "u1", "signed_manifest": "y",
	})
	if d.Allowed {
		t.Fatalf("missing authorization_documents must be denied: %+v", d)
	}

	// Fully-specified valid scan: allowed.
	d, _ = svc.Evaluate(ctx, "scan", map[string]any{
		"actor_id":                  "u1",
		"authorization_documents":   "yes",
		"signed_manifest":           "yes",
		"out_of_scope":              false,
		"engagement_expired":        false,
	})
	if !d.Allowed {
		t.Fatalf("compliant scan must be allowed, got: %+v", d)
	}
}
