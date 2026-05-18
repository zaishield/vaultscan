//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

// TestTenants_SetResidencyAuditTrail asserts the data_region pin
// writes the right row to tenant_residency_history + emits a
// tenant.residency_set audit event.
func TestTenants_SetResidencyAuditTrail(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, _ := h.makeTenant(t, "residency-audit")

	// Set EU pin.
	if err := h.tenants.SetResidency(ctx, tenantID, "eu", &adminID,
		"MSA §4.2 — EU data residency"); err != nil {
		t.Fatalf("SetResidency eu: %v", err)
	}

	// Verify the column.
	var region *string
	if err := h.pool.QueryRow(ctx,
		`SELECT data_region FROM tenants WHERE id = $1`, tenantID).
		Scan(&region); err != nil {
		t.Fatalf("read data_region: %v", err)
	}
	if region == nil || *region != "eu" {
		t.Fatalf("region != eu, got %v", region)
	}

	// History row recorded.
	var fromR, toR *string
	if err := h.pool.QueryRow(ctx, `
		SELECT from_region, to_region FROM tenant_residency_history
		 WHERE tenant_id = $1 ORDER BY changed_at DESC LIMIT 1`, tenantID).
		Scan(&fromR, &toR); err != nil {
		t.Fatalf("read residency_history: %v", err)
	}
	if toR == nil || *toR != "eu" {
		t.Fatalf("history to_region != eu, got %v", toR)
	}
	if fromR != nil && *fromR != "" {
		t.Fatalf("first history entry: from_region should be NULL, got %v", *fromR)
	}

	// Audit event recorded.
	var event string
	if err := h.pool.QueryRow(ctx, `
		SELECT event FROM audit_logs
		 WHERE target_id = $1::text AND event = 'tenant.residency_set'
		 ORDER BY id DESC LIMIT 1`, tenantID).Scan(&event); err != nil {
		t.Fatalf("read audit_logs: %v", err)
	}
}

// TestTenants_CheckResidencyEnforcement verifies the cross-region
// gate: a tenant pinned to "eu" rejected from a "us" pod.
func TestTenants_CheckResidencyEnforcement(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, _ := h.makeTenant(t, "residency-enforce")

	// Unpinned tenant: any podRegion is fine.
	if err := h.tenants.CheckResidency(ctx, tenantID, "us"); err != nil {
		t.Errorf("unpinned: should pass, got %v", err)
	}

	// Empty podRegion = no enforcement.
	if err := h.tenants.SetResidency(ctx, tenantID, "eu", &adminID, "test"); err != nil {
		t.Fatalf("SetResidency: %v", err)
	}
	if err := h.tenants.CheckResidency(ctx, tenantID, ""); err != nil {
		t.Errorf("empty podRegion: should pass, got %v", err)
	}

	// Pinned to eu, pod in us → violation.
	err := h.tenants.CheckResidency(ctx, tenantID, "us")
	if !errors.Is(err, tenants.ErrResidencyViolation) {
		t.Errorf("eu tenant on us pod: want ErrResidencyViolation, got %v", err)
	}

	// Same region passes.
	if err := h.tenants.CheckResidency(ctx, tenantID, "eu"); err != nil {
		t.Errorf("eu tenant on eu pod: should pass, got %v", err)
	}

	// Clear and confirm.
	if err := h.tenants.SetResidency(ctx, tenantID, "", &adminID, "clearing"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := h.tenants.CheckResidency(ctx, tenantID, "us"); err != nil {
		t.Errorf("after clear: should pass, got %v", err)
	}
}
