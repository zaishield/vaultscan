// e2e_workflows_test.go — F-006 closure (external readiness audit).
//
// The external audit captured only /healthz, /readyz, and a missing-
// route negative as "blackbox" coverage and flagged E2E coverage as
// shallow. This file drives the full tenant → engagement → asset →
// finding → evidence → audit-chain loop using the same service-layer
// types every API handler routes through, plus a cross-tenant
// isolation test.
//
// Service-layer over HTTP keeps the test surface narrow; the HTTP
// path stays covered by the blackbox harness under
// backend/test/blackbox/ (added by this commit).

//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

// TestE2E_FullScanLifecycle drives the complete external-scan
// workflow end-to-end through the service layer: tenant + engagement
// → asset → finding ingestion (with dedup proof) → evidence upload
// → integrity verification → audit chain verification.
func TestE2E_FullScanLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID, engID := h.makeTenant(t, "e2e-tenant")
	if tenantID == uuid.Nil || engID == uuid.Nil {
		t.Fatal("makeTenant returned zero IDs")
	}

	asset, err := h.assets.Create(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: &engID,
		AssetType: "ip", Name: "audit-asset-1", Value: "10.20.30.40",
		Plane: "external", Criticality: "medium",
	})
	if err != nil {
		t.Fatalf("assets.Create: %v", err)
	}
	if asset.ID == uuid.Nil {
		t.Fatal("asset id empty")
	}

	in := findings.IngestInput{
		PlatformID:       platformID,
		PartnerID:        directID,
		TenantID:         tenantID,
		EngagementID:     engID,
		AssetID:          &asset.ID,
		Title:            "audit-e2e-finding",
		Description:      "Synthetic finding created by the E2E test.",
		Severity:         "high",
		Scanner:          "audit-suite",
		ScanType:         "e2e",
		AffectedEndpoint: "10.20.30.40",
		Port:             443,
		Protocol:         "tcp",
	}
	f1, isNew, err := h.findings.Upsert(ctx, in)
	if err != nil || !isNew || f1 == nil {
		t.Fatalf("first Upsert: f=%v isNew=%v err=%v", f1, isNew, err)
	}
	f2, isNew2, err := h.findings.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if isNew2 {
		t.Errorf("expected second Upsert to dedup (isNew=false), got isNew=true")
	}
	if f1.ID != f2.ID {
		t.Errorf("dedup did not preserve id: %s vs %s", f1.ID, f2.ID)
	}

	body := []byte("E2E synthetic evidence payload — host: 10.20.30.40")
	ev, err := h.vault.Record(ctx, evidence.PutInput{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: &engID,
		Kind:         "raw_output",
		ContentType:  "text/plain",
		Body:         body,
	})
	if err != nil || ev == nil {
		t.Fatalf("vault.Record: ev=%v err=%v", ev, err)
	}
	if ev.SizeBytes != int64(len(body)) {
		t.Errorf("evidence size mismatch: stored=%d input=%d",
			ev.SizeBytes, len(body))
	}

	ok, err := h.vault.VerifyIntegrity(ctx, ev.ID)
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	if !ok {
		t.Fatal("integrity check failed for freshly-recorded evidence")
	}

	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	}
	if res.FirstBadID != 0 {
		t.Errorf("audit chain broken: first_bad=%d total=%d",
			res.FirstBadID, res.Total)
	}
}

// TestE2E_CrossTenantIsolation: two tenants' findings never bleed
// across the listing API. Catches a regression where the tenant
// filter is dropped from a service-layer SELECT.
func TestE2E_CrossTenantIsolation(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tenantA, engA := h.makeTenant(t, "e2e-iso-a")
	tenantB, engB := h.makeTenant(t, "e2e-iso-b")

	insertFinding := func(tenant, eng uuid.UUID, title string) uuid.UUID {
		f, _, err := h.findings.Upsert(ctx, findings.IngestInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenant, EngagementID: eng,
			Title: title, Severity: "low", Scanner: "iso-test",
			ScanType: "e2e", AffectedEndpoint: "10.0.0.1",
		})
		if err != nil {
			t.Fatalf("Upsert %s: %v", title, err)
		}
		return f.ID
	}
	idA := insertFinding(tenantA, engA, "iso-A-finding")
	idB := insertFinding(tenantB, engB, "iso-B-finding")

	listA, err := h.findings.List(ctx, findings.ListFilter{TenantID: tenantA, Limit: 1000})
	if err != nil {
		t.Fatalf("List tenantA: %v", err)
	}
	listB, err := h.findings.List(ctx, findings.ListFilter{TenantID: tenantB, Limit: 1000})
	if err != nil {
		t.Fatalf("List tenantB: %v", err)
	}
	contains := func(rows []models.Finding, id uuid.UUID) bool {
		for _, r := range rows {
			if r.ID == id {
				return true
			}
		}
		return false
	}
	if !contains(listA, idA) {
		t.Errorf("tenantA list missing its own finding %s", idA)
	}
	if contains(listA, idB) {
		t.Errorf("tenantA list LEAKED tenantB finding %s — RLS broken", idB)
	}
	if !contains(listB, idB) {
		t.Errorf("tenantB list missing its own finding %s", idB)
	}
	if contains(listB, idA) {
		t.Errorf("tenantB list LEAKED tenantA finding %s — RLS broken", idA)
	}
}
