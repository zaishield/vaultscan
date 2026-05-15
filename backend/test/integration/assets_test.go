//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

// TestAssets_CSVImportAndTypes asserts:
//   * All 14 §16 asset types can be created.
//   * CSV import is idempotent (re-import bumps last_seen, doesn't dupe).
//   * Cross-tenant queries return zero rows.
func TestAssets_CSVImportAndTypes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantA, engA := h.makeTenant(t, "assets-tenant-a")
	tenantB, _ := h.makeTenant(t, "assets-tenant-b")

	// Insert one asset of every supported type.
	for _, kind := range models.AssetTypes {
		_, err := h.assets.Create(ctx, assets.CreateInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantA, EngagementID: &engA,
			AssetType: kind, Value: kind + ".example.com",
			Plane: "external", Criticality: "medium",
		})
		if err != nil {
			t.Fatalf("create %s: %v", kind, err)
		}
	}

	listA, err := h.assets.List(ctx, assets.ListFilter{TenantID: tenantA, Limit: 100})
	if err != nil {
		t.Fatalf("list a: %v", err)
	}
	if len(listA) != len(models.AssetTypes) {
		t.Fatalf("expected %d assets for tenant A, got %d", len(models.AssetTypes), len(listA))
	}

	// CSV import is idempotent.
	csv := strings.NewReader(`asset_type,value,plane,criticality
domain,csv.example.com,external,high
ip,203.0.113.7,external,medium
`)
	admin := adminID
	created, _, err := h.assets.ImportCSV(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantA, EngagementID: &engA,
		CreatedBy: &admin,
	}, csv)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if created != 2 {
		t.Fatalf("expected 2 rows created, got %d", created)
	}

	csv2 := strings.NewReader(`asset_type,value,plane,criticality
domain,csv.example.com,external,high
ip,203.0.113.7,external,medium
`)
	if _, _, err := h.assets.ImportCSV(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantA, EngagementID: &engA,
	}, csv2); err != nil {
		t.Fatalf("second import: %v", err)
	}

	// Still the same row count for tenant A.
	listAAfter, _ := h.assets.List(ctx, assets.ListFilter{TenantID: tenantA, Limit: 100})
	if len(listAAfter) != len(models.AssetTypes)+2 {
		t.Fatalf("after dedupe expected %d, got %d", len(models.AssetTypes)+2, len(listAAfter))
	}

	// Cross-tenant isolation: tenant B sees zero assets.
	listB, err := h.assets.List(ctx, assets.ListFilter{TenantID: tenantB, Limit: 100})
	if err != nil {
		t.Fatalf("list b: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("tenant B should have 0 assets, got %d (isolation breach!)", len(listB))
	}
}

