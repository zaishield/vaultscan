//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/branding"
)

// TestVS02_BrandAssetUploadAndETag: upload a logo, the bundle_etag gets
// stamped, re-upload replaces the row, the etag changes.
func TestVS02_BrandAssetUploadAndETag(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := branding.NewAssetService(h.pool, h.vault, h.audit)

	body := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a} // PNG magic bytes
	id, err := svc.Upload(ctx, branding.UploadInput{
		PartnerID: directID, AssetType: branding.AssetLogoDark,
		ContentType: "image/png", Body: body, UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if id == uuidNil() {
		t.Fatalf("returned nil id")
	}

	var etag1 string
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(bundle_etag,'') FROM partner_branding WHERE partner_id=$1`,
		directID).Scan(&etag1)
	if etag1 == "" {
		t.Fatalf("upload should stamp bundle_etag")
	}

	// Re-upload (same asset_type) — must replace row (UNIQUE constraint)
	// and produce a NEW etag.
	_, err = svc.Upload(ctx, branding.UploadInput{
		PartnerID: directID, AssetType: branding.AssetLogoDark,
		ContentType: "image/png", Body: append(body, 0x00, 0x01), UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("re-upload: %v", err)
	}
	var etag2 string
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(bundle_etag,'') FROM partner_branding WHERE partner_id=$1`,
		directID).Scan(&etag2)
	if etag2 == etag1 {
		t.Fatalf("re-upload should bump etag (%s == %s)", etag1, etag2)
	}

	// Only one row per (partner, asset_type) — confirms idempotent upsert.
	var rows int
	_ = h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM partner_brand_assets
		 WHERE partner_id=$1 AND asset_type=$2`,
		directID, branding.AssetLogoDark).Scan(&rows)
	if rows != 1 {
		t.Fatalf("expected exactly one logo_dark row, got %d", rows)
	}

	// List returns it.
	list, err := svc.ListAssets(ctx, directID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].AssetType != branding.AssetLogoDark {
		t.Fatalf("expected one logo_dark in list, got %+v", list)
	}
}

// TestVS02_AssetTypeContentTypeGuards: refuses unknown asset types and
// disallowed content types.
func TestVS02_AssetTypeContentTypeGuards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := branding.NewAssetService(h.pool, h.vault, h.audit)

	if _, err := svc.Upload(ctx, branding.UploadInput{
		PartnerID: directID, AssetType: "background_video",
		ContentType: "video/mp4", Body: []byte{0x00}, UploadedBy: &adminID,
	}); err == nil {
		t.Fatalf("upload of unknown asset_type should fail")
	}

	if _, err := svc.Upload(ctx, branding.UploadInput{
		PartnerID: directID, AssetType: branding.AssetLogoDark,
		ContentType: "text/html", // not allowed for logos
		Body: []byte("<html></html>"), UploadedBy: &adminID,
	}); err == nil {
		t.Fatalf("upload with disallowed content-type should fail")
	}

	if _, err := svc.Upload(ctx, branding.UploadInput{
		PartnerID: directID, AssetType: branding.AssetLogoDark,
		ContentType: "image/png", Body: nil, UploadedBy: &adminID,
	}); err == nil {
		t.Fatalf("empty body upload should fail")
	}
}

// TestVS02_DNSCheck_MissingDomain returns missing for SPF + DMARC when the
// domain doesn't resolve. We can't reach real DNS from the sandbox; the
// missing-state path is the deterministic one to assert.
func TestVS02_DNSCheck_MissingDomain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := branding.NewAssetService(h.pool, h.vault, h.audit)

	// Use a TLD that definitely won't resolve (.invalid per RFC 6761).
	posture, err := svc.CheckSenderDomain(ctx, directID, "no-such-host.invalid", "default")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if posture.SPFStatus != "missing" {
		t.Fatalf("expected SPF missing for unresolvable domain, got %s", posture.SPFStatus)
	}
	if posture.DMARCStatus != "missing" {
		t.Fatalf("expected DMARC missing, got %s", posture.DMARCStatus)
	}
	if posture.DKIMStatus != "missing" {
		t.Fatalf("expected DKIM missing, got %s", posture.DKIMStatus)
	}
	// Row persisted.
	var saved int
	_ = h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM partner_sender_dns
		 WHERE partner_id=$1 AND domain=$2`, directID, "no-such-host.invalid").Scan(&saved)
	if saved != 1 {
		t.Fatalf("expected one partner_sender_dns row, got %d", saved)
	}
}

func uuidNil() [16]byte { return [16]byte{} }
