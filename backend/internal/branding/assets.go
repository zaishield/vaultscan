package branding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// AssetType enumerates the partner-uploadable branding artefacts.
const (
	AssetLogoDark  = "logo_dark"
	AssetLogoLight = "logo_light"
	AssetFavicon   = "favicon"
	AssetPDFCover  = "pdf_cover"
	AssetWatermark = "watermark"
)

// AllowedAssetTypes is the closed set we accept on upload.
var AllowedAssetTypes = []string{
	AssetLogoDark, AssetLogoLight, AssetFavicon, AssetPDFCover, AssetWatermark,
}

// AllowedContentTypes maps assetType → allowed MIME prefixes. Defence in
// depth: nginx already serves these as the user-supplied content-type, but
// the API refuses to ingest anything outside this set.
var AllowedContentTypes = map[string][]string{
	AssetLogoDark:  {"image/png", "image/svg+xml", "image/webp"},
	AssetLogoLight: {"image/png", "image/svg+xml", "image/webp"},
	AssetFavicon:   {"image/png", "image/x-icon", "image/svg+xml"},
	AssetPDFCover:  {"image/png", "image/jpeg", "application/pdf"},
	AssetWatermark: {"image/png", "image/svg+xml"},
}

// MaxAssetSize is the hard cap per asset (5MB). Anything bigger should be
// served from a CDN, not uploaded.
const MaxAssetSize = 5 * 1024 * 1024

// AssetService manages partner-uploaded brand assets. It piggy-backs
// on the evidence vault for storage so logos get the same AES-256-GCM
// at-rest encryption + signed-URL access controls as scanner output.
// When a CDN is configured (SetCDNConfig) the URLs returned by
// ListAssets are rewritten through the CDN — either a naive prefix
// swap or a CloudFront signed URL — so the portal hits the edge
// instead of the evidence vault on every page load.
type AssetService struct {
	pool  *pgxpool.Pool
	vault *evidence.Vault
	audit *audit.Service
	cdn   *CDNConfig
}

// NewAssetService wires the assets service.
func NewAssetService(pool *pgxpool.Pool, vault *evidence.Vault, a *audit.Service) *AssetService {
	return &AssetService{pool: pool, vault: vault, audit: a}
}

// UploadInput is one branded asset to store.
type UploadInput struct {
	PartnerID   uuid.UUID
	AssetType   string
	ContentType string
	Body        []byte
	UploadedBy  *uuid.UUID
}

// Upload validates the asset, stores it in the encrypted evidence vault,
// and upserts the partner_brand_assets row. Re-uploading the same asset
// type replaces the previous one. Bumps bundle_etag so portals know to
// re-fetch.
func (s *AssetService) Upload(ctx context.Context, in UploadInput) (uuid.UUID, error) {
	if !inSlice(AllowedAssetTypes, in.AssetType) {
		return uuid.Nil, fmt.Errorf("branding: asset_type %q not allowed", in.AssetType)
	}
	if !contentTypeAllowed(in.AssetType, in.ContentType) {
		return uuid.Nil, fmt.Errorf("branding: content-type %q not allowed for %s",
			in.ContentType, in.AssetType)
	}
	if len(in.Body) == 0 {
		return uuid.Nil, errors.New("branding: empty body")
	}
	if int64(len(in.Body)) > MaxAssetSize {
		return uuid.Nil, fmt.Errorf("branding: asset exceeds %d byte cap", MaxAssetSize)
	}

	// Resolve the partner's platform_id so the evidence vault can pick a
	// per-tenant storage prefix. We treat brand-asset storage as
	// platform-scoped, not per-customer-tenant, so use the partner's
	// platform_id as a synthetic tenant id.
	var platformID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT platform_id FROM partners WHERE id=$1`, in.PartnerID).Scan(&platformID); err != nil {
		return uuid.Nil, fmt.Errorf("branding: resolve partner: %w", err)
	}

	storageURL, err := s.vault.Put(ctx, evidence.PutInput{
		TenantID:    platformID, // platform-scoped storage prefix
		PartnerID:   in.PartnerID,
		Kind:        "brand_asset",
		ContentType: in.ContentType,
		Body:        in.Body,
		UploadedBy:  in.UploadedBy,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("branding: vault put: %w", err)
	}

	sum := sha256.Sum256(in.Body)
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO partner_brand_assets(id, partner_id, asset_type, content_type,
		    sha256, size_bytes, storage_url, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (partner_id, asset_type) DO UPDATE SET
		    content_type=EXCLUDED.content_type, sha256=EXCLUDED.sha256,
		    size_bytes=EXCLUDED.size_bytes, storage_url=EXCLUDED.storage_url,
		    uploaded_by=EXCLUDED.uploaded_by, uploaded_at=now()`,
		id, in.PartnerID, in.AssetType, in.ContentType,
		hex.EncodeToString(sum[:]), int64(len(in.Body)), storageURL, in.UploadedBy); err != nil {
		return uuid.Nil, err
	}
	// Bump branding bundle ETag so the portal short-cache invalidates.
	// Update-only: a partner without a branding row hasn't customised
	// anything yet, so there's no portal cache to invalidate. The first
	// branding write (UpdateBranding) creates the row with product_name.
	if _, err := s.pool.Exec(ctx, `
		UPDATE partner_branding
		   SET bundle_etag=$2, updated_at=now()
		 WHERE partner_id=$1`,
		in.PartnerID, newETag(in.PartnerID, time.Now())); err != nil {
		return uuid.Nil, err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: platformID, PartnerID: &in.PartnerID,
			ActorID: in.UploadedBy, Event: "brand_asset.uploaded",
			TargetType: "partner_brand_asset", TargetID: id.String(),
			Payload: map[string]any{
				"asset_type":   in.AssetType,
				"content_type": in.ContentType,
				"size_bytes":   len(in.Body),
				"sha256":       hex.EncodeToString(sum[:]),
			},
		})
	}
	return id, nil
}

// ListAssets returns every brand asset for a partner.
type Asset struct {
	ID          uuid.UUID `json:"id"`
	AssetType   string    `json:"asset_type"`
	ContentType string    `json:"content_type"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	StorageURL  string    `json:"storage_url"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

func (s *AssetService) ListAssets(ctx context.Context, partnerID uuid.UUID) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_type, content_type, sha256, size_bytes, storage_url, uploaded_at
		  FROM partner_brand_assets WHERE partner_id=$1 ORDER BY asset_type`, partnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.AssetType, &a.ContentType, &a.SHA256,
			&a.SizeBytes, &a.StorageURL, &a.UploadedAt); err != nil {
			return nil, err
		}
		// Apply the CDN rewrite if configured. CDNModeDisabled
		// (default) returns the URL unchanged so the legacy path
		// continues to work.
		a.StorageURL = s.rewriteStorageURL(a.StorageURL)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ----- Sender-domain DNS checks --------------------------------------------

// SenderDNS is the SPF/DKIM/DMARC posture for one partner-configured
// sender domain. CheckSenderDomain populates the row by resolving against
// the public DNS (no inbound exposure required).
type SenderDNS struct {
	Domain        string    `json:"domain"`
	SPFStatus     string    `json:"spf_status"`     // pass | missing | misconfigured
	SPFRecord     string    `json:"spf_record,omitempty"`
	DKIMStatus    string    `json:"dkim_status"`
	DKIMSelector  string    `json:"dkim_selector,omitempty"`
	DMARCStatus   string    `json:"dmarc_status"`
	DMARCRecord   string    `json:"dmarc_record,omitempty"`
	LastCheckedAt time.Time `json:"last_checked_at"`
}

// CheckSenderDomain resolves the domain's TXT records, classifies SPF +
// DMARC, and persists the result. DKIM requires a selector hint because
// DKIM keys live under <selector>._domainkey.<domain> — we accept the
// selector as input. Returns the populated SenderDNS row.
func (s *AssetService) CheckSenderDomain(ctx context.Context, partnerID uuid.UUID, domain, dkimSelector string) (*SenderDNS, error) {
	if domain == "" {
		return nil, errors.New("branding: domain required")
	}
	posture := &SenderDNS{Domain: domain, LastCheckedAt: time.Now()}

	resolver := &net.Resolver{PreferGo: true}
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		posture.SPFStatus = "missing"
		posture.DMARCStatus = "missing"
	} else {
		posture.SPFStatus = "missing"
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				posture.SPFRecord = t
				posture.SPFStatus = classifySPF(t)
				break
			}
		}
	}
	if dmarcTXTs, err := resolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		posture.DMARCStatus = "missing"
		for _, t := range dmarcTXTs {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				posture.DMARCRecord = t
				posture.DMARCStatus = classifyDMARC(t)
				break
			}
		}
	} else {
		posture.DMARCStatus = "missing"
	}
	if dkimSelector != "" {
		posture.DKIMSelector = dkimSelector
		if dkimTXTs, err := resolver.LookupTXT(ctx, dkimSelector+"._domainkey."+domain); err == nil {
			posture.DKIMStatus = "missing"
			for _, t := range dkimTXTs {
				if strings.Contains(strings.ToLower(t), "v=dkim1") {
					posture.DKIMStatus = "pass"
					break
				}
			}
		} else {
			posture.DKIMStatus = "missing"
		}
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO partner_sender_dns(partner_id, domain, spf_status, spf_record,
		    dkim_status, dkim_selector, dmarc_status, dmarc_record, last_checked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		ON CONFLICT (partner_id, domain) DO UPDATE SET
		    spf_status=EXCLUDED.spf_status, spf_record=EXCLUDED.spf_record,
		    dkim_status=EXCLUDED.dkim_status, dkim_selector=EXCLUDED.dkim_selector,
		    dmarc_status=EXCLUDED.dmarc_status, dmarc_record=EXCLUDED.dmarc_record,
		    last_checked_at=now()`,
		partnerID, domain, posture.SPFStatus, nullIfEmpty(posture.SPFRecord),
		posture.DKIMStatus, nullIfEmpty(posture.DKIMSelector),
		posture.DMARCStatus, nullIfEmpty(posture.DMARCRecord)); err != nil {
		return nil, err
	}
	return posture, nil
}

func classifySPF(record string) string {
	r := strings.ToLower(record)
	// minimal smell test: must end with a qualifier ~all or -all to count as configured
	if strings.HasSuffix(r, "-all") || strings.HasSuffix(r, "~all") {
		return "pass"
	}
	return "misconfigured"
}

func classifyDMARC(record string) string {
	r := strings.ToLower(record)
	if !strings.Contains(r, "p=") {
		return "misconfigured"
	}
	if strings.Contains(r, "p=quarantine") || strings.Contains(r, "p=reject") {
		return "pass"
	}
	return "monitor"
}

// ----- helpers --------------------------------------------------------------

func contentTypeAllowed(assetType, ct string) bool {
	allowed, ok := AllowedContentTypes[assetType]
	if !ok {
		return false
	}
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	for _, prefix := range allowed {
		if ct == prefix {
			return true
		}
	}
	return false
}

func inSlice(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func newETag(partnerID uuid.UUID, t time.Time) string {
	h := sha256.New()
	h.Write(partnerID[:])
	h.Write([]byte(t.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

