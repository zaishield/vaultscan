// Package branding resolves a request domain to the partner branding payload
// the portal renders on first paint (Blueprint §8.5).
package branding

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

type Service struct {
	pool          *pgxpool.Pool
	audit         *audit.Service
	defaultSlug   string
}

func New(pool *pgxpool.Pool, a *audit.Service, defaultSlug string) *Service {
	return &Service{pool: pool, audit: a, defaultSlug: defaultSlug}
}

// ResolveByDomain returns branding + flags + support for a host header. If the
// domain is not registered, it falls back to the configured default partner so
// the portal always renders something.
func (s *Service) ResolveByDomain(ctx context.Context, domain string) (*Bundle, error) {
	var partnerID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT pd.partner_id
		  FROM partner_domains pd
		 WHERE pd.domain = $1
		 LIMIT 1`, domain).Scan(&partnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = s.pool.QueryRow(ctx,
			`SELECT id FROM partners WHERE slug=$1`, s.defaultSlug).Scan(&partnerID)
	}
	if err != nil {
		return nil, fmt.Errorf("branding: resolve %q: %w", domain, err)
	}
	return s.LoadBundle(ctx, partnerID)
}

type Bundle struct {
	Partner       models.Partner          `json:"partner"`
	Branding      models.PartnerBranding  `json:"branding"`
	FeatureFlags  map[string]bool         `json:"feature_flags"`
	Support       Support                 `json:"support"`
}

type Support struct {
	URL    string `json:"url"`
	Email  string `json:"email"`
	Phone  string `json:"phone"`
	SLAMin int    `json:"sla_response_minutes"`
}

func (s *Service) LoadBundle(ctx context.Context, partnerID uuid.UUID) (*Bundle, error) {
	b := &Bundle{FeatureFlags: map[string]bool{}}
	err := s.pool.QueryRow(ctx, `
		SELECT p.id, p.platform_id, p.parent_id, t.code, p.name, p.slug, p.status, p.created_at
		  FROM partners p JOIN partner_types t ON t.id = p.type_id
		 WHERE p.id=$1`, partnerID).
		Scan(&b.Partner.ID, &b.Partner.PlatformID, &b.Partner.ParentID, &b.Partner.TypeCode,
			&b.Partner.Name, &b.Partner.Slug, &b.Partner.Status, &b.Partner.CreatedAt)
	if err != nil {
		return nil, err
	}
	err = s.pool.QueryRow(ctx, `
		SELECT partner_id, COALESCE(product_name,''), COALESCE(logo_url,''),
		       COALESCE(favicon_url,''), primary_color, secondary_color,
		       COALESCE(accent_color,''), COALESCE(legal_footer,''),
		       COALESCE(terms_of_service,''), COALESCE(privacy_policy,''),
		       COALESCE(support_email,''), COALESCE(support_phone,''),
		       COALESCE(sender_email,''), COALESCE(sender_name,''),
		       COALESCE(pdf_cover_url,''), COALESCE(watermark_text,''),
		       COALESCE(confidentiality_tag,'')
		  FROM partner_branding WHERE partner_id=$1`, partnerID).
		Scan(&b.Branding.PartnerID, &b.Branding.ProductName, &b.Branding.LogoURL,
			&b.Branding.FaviconURL, &b.Branding.PrimaryColor, &b.Branding.SecondaryColor,
			&b.Branding.AccentColor, &b.Branding.LegalFooter, &b.Branding.TermsOfService,
			&b.Branding.PrivacyPolicy, &b.Branding.SupportEmail, &b.Branding.SupportPhone,
			&b.Branding.SenderEmail, &b.Branding.SenderName, &b.Branding.PdfCoverURL,
			&b.Branding.WatermarkText, &b.Branding.ConfidentialityTag)
	if errors.Is(err, pgx.ErrNoRows) {
		b.Branding.PartnerID = partnerID
		b.Branding.ProductName = b.Partner.Name
		b.Branding.PrimaryColor = "#0F172A"
		b.Branding.SecondaryColor = "#38BDF8"
	} else if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT flag, enabled FROM partner_feature_flags WHERE partner_id=$1`, partnerID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var flag string
			var enabled bool
			if err := rows.Scan(&flag, &enabled); err == nil {
				b.FeatureFlags[flag] = enabled
			}
		}
	}
	_ = s.pool.QueryRow(ctx, `
		SELECT COALESCE(support_url,''), COALESCE(support_email,''),
		       COALESCE(support_phone,''), COALESCE(sla_response_minutes, 60)
		  FROM partner_support_settings WHERE partner_id=$1`, partnerID).
		Scan(&b.Support.URL, &b.Support.Email, &b.Support.Phone, &b.Support.SLAMin)
	return b, nil
}

type UpdateBrandingInput struct {
	ProductName, LogoURL, FaviconURL                string
	PrimaryColor, SecondaryColor, AccentColor       string
	LegalFooter, TermsOfService, PrivacyPolicy      string
	SupportEmail, SupportPhone                      string
	SenderEmail, SenderName                         string
	PdfCoverURL, WatermarkText, ConfidentialityTag  string
}

func (s *Service) UpdateBranding(ctx context.Context, actor *uuid.UUID, partnerID uuid.UUID, in UpdateBrandingInput) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_branding(partner_id, product_name, logo_url, favicon_url,
		    primary_color, secondary_color, accent_color, legal_footer, terms_of_service,
		    privacy_policy, support_email, support_phone, sender_email, sender_name,
		    pdf_cover_url, watermark_text, confidentiality_tag, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17, now(), $18)
		ON CONFLICT (partner_id) DO UPDATE SET
		    product_name = EXCLUDED.product_name,
		    logo_url     = EXCLUDED.logo_url,
		    favicon_url  = EXCLUDED.favicon_url,
		    primary_color   = EXCLUDED.primary_color,
		    secondary_color = EXCLUDED.secondary_color,
		    accent_color    = EXCLUDED.accent_color,
		    legal_footer    = EXCLUDED.legal_footer,
		    terms_of_service= EXCLUDED.terms_of_service,
		    privacy_policy  = EXCLUDED.privacy_policy,
		    support_email   = EXCLUDED.support_email,
		    support_phone   = EXCLUDED.support_phone,
		    sender_email    = EXCLUDED.sender_email,
		    sender_name     = EXCLUDED.sender_name,
		    pdf_cover_url   = EXCLUDED.pdf_cover_url,
		    watermark_text  = EXCLUDED.watermark_text,
		    confidentiality_tag = EXCLUDED.confidentiality_tag,
		    updated_at      = now(),
		    updated_by      = $18`,
		partnerID, in.ProductName, in.LogoURL, in.FaviconURL,
		in.PrimaryColor, in.SecondaryColor, in.AccentColor,
		in.LegalFooter, in.TermsOfService, in.PrivacyPolicy,
		in.SupportEmail, in.SupportPhone, in.SenderEmail, in.SenderName,
		in.PdfCoverURL, in.WatermarkText, in.ConfidentialityTag,
		actor)
	if err != nil {
		return err
	}
	var platformID uuid.UUID
	_ = s.pool.QueryRow(ctx, `SELECT platform_id FROM partners WHERE id=$1`, partnerID).Scan(&platformID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &partnerID,
		ActorID: actor, Event: audit.EventBrandingChanged,
		TargetType: "partner_branding", TargetID: partnerID.String(),
		Payload: map[string]any{"product_name": in.ProductName},
	})
}

// AddDomain registers a portal hostname for a partner.
func (s *Service) AddDomain(ctx context.Context, partnerID uuid.UUID, domain string, primary bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_domains(partner_id, domain, is_primary)
		VALUES ($1,$2,$3)
		ON CONFLICT (domain) DO UPDATE
		   SET partner_id=$1, is_primary=$3`, partnerID, domain, primary)
	return err
}

// SetFeatureFlag toggles a partner-level feature flag (Blueprint §8.6).
func (s *Service) SetFeatureFlag(ctx context.Context, partnerID uuid.UUID, flag string, enabled bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_feature_flags(partner_id, flag, enabled)
		VALUES ($1,$2,$3)
		ON CONFLICT (partner_id, flag) DO UPDATE SET enabled=EXCLUDED.enabled`,
		partnerID, flag, enabled)
	return err
}
