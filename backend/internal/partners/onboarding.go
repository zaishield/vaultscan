// onboarding.go — partner first-day setup tracking.
//
// Six milestones tracked per partner (migration 0053). The portal
// queries the row on every dashboard render and shows a checklist;
// each milestone is flipped to true by the corresponding API call
// in handlers_branding / handlers_tenant_branding so the partner
// never has to mark them by hand.
//
// Once all six are true the row's completed_at gets stamped and the
// portal stops showing the onboarding banner.

package partners

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OnboardingStatus carries the six checklist booleans plus their
// completion timestamps, and the overall completed_at.
type OnboardingStatus struct {
	PartnerID            uuid.UUID  `json:"partner_id"`
	BrandingSet          bool       `json:"branding_set"`
	BrandingSetAt        *time.Time `json:"branding_set_at,omitempty"`
	LogoUploaded         bool       `json:"logo_uploaded"`
	LogoUploadedAt       *time.Time `json:"logo_uploaded_at,omitempty"`
	DomainRegistered     bool       `json:"domain_registered"`
	DomainRegisteredAt   *time.Time `json:"domain_registered_at,omitempty"`
	SupportConfigured    bool       `json:"support_configured"`
	SupportConfiguredAt  *time.Time `json:"support_configured_at,omitempty"`
	SenderDNSVerified    bool       `json:"sender_dns_verified"`
	SenderDNSVerifiedAt  *time.Time `json:"sender_dns_verified_at,omitempty"`
	FirstTenantCreated   bool       `json:"first_tenant_created"`
	FirstTenantCreatedAt *time.Time `json:"first_tenant_created_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// PercentComplete returns 0..100 over the six milestones.
func (o *OnboardingStatus) PercentComplete() int {
	if o == nil {
		return 0
	}
	steps := []bool{
		o.BrandingSet, o.LogoUploaded, o.DomainRegistered,
		o.SupportConfigured, o.SenderDNSVerified, o.FirstTenantCreated,
	}
	done := 0
	for _, s := range steps {
		if s {
			done++
		}
	}
	return done * 100 / len(steps)
}

// GetOnboarding returns the partner's current onboarding row,
// creating it on demand if the partner predates migration 0053.
func (s *Service) GetOnboarding(ctx context.Context, partnerID uuid.UUID) (*OnboardingStatus, error) {
	st, err := s.fetchOnboarding(ctx, partnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO partner_onboarding(partner_id) VALUES ($1)
			 ON CONFLICT (partner_id) DO NOTHING`, partnerID); err != nil {
			return nil, err
		}
		return s.fetchOnboarding(ctx, partnerID)
	}
	return st, err
}

func (s *Service) fetchOnboarding(ctx context.Context, partnerID uuid.UUID) (*OnboardingStatus, error) {
	st := &OnboardingStatus{PartnerID: partnerID}
	err := s.pool.QueryRow(ctx, `
		SELECT branding_set, branding_set_at,
		       logo_uploaded, logo_uploaded_at,
		       domain_registered, domain_registered_at,
		       support_configured, support_configured_at,
		       sender_dns_verified, sender_dns_verified_at,
		       first_tenant_created, first_tenant_created_at,
		       completed_at, created_at
		  FROM partner_onboarding WHERE partner_id=$1`, partnerID).
		Scan(&st.BrandingSet, &st.BrandingSetAt,
			&st.LogoUploaded, &st.LogoUploadedAt,
			&st.DomainRegistered, &st.DomainRegisteredAt,
			&st.SupportConfigured, &st.SupportConfiguredAt,
			&st.SenderDNSVerified, &st.SenderDNSVerifiedAt,
			&st.FirstTenantCreated, &st.FirstTenantCreatedAt,
			&st.CompletedAt, &st.CreatedAt)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// Milestone constants name every checklist step. Helper for the
// MarkMilestone API and the per-handler call sites.
const (
	MilestoneBranding     = "branding_set"
	MilestoneLogo         = "logo_uploaded"
	MilestoneDomain       = "domain_registered"
	MilestoneSupport      = "support_configured"
	MilestoneSenderDNS    = "sender_dns_verified"
	MilestoneFirstTenant  = "first_tenant_created"
)

// MarkMilestone flips the named milestone to true. Idempotent — a
// second call leaves the existing timestamp in place. Once all six
// flip to true the row's completed_at is stamped.
//
// Nil-safe on both the receiver and the pool: callers happily fire
// this from API handlers that may run in test harnesses where
// Partners isn't fully wired. Rather than gate every call site
// (six of them in handlers.go) we no-op here.
func (s *Service) MarkMilestone(ctx context.Context, partnerID uuid.UUID, milestone string) error {
	if s == nil || s.pool == nil {
		return nil
	}
	col, atCol, ok := milestoneColumns(milestone)
	if !ok {
		return errors.New("partners: unknown milestone " + milestone)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Ensure a row exists.
	if _, err := tx.Exec(ctx,
		`INSERT INTO partner_onboarding(partner_id) VALUES ($1)
		 ON CONFLICT (partner_id) DO NOTHING`, partnerID); err != nil {
		return err
	}
	// Set the boolean + timestamp; idempotent via COALESCE on the
	// timestamp column (we only stamp it on the first true).
	q := `UPDATE partner_onboarding
	         SET ` + col + ` = true,
	             ` + atCol + ` = COALESCE(` + atCol + `, now())
	       WHERE partner_id=$1`
	if _, err := tx.Exec(ctx, q, partnerID); err != nil {
		return err
	}
	// If all six are true and completed_at is still null, stamp it.
	if _, err := tx.Exec(ctx, `
		UPDATE partner_onboarding
		   SET completed_at = now()
		 WHERE partner_id=$1
		   AND completed_at IS NULL
		   AND branding_set AND logo_uploaded AND domain_registered
		   AND support_configured AND sender_dns_verified
		   AND first_tenant_created`, partnerID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// milestoneColumns is the milestone-name → (boolean column,
// timestamp column) lookup. Centralised so MarkMilestone doesn't
// build SQL identifiers from user input (the identifiers are
// hardcoded here; the milestone name is a switch key).
func milestoneColumns(milestone string) (string, string, bool) {
	switch milestone {
	case MilestoneBranding:
		return "branding_set", "branding_set_at", true
	case MilestoneLogo:
		return "logo_uploaded", "logo_uploaded_at", true
	case MilestoneDomain:
		return "domain_registered", "domain_registered_at", true
	case MilestoneSupport:
		return "support_configured", "support_configured_at", true
	case MilestoneSenderDNS:
		return "sender_dns_verified", "sender_dns_verified_at", true
	case MilestoneFirstTenant:
		return "first_tenant_created", "first_tenant_created_at", true
	}
	return "", "", false
}
