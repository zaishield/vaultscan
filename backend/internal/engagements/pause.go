package engagements

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// Pause stops an engagement without ending it. Scope Guard refuses every
// scan submitted against a paused engagement (status != 'active').
// Reactivate via Resume when the customer is ready.
func (s *Service) Pause(ctx context.Context, id uuid.UUID, actor *uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE engagements
		   SET status = 'paused',
		       pause_reason = $3,
		       paused_at = now(),
		       paused_by = $2,
		       updated_at = now()
		 WHERE id = $1
		   AND status IN ('active', 'draft')`, id, actor, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("engagements: cannot pause (not active/draft)")
	}
	pid, partnerID, tenantID := s.fetchContext(ctx, id)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: "engagement.paused",
		TargetType: "engagement", TargetID: id.String(),
		Payload: map[string]any{"reason": reason},
	})
}

// Resume flips a paused engagement back to active. Refuses if the
// engagement's ends_at has passed in the meantime — operators must
// extend or close it instead.
func (s *Service) Resume(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE engagements
		   SET status = 'active',
		       pause_reason = NULL,
		       paused_at = NULL,
		       paused_by = NULL,
		       updated_at = now()
		 WHERE id = $1
		   AND status = 'paused'
		   AND ends_at > now()`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("engagements: cannot resume (not paused, or already ended)")
	}
	pid, partnerID, tenantID := s.fetchContext(ctx, id)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: "engagement.resumed",
		TargetType: "engagement", TargetID: id.String(),
	})
}

// SetRateLimit overrides the global per-tenant rate limit for one
// engagement. Scope Guard reads this in addition to the platform default.
func (s *Service) SetRateLimit(ctx context.Context, id uuid.UUID, actor *uuid.UUID, maxPerHour int) error {
	if maxPerHour <= 0 {
		return errors.New("engagements: max_scans_per_hour must be > 0")
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE engagements SET max_scans_per_hour=$2, updated_at=now() WHERE id=$1`,
		id, maxPerHour)
	if err != nil {
		return err
	}
	pid, partnerID, tenantID := s.fetchContext(ctx, id)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: "engagement.rate_limit_set",
		TargetType: "engagement", TargetID: id.String(),
		Payload: map[string]any{"max_scans_per_hour": maxPerHour},
	})
}

// LogAuthDocAccess records that someone viewed/downloaded the engagement's
// authorization document. The audit chain captures this too; the dedicated
// table makes compliance queries cheap.
func (s *Service) LogAuthDocAccess(ctx context.Context, documentID uuid.UUID, actor *uuid.UUID, action string, ip net.IP, ua string) error {
	if action != "view" && action != "download" {
		return errors.New("engagements: action must be view|download")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO authorization_access_logs(document_id, user_id, action, ip, user_agent)
		VALUES ($1, $2, $3, $4::inet, $5)`,
		documentID, actor, action, ipOrNull(ip), nullIfEmpty(ua))
	return err
}

func ipOrNull(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// IntensityRank ranks scan-profile intensities so Scope Guard can refuse a
// job whose profile is more aggressive than the engagement permits.
func IntensityRank(intensity string) int {
	switch intensity {
	case "light":
		return 1
	case "standard":
		return 2
	case "aggressive":
		return 3
	}
	return 0
}

// Internal: silence unused-import warnings for time when no exported helper
// uses it.
var _ = time.Time{}
