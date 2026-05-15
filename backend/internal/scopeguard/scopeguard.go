// Package scopeguard is the legal and operational gate that every scan must
// pass through (Blueprint §14). The decision matrix is exhaustive and audited.
package scopeguard

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Decision codes match Blueprint §14.4 exactly.
const (
	DecisionApproved                = "approved"
	DecisionBlockedOutOfScope       = "blocked_out_of_scope"
	DecisionBlockedMissingAuth      = "blocked_missing_authorization"
	DecisionBlockedExpired          = "blocked_expired_engagement"
	DecisionBlockedTimeWindow       = "blocked_time_window"
	DecisionBlockedWrongAgent       = "blocked_wrong_agent"
	DecisionBlockedWrongTenant      = "blocked_wrong_tenant"
	DecisionBlockedRateLimit        = "blocked_rate_limit"
	DecisionRequiresManualApproval  = "requires_manual_approval"
)

// Inputs match Blueprint §14.3 exactly.
type Inputs struct {
	TenantID            uuid.UUID
	PartnerID           uuid.UUID
	EngagementID        uuid.UUID
	ScanProfile         string
	TargetType          string
	TargetValue         string
	Plane               string         // external | internal
	AgentID             *uuid.UUID
	ScannerRegion       string
	RequestedBy         *uuid.UUID
	Now                 time.Time      // optional override for testing
	RecentJobsLastHour  int            // injected by caller for rate-limit logic
	Intensity           string         // light | standard | aggressive
}

type Decision struct {
	Code    string         `json:"code"`
	Reason  string         `json:"reason"`
	Inputs  map[string]any `json:"inputs"`
}

type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Evaluate returns one of the 9 documented decision codes plus reason and
// records the decision in scope_decision_logs.
func (s *Service) Evaluate(ctx context.Context, in Inputs) (*Decision, error) {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	d := &Decision{
		Inputs: map[string]any{
			"tenant_id": in.TenantID, "partner_id": in.PartnerID,
			"engagement_id": in.EngagementID, "scan_profile": in.ScanProfile,
			"target_type": in.TargetType, "target_value": in.TargetValue,
			"plane": in.Plane, "scanner_region": in.ScannerRegion,
			"agent_id": in.AgentID, "intensity": in.Intensity,
		},
	}

	// Rate limit: per-tenant per-engagement cap
	if in.RecentJobsLastHour >= 50 {
		d.Code = DecisionBlockedRateLimit
		d.Reason = "tenant rate limit exceeded (>=50 scans/hour)"
		s.log(ctx, in, d)
		return d, nil
	}

	// 1. Engagement must exist, belong to tenant/partner, and be active.
	var status string
	var startsAt, endsAt time.Time
	var ownerTenant, ownerPartner uuid.UUID
	var intensity string
	err := s.pool.QueryRow(ctx, `
		SELECT status, starts_at, ends_at, tenant_id, partner_id, intensity
		  FROM engagements WHERE id=$1`, in.EngagementID).
		Scan(&status, &startsAt, &endsAt, &ownerTenant, &ownerPartner, &intensity)
	if err != nil {
		d.Code = DecisionBlockedMissingAuth
		d.Reason = "engagement not found"
		s.log(ctx, in, d)
		return d, nil
	}
	if ownerTenant != in.TenantID || ownerPartner != in.PartnerID {
		d.Code = DecisionBlockedWrongTenant
		d.Reason = "engagement does not belong to requested tenant or partner"
		s.log(ctx, in, d)
		return d, nil
	}
	if status != "active" || in.Now.After(endsAt) || in.Now.Before(startsAt) {
		d.Code = DecisionBlockedExpired
		d.Reason = "engagement is not currently active"
		s.log(ctx, in, d)
		return d, nil
	}

	// 2. Authorization document required.
	var docCount int
	_ = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM authorization_documents WHERE engagement_id=$1`, in.EngagementID).
		Scan(&docCount)
	if docCount == 0 {
		d.Code = DecisionBlockedMissingAuth
		d.Reason = "no authorization document on file for engagement"
		s.log(ctx, in, d)
		return d, nil
	}

	// 3a. Blackout window check (Black Friday, RTO drills, etc).
	if blocked, why := s.checkBlackouts(ctx, in.EngagementID, in.Now); blocked {
		d.Code = DecisionBlockedTimeWindow
		d.Reason = why
		s.log(ctx, in, d)
		return d, nil
	}

	// 3b. Scan window check via rules_of_engagement.
	if blocked, why := s.checkWindow(ctx, in.EngagementID, in.Now); blocked {
		d.Code = DecisionBlockedTimeWindow
		d.Reason = why
		s.log(ctx, in, d)
		return d, nil
	}

	// 4. Target-in-scope check (CIDR-aware for IP/network).
	inScope, err := s.targetInScope(ctx, in.EngagementID, in.TargetType, in.TargetValue, in.Plane)
	if err != nil {
		return nil, err
	}
	if !inScope {
		d.Code = DecisionBlockedOutOfScope
		d.Reason = "target is not within an approved scope entry"
		s.log(ctx, in, d)
		return d, nil
	}

	// 5. Agent-tenant binding for internal scans.
	if in.Plane == "internal" {
		if in.AgentID == nil {
			d.Code = DecisionBlockedWrongAgent
			d.Reason = "internal scan requires an assigned agent"
			s.log(ctx, in, d)
			return d, nil
		}
		var agentTenant uuid.UUID
		var agentStatus string
		err := s.pool.QueryRow(ctx,
			`SELECT tenant_id, status FROM agents WHERE id=$1`, *in.AgentID).
			Scan(&agentTenant, &agentStatus)
		if err != nil || agentTenant != in.TenantID || (agentStatus != "online" && agentStatus != "pending") {
			d.Code = DecisionBlockedWrongAgent
			d.Reason = "agent missing, offline, or bound to a different tenant"
			s.log(ctx, in, d)
			return d, nil
		}
		// Assigned scope check
		var assigned int
		_ = s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM agent_assigned_scope WHERE agent_id=$1 AND engagement_id=$2`,
			*in.AgentID, in.EngagementID).Scan(&assigned)
		if assigned == 0 {
			d.Code = DecisionBlockedWrongAgent
			d.Reason = "agent is not assigned to this engagement"
			s.log(ctx, in, d)
			return d, nil
		}
	}

	// 6. Aggressive scans require explicit approval.
	requiresApproval := false
	var profileIntensity string
	var profileRequiresApproval bool
	_ = s.pool.QueryRow(ctx,
		`SELECT intensity, requires_approval FROM scan_profiles WHERE code=$1`, in.ScanProfile).
		Scan(&profileIntensity, &profileRequiresApproval)
	if profileRequiresApproval || profileIntensity == "aggressive" || in.Intensity == "aggressive" {
		requiresApproval = true
	}
	if requiresApproval && intensity != "aggressive" {
		d.Code = DecisionRequiresManualApproval
		d.Reason = "aggressive scan profile requires explicit approve_aggressive_scan permission"
		s.log(ctx, in, d)
		return d, nil
	}

	d.Code = DecisionApproved
	d.Reason = "all guardrails satisfied"
	s.log(ctx, in, d)
	return d, nil
}

func (s *Service) checkWindow(ctx context.Context, engagementID uuid.UUID, now time.Time) (bool, string) {
	var startStr, endStr *time.Time
	var dows []string
	err := s.pool.QueryRow(ctx, `
		SELECT scan_window_start, scan_window_end,
		       COALESCE((SELECT array_agg(value) FROM jsonb_array_elements_text(days_of_week)),
		                ARRAY[]::TEXT[])
		  FROM rules_of_engagement WHERE engagement_id=$1
		  ORDER BY created_at DESC LIMIT 1`, engagementID).
		Scan(&startStr, &endStr, &dows)
	if err != nil {
		return false, "" // no rules == no extra restriction
	}
	if len(dows) > 0 {
		dow := strings.ToLower(now.Weekday().String()[:3])
		ok := false
		for _, d := range dows {
			if strings.EqualFold(d, dow) {
				ok = true
				break
			}
		}
		if !ok {
			return true, "current day not in rules-of-engagement window"
		}
	}
	if startStr != nil && endStr != nil {
		nh, nm := now.Hour()*60+now.Minute(), 0
		_ = nm
		sh := startStr.Hour()*60 + startStr.Minute()
		eh := endStr.Hour()*60 + endStr.Minute()
		if sh != eh && (nh < sh || nh > eh) {
			return true, "current time outside rules-of-engagement window"
		}
	}
	return false, ""
}

// checkBlackouts reads the engagement's rules_of_engagement.blackouts and
// returns (true, reason) when `now` falls inside any window.
func (s *Service) checkBlackouts(ctx context.Context, engagementID uuid.UUID, now time.Time) (bool, string) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `
		SELECT blackouts FROM rules_of_engagement
		 WHERE engagement_id=$1 ORDER BY created_at DESC LIMIT 1`, engagementID).
		Scan(&raw); err != nil {
		return false, "" // no RoE → no blackouts
	}
	var blackouts []struct {
		Label    string    `json:"label"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
	}
	_ = json.Unmarshal(raw, &blackouts)
	for _, b := range blackouts {
		if !b.StartsAt.After(now) && !b.EndsAt.Before(now) {
			return true, "blackout window active: " + b.Label
		}
	}
	return false, ""
}

func (s *Service) targetInScope(ctx context.Context, engagementID uuid.UUID,
	targetType, value, plane string) (bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT target_type, target_value, plane
		  FROM scope_targets
		 WHERE engagement_id=$1 AND status='approved'`, engagementID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var ttype, tval, tplane string
		if err := rows.Scan(&ttype, &tval, &tplane); err != nil {
			return false, err
		}
		if tplane != plane {
			continue
		}
		if matches(ttype, tval, targetType, value) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func matches(scopeType, scopeValue, targetType, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	scopeValue = strings.ToLower(strings.TrimSpace(scopeValue))
	switch scopeType {
	case "domain":
		// A URL target like "https://api.example.com/x" is in-scope for the
		// domain scope "example.com" — extract the host first.
		t := target
		if targetType == "url" {
			if host := hostFromURL(t); host != "" {
				t = host
			}
		}
		return t == scopeValue || strings.HasSuffix(t, "."+scopeValue)
	case "subdomain", "url", "api":
		return target == scopeValue
	case "ip":
		return target == scopeValue
	case "cidr":
		_, network, err := net.ParseCIDR(scopeValue)
		if err != nil {
			return false
		}
		ip := net.ParseIP(target)
		if ip != nil {
			return network.Contains(ip)
		}
		// allow CIDR-in-CIDR if target is itself a CIDR
		_, t, err := net.ParseCIDR(target)
		if err == nil {
			ones, _ := t.Mask.Size()
			snets, _ := network.Mask.Size()
			return network.Contains(t.IP) && ones >= snets
		}
		return false
	default:
		return target == scopeValue
	}
}

// hostFromURL returns the host portion of a URL-like string. Strips the
// scheme and any path / port / query / fragment. Returns "" if the input
// doesn't look like a URL.
func hostFromURL(s string) string {
	if !strings.Contains(s, "://") {
		return ""
	}
	rest := s[strings.Index(s, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, ":"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func (s *Service) log(ctx context.Context, in Inputs, d *Decision) {
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO scope_decision_logs(engagement_id, tenant_id, requested_by,
		    target_value, target_type, plane, decision, reason, inputs)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
		in.EngagementID, in.TenantID, in.RequestedBy,
		in.TargetValue, in.TargetType, in.Plane,
		d.Code, d.Reason, jsonbBytes(d.Inputs))
}
