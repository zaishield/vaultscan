// Package billing implements partner-level quota enforcement on top
// of the partner_billing_plans table (Blueprint §8.7).
//
// Model: every partner has zero or one ACTIVE plan at a time
// (partner_billing_plans rows are time-bounded by valid_from /
// valid_to). The plan declares per-resource quotas:
//
//	asset_quota  — number of assets that can exist concurrently
//	scan_quota   — number of scan jobs created in the current
//	               billing cycle (monthly by default)
//	agent_quota  — number of enrolled agents
//
// Convention: a quota of 0 means UNLIMITED. This matches the
// pre-existing schema defaults so partners that never had a plan
// keep working without surprise.
//
// Enforcement points (call CheckAsset / CheckScan / CheckAgent
// from these paths before the INSERT):
//
//	asset creation   — assets.Service.Create
//	scan submission  — scanorch.Orchestrator.Submit
//	agent enrollment — agents.Service.Provision
//
// On block, the service inserts a row into partner_quota_blocks
// (operator-visible audit trail) and returns ErrQuotaExceeded with
// the kind, current usage, and limit so the API can return a
// detailed 429 to the client.
//
// Overage policies:
//
//	block — refuse the operation (default)
//	warn  — allow + emit a warning event; the API can choose to
//	        surface this in the response headers
//	allow — pass-through (useful for "soft-launch" trials)
package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// Kind identifies which quota family a check applies to.
type Kind string

const (
	KindAsset Kind = "asset"
	KindScan  Kind = "scan"
	KindAgent Kind = "agent"
)

// OveragePolicy values match the partner_billing_plans.overage_policy
// column. The default is "block" — refusing the operation; "warn"
// lets it through but emits a warning event; "allow" is pass-through.
const (
	OverageBlock = "block"
	OverageWarn  = "warn"
	OverageAllow = "allow"
)

// ErrQuotaExceeded is the structured rejection from a Check call.
// Carries enough detail for the API to translate into an actionable
// 429 (current usage, limit, kind, plan name).
type ErrQuotaExceeded struct {
	Kind    Kind
	Plan    string // plan name or code
	Current int
	Limit   int
}

func (e *ErrQuotaExceeded) Error() string {
	return fmt.Sprintf("billing: %s quota exceeded on plan %q (using %d of %d)",
		e.Kind, e.Plan, e.Current, e.Limit)
}

// IsQuotaExceeded is a stable type-check for callers.
func IsQuotaExceeded(err error) bool {
	var qe *ErrQuotaExceeded
	return errors.As(err, &qe)
}

// Service is the partner-billing entry point.
type Service struct {
	pool *pgxpool.Pool
	bus  *eventbus.Bus
}

// New wires the service. bus is optional — pass nil to skip warning
// events.
func New(pool *pgxpool.Pool, bus *eventbus.Bus) *Service {
	return &Service{pool: pool, bus: bus}
}

// Plan describes the currently-active billing plan for a partner.
// Limit == 0 means unlimited for that resource.
type Plan struct {
	ID            uuid.UUID `json:"id"`
	PartnerID     uuid.UUID `json:"partner_id"`
	PlanCode      string    `json:"plan_code"`
	Name          string    `json:"name,omitempty"`
	AssetQuota    int       `json:"asset_quota"`
	ScanQuota     int       `json:"scan_quota"`
	AgentQuota    int       `json:"agent_quota"`
	OveragePolicy string    `json:"overage_policy"`
	Currency      string    `json:"currency"`
	PriceCents    int64     `json:"price_cents,omitempty"`
	BillingCycle  string    `json:"billing_cycle"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidTo       *time.Time `json:"valid_to,omitempty"`
}

// Usage is a live snapshot of consumption across the three
// enforced resources for a single partner.
type Usage struct {
	PartnerID uuid.UUID `json:"partner_id"`
	Assets    int       `json:"assets"`
	Scans     int       `json:"scans_current_cycle"`
	Agents    int       `json:"agents"`
	AsOf      time.Time `json:"as_of"`
}

// CurrentPlan returns the plan currently in effect for the partner.
// Returns (nil, nil) if no plan is configured (= unlimited).
func (s *Service) CurrentPlan(ctx context.Context, partnerID uuid.UUID) (*Plan, error) {
	p := &Plan{}
	err := s.pool.QueryRow(ctx, `
		SELECT plan_id, partner_id, plan_code, COALESCE(name,''),
		       asset_quota, scan_quota, agent_quota,
		       overage_policy, currency, COALESCE(price_cents,0),
		       billing_cycle, valid_from, valid_to
		  FROM partner_active_plan
		 WHERE partner_id = $1`, partnerID).
		Scan(&p.ID, &p.PartnerID, &p.PlanCode, &p.Name,
			&p.AssetQuota, &p.ScanQuota, &p.AgentQuota,
			&p.OveragePolicy, &p.Currency, &p.PriceCents,
			&p.BillingCycle, &p.ValidFrom, &p.ValidTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Usage computes live consumption counts. Used to power both the
// portal usage view and the gating Check methods (we read once,
// then enforce; in a hot loop the caller can pass a cached Usage).
//
// scan_quota counts jobs created in the current billing cycle. The
// cycle is "monthly" by default and starts at the plan's valid_from
// anchor (so a partner who signed up on the 15th has cycles ending
// the 15th, not the calendar month boundary). This matches the
// invoice generator the platform integrates with.
func (s *Service) UsageFor(ctx context.Context, partnerID uuid.UUID, plan *Plan) (*Usage, error) {
	u := &Usage{PartnerID: partnerID, AsOf: time.Now().UTC()}

	// Asset count: every row in `assets` whose tenant maps to this
	// partner via partner_customer_mapping.
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM assets a
		 WHERE a.tenant_id IN (
		     SELECT tenant_id FROM partner_customer_mapping WHERE partner_id=$1
		 )`, partnerID).Scan(&u.Assets); err != nil {
		return nil, fmt.Errorf("billing: count assets: %w", err)
	}

	// Agent count: agents.partner_id direct (no mapping needed —
	// agents are partner-owned in the schema).
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agents WHERE partner_id=$1
		   AND status != 'revoked'`, partnerID).Scan(&u.Agents); err != nil {
		return nil, fmt.Errorf("billing: count agents: %w", err)
	}

	// Scan count: scan_jobs created within the current billing cycle.
	// Cycle start defaults to "30 days ago" when no plan is set;
	// otherwise plan.ValidFrom + N*BillingCycle.
	cycleStart := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if plan != nil {
		cycleStart = currentCycleStart(plan.ValidFrom, plan.BillingCycle, time.Now().UTC())
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM scan_jobs sj
		 WHERE sj.partner_id=$1 AND sj.created_at >= $2`,
		partnerID, cycleStart).Scan(&u.Scans); err != nil {
		return nil, fmt.Errorf("billing: count scans: %w", err)
	}
	return u, nil
}

// currentCycleStart returns the start of the billing cycle that
// contains `now`, anchored to the plan's first valid_from. Supports
// "monthly" (default), "quarterly", and "annually" cycles.
func currentCycleStart(anchor time.Time, cycle string, now time.Time) time.Time {
	if anchor.After(now) {
		return anchor
	}
	switch cycle {
	case "annually":
		years := now.Year() - anchor.Year()
		candidate := anchor.AddDate(years, 0, 0)
		if candidate.After(now) {
			candidate = candidate.AddDate(-1, 0, 0)
		}
		return candidate
	case "quarterly":
		// Step by 3 months from anchor until we pass `now`, then back off one.
		c := anchor
		for c.AddDate(0, 3, 0).Before(now) || c.AddDate(0, 3, 0).Equal(now) {
			c = c.AddDate(0, 3, 0)
		}
		return c
	default: // "monthly"
		c := anchor
		for c.AddDate(0, 1, 0).Before(now) || c.AddDate(0, 1, 0).Equal(now) {
			c = c.AddDate(0, 1, 0)
		}
		return c
	}
}

// CheckAsset / CheckScan / CheckAgent are the three enforcement entry
// points. They share a common Check core; the named wrappers exist so
// the call sites read clearly at the consumption point.
func (s *Service) CheckAsset(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID) error {
	return s.check(ctx, partnerID, actor, KindAsset)
}
func (s *Service) CheckScan(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID) error {
	return s.check(ctx, partnerID, actor, KindScan)
}
func (s *Service) CheckAgent(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID) error {
	return s.check(ctx, partnerID, actor, KindAgent)
}

func (s *Service) check(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID, kind Kind) error {
	plan, err := s.CurrentPlan(ctx, partnerID)
	if err != nil {
		return err
	}
	if plan == nil {
		// No plan = unlimited; matches backwards-compat.
		return nil
	}
	limit := 0
	switch kind {
	case KindAsset:
		limit = plan.AssetQuota
	case KindScan:
		limit = plan.ScanQuota
	case KindAgent:
		limit = plan.AgentQuota
	}
	if limit == 0 {
		// 0 = unlimited.
		return nil
	}
	usage, err := s.UsageFor(ctx, partnerID, plan)
	if err != nil {
		return err
	}
	current := 0
	switch kind {
	case KindAsset:
		current = usage.Assets
	case KindScan:
		current = usage.Scans
	case KindAgent:
		current = usage.Agents
	}
	if current < limit {
		return nil
	}
	// Over (or at) limit. Apply the plan's overage_policy.
	switch plan.OveragePolicy {
	case OverageAllow:
		return nil
	case OverageWarn:
		s.emitWarning(ctx, partnerID, kind, current, limit, plan)
		return nil
	default: // OverageBlock
		s.recordBlock(ctx, partnerID, actor, plan, kind, current, limit)
		return &ErrQuotaExceeded{
			Kind: kind, Plan: planLabel(plan),
			Current: current, Limit: limit,
		}
	}
}

func (s *Service) recordBlock(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID,
	plan *Plan, kind Kind, current, limit int) {
	// Best-effort — never fail a Check call because the audit row
	// couldn't be written. Operators still see the 429 response.
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO partner_quota_blocks(partner_id, plan_id, quota_kind,
		    current_usage, quota_limit, actor_id, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		partnerID, plan.ID, string(kind), current, limit, actor,
		fmt.Sprintf("over %s quota on plan %s", kind, plan.PlanCode))
	if s.bus != nil {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type:      eventbus.PartnerQuotaBlocked,
			PartnerID: &partnerID,
			ActorID:   actor,
			Payload: map[string]any{
				"kind": string(kind), "current": current, "limit": limit,
				"plan": plan.PlanCode,
			},
		})
	}
}

func (s *Service) emitWarning(ctx context.Context, partnerID uuid.UUID,
	kind Kind, current, limit int, plan *Plan) {
	if s.bus == nil {
		return
	}
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type:      eventbus.PartnerQuotaWarning,
		PartnerID: &partnerID,
		Payload: map[string]any{
			"kind": string(kind), "current": current, "limit": limit,
			"plan": plan.PlanCode,
		},
	})
}

func planLabel(p *Plan) string {
	if p.Name != "" {
		return p.Name
	}
	return p.PlanCode
}

// AssignPlan replaces the partner's active plan with a new one.
// Closes the prior plan's valid_to to now() and inserts a fresh
// row. Operators wanting to backdate or schedule a future plan
// change should write to partner_billing_plans directly through
// a migration / runbook.
type AssignInput struct {
	PartnerID     uuid.UUID
	PlanCode      string
	Name          string
	AssetQuota    int
	ScanQuota     int
	AgentQuota    int
	OveragePolicy string
	Currency      string
	PriceCents    int64
	BillingCycle  string
}

func (s *Service) AssignPlan(ctx context.Context, in AssignInput, actor *uuid.UUID) (*Plan, error) {
	if in.PartnerID == uuid.Nil || in.PlanCode == "" {
		return nil, errors.New("billing: partner_id + plan_code required")
	}
	if in.OveragePolicy == "" {
		in.OveragePolicy = OverageBlock
	}
	if in.Currency == "" {
		in.Currency = "USD"
	}
	if in.BillingCycle == "" {
		in.BillingCycle = "monthly"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Close any currently-active plan.
	if _, err := tx.Exec(ctx, `
		UPDATE partner_billing_plans
		   SET valid_to = now(), updated_at = now()
		 WHERE partner_id=$1
		   AND valid_from <= now()
		   AND (valid_to IS NULL OR valid_to > now())`, in.PartnerID); err != nil {
		return nil, err
	}
	p := &Plan{
		ID: uuid.New(), PartnerID: in.PartnerID,
		PlanCode: in.PlanCode, Name: in.Name,
		AssetQuota: in.AssetQuota, ScanQuota: in.ScanQuota, AgentQuota: in.AgentQuota,
		OveragePolicy: in.OveragePolicy, Currency: in.Currency,
		PriceCents: in.PriceCents, BillingCycle: in.BillingCycle,
		ValidFrom: time.Now().UTC(),
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO partner_billing_plans(id, partner_id, plan_code, name,
		    asset_quota, scan_quota, agent_quota, overage_policy,
		    currency, price_cents, billing_cycle, valid_from)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING valid_from`,
		p.ID, p.PartnerID, p.PlanCode, p.Name,
		p.AssetQuota, p.ScanQuota, p.AgentQuota, p.OveragePolicy,
		p.Currency, p.PriceCents, p.BillingCycle, p.ValidFrom,
	).Scan(&p.ValidFrom); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if s.bus != nil {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type:      eventbus.PartnerPlanChanged,
			PartnerID: &in.PartnerID,
			ActorID:   actor,
			Payload: map[string]any{
				"plan_code": p.PlanCode, "plan_id": p.ID.String(),
			},
		})
	}
	return p, nil
}

// RecentBlocks returns the most recent N blocks for a partner.
// Used by the portal's "quota status" widget so admins can see
// what was rejected without scraping audit logs.
type Block struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"`
	QuotaKind  string     `json:"quota_kind"`
	Current    int        `json:"current_usage"`
	Limit      int        `json:"quota_limit"`
	Reason     string     `json:"reason"`
	BlockedAt  time.Time  `json:"blocked_at"`
}

func (s *Service) RecentBlocks(ctx context.Context, partnerID uuid.UUID, limit int) ([]Block, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, quota_kind, current_usage, quota_limit,
		       COALESCE(reason,''), blocked_at
		  FROM partner_quota_blocks
		 WHERE partner_id=$1
		 ORDER BY blocked_at DESC
		 LIMIT $2`, partnerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		var b Block
		if err := rows.Scan(&b.ID, &b.TenantID, &b.QuotaKind,
			&b.Current, &b.Limit, &b.Reason, &b.BlockedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
