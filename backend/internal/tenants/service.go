// Package tenants implements the multi-tenant CRUD layer (Blueprint §9).
package tenants

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
	bus   *eventbus.Bus
}

func New(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus) *Service {
	return &Service{pool: pool, audit: a, bus: b}
}

type CreateInput struct {
	PlatformID    uuid.UUID
	PartnerID     uuid.UUID
	Name          string
	Slug          string
	IsolationMode string
}

func (s *Service) Create(ctx context.Context, actor *uuid.UUID, in CreateInput) (*models.Tenant, error) {
	if in.Name == "" || in.Slug == "" {
		return nil, errors.New("tenants: name and slug required")
	}
	if in.IsolationMode == "" {
		in.IsolationMode = "shared"
	}
	t := &models.Tenant{
		ID:            uuid.New(),
		PlatformID:    in.PlatformID,
		PartnerID:     in.PartnerID,
		Name:          in.Name,
		Slug:          in.Slug,
		Status:        "active",
		IsolationMode: in.IsolationMode,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `
		INSERT INTO tenants(id, platform_id, partner_id, name, slug, status, isolation_mode)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at`,
		t.ID, t.PlatformID, t.PartnerID, t.Name, t.Slug, t.Status, t.IsolationMode,
	).Scan(&t.CreatedAt); err != nil {
		return nil, fmt.Errorf("tenants: insert: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenant_settings(tenant_id) VALUES ($1)`, t.ID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO partner_customer_mapping(partner_id, tenant_id) VALUES ($1,$2)
		 ON CONFLICT DO NOTHING`, t.PartnerID, t.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: t.PlatformID, PartnerID: &t.PartnerID, TenantID: &t.ID,
		ActorID: actor, Event: audit.EventTenantCreated,
		TargetType: "tenant", TargetID: t.ID.String(),
		Payload: map[string]any{"name": t.Name, "slug": t.Slug},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.TenantCreated, TenantID: &t.ID, PartnerID: &t.PartnerID,
		ActorID: actor, Payload: map[string]any{"slug": t.Slug, "name": t.Name},
	})
	return t, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	t := &models.Tenant{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, name, slug, status, isolation_mode, created_at
		  FROM tenants WHERE id=$1`, id).
		Scan(&t.ID, &t.PlatformID, &t.PartnerID, &t.Name, &t.Slug, &t.Status,
			&t.IsolationMode, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

type ListFilter struct {
	PlatformID uuid.UUID
	PartnerID  *uuid.UUID
	Limit      int
	Offset     int
}

func (s *Service) List(ctx context.Context, f ListFilter) ([]models.Tenant, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	// Bound OFFSET to stop hostile callers forcing a billion-row scan.
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.Offset > 100_000 {
		f.Offset = 100_000
	}
	args := []any{f.PlatformID, f.Limit, f.Offset}
	q := `SELECT id, platform_id, partner_id, name, slug, status, isolation_mode, created_at
	        FROM tenants WHERE platform_id=$1`
	if f.PartnerID != nil {
		q += " AND partner_id=$4"
		args = append(args, *f.PartnerID)
	}
	q += " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Tenant
	for rows.Next() {
		var t models.Tenant
		if err := rows.Scan(&t.ID, &t.PlatformID, &t.PartnerID, &t.Name,
			&t.Slug, &t.Status, &t.IsolationMode, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Suspend marks the tenant suspended (operationally: every authenticated
// request that resolves this tenant returns 403 until Reactivate is called).
func (s *Service) Suspend(ctx context.Context, id uuid.UUID, actor *uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tenants SET status='suspended', suspension_reason=$3,
		                  suspended_at=now(), suspended_by=$2, updated_at=now()
		 WHERE id=$1`, id, actor, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("tenants: not found")
	}
	t, _ := s.Get(ctx, id)
	if t != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: t.PlatformID, PartnerID: &t.PartnerID, TenantID: &t.ID,
			ActorID: actor, Event: "tenant.suspended",
			TargetType: "tenant", TargetID: id.String(),
			Payload: map[string]any{"reason": reason},
		})
	}
	return nil
}

// Reactivate undoes Suspend.
func (s *Service) Reactivate(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tenants SET status='active', suspension_reason=NULL,
		                  suspended_at=NULL, suspended_by=NULL, updated_at=now()
		 WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("tenants: not found")
	}
	t, _ := s.Get(ctx, id)
	if t != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: t.PlatformID, PartnerID: &t.PartnerID, TenantID: &t.ID,
			ActorID: actor, Event: "tenant.reactivated",
			TargetType: "tenant", TargetID: id.String(),
		})
	}
	return nil
}

var ErrNotFound = errors.New("tenant not found")

// ErrResidencyViolation is returned when a request handling pod's
// VAULTSCAN_REGION doesn't match the tenant's data_region pin. The
// API surfaces this as 451 (Unavailable For Legal Reasons) — the
// closest fitting status for "we can't process this here because
// of a residency commitment".
var ErrResidencyViolation = errors.New("tenants: data-residency pin does not match pod region")

// CheckResidency enforces the tenant's data-residency commitment.
// Returns nil when the pin is not set (legacy tenants), when the pod
// has no region configured (single-region deployments), or when they
// match. Otherwise ErrResidencyViolation.
//
// Call this from any service-layer write path that creates new
// long-lived data for the tenant (scans, findings, evidence). The
// idea is to surface a misconfigured cross-region routing before
// the data lands in the wrong region.
func (s *Service) CheckResidency(ctx context.Context, tenantID uuid.UUID, podRegion string) error {
	if podRegion == "" {
		return nil // single-region deployment; no enforcement possible
	}
	var pinned *string
	err := s.pool.QueryRow(ctx, `SELECT data_region FROM tenants WHERE id=$1`, tenantID).Scan(&pinned)
	if err != nil {
		return fmt.Errorf("tenants.CheckResidency: %w", err)
	}
	if pinned == nil || *pinned == "" {
		return nil
	}
	if *pinned != podRegion {
		return ErrResidencyViolation
	}
	return nil
}

// SetResidency updates the data_region pin and writes an audit row +
// a tenant_residency_history entry. Empty region clears the pin.
func (s *Service) SetResidency(ctx context.Context, tenantID uuid.UUID, region string, actor *uuid.UUID, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var prev *string
	if err := tx.QueryRow(ctx, `SELECT data_region FROM tenants WHERE id=$1`, tenantID).Scan(&prev); err != nil {
		return err
	}
	newVal := any(region)
	if region == "" {
		newVal = nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenants SET data_region=$2, updated_at=now() WHERE id=$1`,
		tenantID, newVal); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_residency_history(tenant_id, from_region, to_region, actor_id, reason)
		VALUES ($1,$2,$3,$4,$5)`,
		tenantID, prev, newVal, actor, reason); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	t, _ := s.Get(ctx, tenantID)
	if t != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: t.PlatformID, PartnerID: &t.PartnerID, TenantID: &t.ID,
			ActorID: actor, Event: "tenant.residency_set",
			TargetType: "tenant", TargetID: tenantID.String(),
			Payload: map[string]any{"from": prev, "to": region, "reason": reason},
		})
	}
	return nil
}
