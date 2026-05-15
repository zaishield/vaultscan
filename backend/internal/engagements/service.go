// Package engagements implements engagement lifecycle (Blueprint §14, §20.1).
package engagements

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	TenantID      uuid.UUID
	ClientID      *uuid.UUID
	Code          string
	Name          string
	Description   string
	StartsAt      time.Time
	EndsAt        time.Time
	Intensity     string
	EmergencyName string
	EmergencyMail string
	EmergencyPhone string
}

func (s *Service) Create(ctx context.Context, actor *uuid.UUID, in CreateInput) (*models.Engagement, error) {
	if in.Code == "" || in.Name == "" {
		return nil, errors.New("engagements: code and name required")
	}
	if !in.EndsAt.After(in.StartsAt) {
		return nil, errors.New("engagements: ends_at must be after starts_at")
	}
	if in.Intensity == "" {
		in.Intensity = "standard"
	}
	e := &models.Engagement{
		ID:          uuid.New(),
		PlatformID:  in.PlatformID,
		PartnerID:   in.PartnerID,
		TenantID:    in.TenantID,
		ClientID:    in.ClientID,
		Code:        in.Code,
		Name:        in.Name,
		Description: in.Description,
		Status:      "draft",
		StartsAt:    in.StartsAt,
		EndsAt:      in.EndsAt,
		Intensity:   in.Intensity,
	}
	e.EmergencyContact.Name = in.EmergencyName
	e.EmergencyContact.Email = in.EmergencyMail
	e.EmergencyContact.Phone = in.EmergencyPhone
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO engagements(id, platform_id, partner_id, tenant_id, client_id,
		                        code, name, description, status, starts_at, ends_at,
		                        intensity,
		                        emergency_contact_name, emergency_contact_email, emergency_contact_phone,
		                        created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING created_at`,
		e.ID, e.PlatformID, e.PartnerID, e.TenantID, e.ClientID,
		e.Code, e.Name, e.Description, e.Status, e.StartsAt, e.EndsAt,
		e.Intensity, in.EmergencyName, in.EmergencyMail, in.EmergencyPhone,
		actor).Scan(&e.CreatedAt); err != nil {
		return nil, fmt.Errorf("engagements: insert: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: e.PlatformID, PartnerID: &e.PartnerID, TenantID: &e.TenantID,
		ActorID: actor, Event: "engagement.created",
		TargetType: "engagement", TargetID: e.ID.String(),
		Payload: map[string]any{"code": e.Code, "name": e.Name},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.EngagementCreated, TenantID: &e.TenantID, PartnerID: &e.PartnerID,
		ActorID: actor, Payload: map[string]any{"code": e.Code},
	})
	return e, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Engagement, error) {
	e := &models.Engagement{}
	var name, mail, phone string
	err := s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, client_id, code, name,
		       COALESCE(description,''), status, starts_at, ends_at, intensity,
		       COALESCE(emergency_contact_name,''),
		       COALESCE(emergency_contact_email,''),
		       COALESCE(emergency_contact_phone,''),
		       created_at
		  FROM engagements WHERE id=$1`, id).
		Scan(&e.ID, &e.PlatformID, &e.PartnerID, &e.TenantID, &e.ClientID,
			&e.Code, &e.Name, &e.Description, &e.Status, &e.StartsAt, &e.EndsAt,
			&e.Intensity, &name, &mail, &phone, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.EmergencyContact.Name = name
	e.EmergencyContact.Email = mail
	e.EmergencyContact.Phone = phone
	return e, nil
}

func (s *Service) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.Engagement, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, client_id, code, name,
		       COALESCE(description,''), status, starts_at, ends_at, intensity,
		       COALESCE(emergency_contact_name,''),
		       COALESCE(emergency_contact_email,''),
		       COALESCE(emergency_contact_phone,''), created_at
		  FROM engagements WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Engagement
	for rows.Next() {
		var e models.Engagement
		var name, mail, phone string
		if err := rows.Scan(&e.ID, &e.PlatformID, &e.PartnerID, &e.TenantID, &e.ClientID,
			&e.Code, &e.Name, &e.Description, &e.Status, &e.StartsAt, &e.EndsAt,
			&e.Intensity, &name, &mail, &phone, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.EmergencyContact.Name, e.EmergencyContact.Email, e.EmergencyContact.Phone = name, mail, phone
		out = append(out, e)
	}
	return out, rows.Err()
}

// Activate transitions an engagement from draft to active. Requires that
// at least one authorization document and one approved scope target exist.
func (s *Service) Activate(ctx context.Context, actor *uuid.UUID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var docs, scope int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM authorization_documents WHERE engagement_id=$1`, id).Scan(&docs); err != nil {
		return err
	}
	if docs == 0 {
		return errors.New("engagements: cannot activate without authorization document")
	}
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM scope_targets WHERE engagement_id=$1 AND status='approved'`, id).Scan(&scope); err != nil {
		return err
	}
	if scope == 0 {
		return errors.New("engagements: cannot activate without approved scope")
	}
	tag, err := tx.Exec(ctx, `
		UPDATE engagements
		   SET status='active', approved_by=$2, approved_at=now(), updated_at=now()
		 WHERE id=$1 AND status IN ('draft','paused')`, id, actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("engagements: not in draft/paused state")
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	var pid, partnerID uuid.UUID
	var tenant uuid.UUID
	_ = s.pool.QueryRow(ctx,
		`SELECT platform_id, partner_id, tenant_id FROM engagements WHERE id=$1`, id).
		Scan(&pid, &partnerID, &tenant)
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenant,
		ActorID: actor, Event: "engagement.activated",
		TargetType: "engagement", TargetID: id.String(),
	})
	return nil
}

// AddScope inserts a scope target in pending state.
func (s *Service) AddScope(ctx context.Context, actor *uuid.UUID, engagementID uuid.UUID,
	targetType, value, plane, notes string) (*models.ScopeTarget, error) {
	t := &models.ScopeTarget{
		ID: uuid.New(), EngagementID: engagementID, TargetType: targetType,
		TargetValue: value, Plane: plane, Status: "pending", Notes: notes,
	}
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO scope_targets(id, engagement_id, target_type, target_value, plane, status, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		t.ID, t.EngagementID, t.TargetType, t.TargetValue, t.Plane, t.Status, t.Notes,
	).Scan(&t.CreatedAt); err != nil {
		return nil, fmt.Errorf("scope: insert: %w", err)
	}
	pid, partnerID, tenantID := s.fetchContext(ctx, engagementID)
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: audit.EventScopeAdded,
		TargetType: "scope", TargetID: t.ID.String(),
		Payload: map[string]any{"engagement_id": engagementID, "value": value, "type": targetType, "plane": plane},
	})
	return t, nil
}

// ApproveScope marks a scope target as approved (Blueprint §14, §23.2).
func (s *Service) ApproveScope(ctx context.Context, actor *uuid.UUID, scopeID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE scope_targets
		   SET status='approved', approved_by=$2, approved_at=now()
		 WHERE id=$1 AND status='pending'`, scopeID, actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("scope: not in pending state")
	}
	var engagementID uuid.UUID
	_ = s.pool.QueryRow(ctx, `SELECT engagement_id FROM scope_targets WHERE id=$1`, scopeID).
		Scan(&engagementID)
	pid, partnerID, tenantID := s.fetchContext(ctx, engagementID)
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: audit.EventScopeApproved,
		TargetType: "scope", TargetID: scopeID.String(),
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ScopeApproved, TenantID: &tenantID, PartnerID: &partnerID,
		ActorID: actor, Payload: map[string]any{"scope_id": scopeID, "engagement_id": engagementID},
	})
	return nil
}

func (s *Service) ListScope(ctx context.Context, engagementID uuid.UUID) ([]models.ScopeTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, engagement_id, target_type, target_value, plane, status,
		       approved_by, approved_at, COALESCE(notes,''), created_at
		  FROM scope_targets WHERE engagement_id=$1 ORDER BY created_at DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ScopeTarget
	for rows.Next() {
		var t models.ScopeTarget
		if err := rows.Scan(&t.ID, &t.EngagementID, &t.TargetType, &t.TargetValue, &t.Plane,
			&t.Status, &t.ApprovedBy, &t.ApprovedAt, &t.Notes, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) fetchContext(ctx context.Context, engagementID uuid.UUID) (platform, partner, tenant uuid.UUID) {
	_ = s.pool.QueryRow(ctx,
		`SELECT platform_id, partner_id, tenant_id FROM engagements WHERE id=$1`, engagementID).
		Scan(&platform, &partner, &tenant)
	return
}

var ErrNotFound = errors.New("engagement not found")
