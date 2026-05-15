// Package partners implements the partner hierarchy (Blueprint §8).
package partners

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
	PlatformID uuid.UUID
	ParentID   *uuid.UUID
	TypeCode   string
	Name       string
	Slug       string
}

func (s *Service) Create(ctx context.Context, actor *uuid.UUID, in CreateInput) (*models.Partner, error) {
	if in.Name == "" || in.Slug == "" || in.TypeCode == "" {
		return nil, errors.New("partners: name, slug and type required")
	}
	var typeID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT id FROM partner_types WHERE code=$1`, in.TypeCode).Scan(&typeID); err != nil {
		return nil, fmt.Errorf("partners: unknown type %q", in.TypeCode)
	}
	p := &models.Partner{
		ID:         uuid.New(),
		PlatformID: in.PlatformID,
		ParentID:   in.ParentID,
		TypeCode:   in.TypeCode,
		Name:       in.Name,
		Slug:       in.Slug,
		Status:     "active",
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `
		INSERT INTO partners(id, platform_id, parent_id, type_id, name, slug, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at`,
		p.ID, p.PlatformID, p.ParentID, typeID, p.Name, p.Slug, p.Status,
	).Scan(&p.CreatedAt); err != nil {
		return nil, fmt.Errorf("partners: insert: %w", err)
	}
	// Record distributor->reseller link for hierarchy queries
	if p.ParentID != nil && in.TypeCode == "reseller" {
		if _, err := tx.Exec(ctx,
			`INSERT INTO partner_reseller_mapping(distributor_id, reseller_id) VALUES ($1,$2)
			 ON CONFLICT DO NOTHING`, *p.ParentID, p.ID); err != nil {
			return nil, err
		}
	}
	// Default branding stub so the portal always has something to render.
	if _, err := tx.Exec(ctx, `
		INSERT INTO partner_branding(partner_id, product_name, primary_color, secondary_color)
		VALUES ($1,$2,'#0F172A','#38BDF8')`, p.ID, p.Name); err != nil {
		return nil, err
	}
	// Default support settings.
	if _, err := tx.Exec(ctx,
		`INSERT INTO partner_support_settings(partner_id) VALUES ($1)`, p.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: p.PlatformID, PartnerID: &p.ID,
		ActorID: actor, Event: audit.EventPartnerCreated,
		TargetType: "partner", TargetID: p.ID.String(),
		Payload: map[string]any{"name": p.Name, "type": p.TypeCode},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.PartnerCreated, PartnerID: &p.ID, ActorID: actor,
		Payload: map[string]any{"slug": p.Slug, "type": p.TypeCode},
	})
	return p, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Partner, error) {
	p := &models.Partner{}
	err := s.pool.QueryRow(ctx, `
		SELECT p.id, p.platform_id, p.parent_id, t.code, p.name, p.slug, p.status, p.created_at
		  FROM partners p JOIN partner_types t ON t.id = p.type_id
		 WHERE p.id=$1`, id).
		Scan(&p.ID, &p.PlatformID, &p.ParentID, &p.TypeCode, &p.Name, &p.Slug, &p.Status, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

func (s *Service) List(ctx context.Context, platformID uuid.UUID) ([]models.Partner, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.platform_id, p.parent_id, t.code, p.name, p.slug, p.status, p.created_at
		  FROM partners p JOIN partner_types t ON t.id = p.type_id
		 WHERE p.platform_id=$1
		 ORDER BY p.created_at DESC`, platformID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Partner
	for rows.Next() {
		var p models.Partner
		if err := rows.Scan(&p.ID, &p.PlatformID, &p.ParentID, &p.TypeCode,
			&p.Name, &p.Slug, &p.Status, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Hierarchy resolves the chain ZAISHIELD → Distributor → Reseller for a tenant.
type Hierarchy struct {
	Platform   string `json:"platform"`
	Distributor string `json:"distributor,omitempty"`
	Reseller    string `json:"reseller,omitempty"`
	Partner     string `json:"partner"`
}

func (s *Service) HierarchyForTenant(ctx context.Context, tenantID uuid.UUID) (*Hierarchy, error) {
	row := s.pool.QueryRow(ctx, `
		WITH t AS (SELECT partner_id, platform_id FROM tenants WHERE id=$1),
		     p AS (SELECT pt.id, pt.parent_id, pt.name, pt.slug, ty.code AS type_code
		             FROM partners pt JOIN partner_types ty ON ty.id = pt.type_id
		            WHERE pt.id = (SELECT partner_id FROM t))
		SELECT pl.name, p.name, p.type_code, p.parent_id
		  FROM p, platforms pl WHERE pl.id=(SELECT platform_id FROM t)`, tenantID)
	h := &Hierarchy{}
	var partnerName, typeCode string
	var parentID *uuid.UUID
	if err := row.Scan(&h.Platform, &partnerName, &typeCode, &parentID); err != nil {
		return nil, err
	}
	h.Partner = partnerName
	switch typeCode {
	case "reseller":
		h.Reseller = partnerName
		if parentID != nil {
			var name string
			_ = s.pool.QueryRow(ctx, `SELECT name FROM partners WHERE id=$1`, *parentID).Scan(&name)
			h.Distributor = name
		}
	case "distributor":
		h.Distributor = partnerName
	}
	return h, nil
}

var ErrNotFound = errors.New("partner not found")
