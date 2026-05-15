// Package users handles user lifecycle + role assignment + login event
// recording (Blueprint §23, §32.1). Production deployments back this with
// Keycloak SCIM; the service here is the platform-side mirror so RBAC
// decisions stay deterministic even when the IdP is unreachable.
package users

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

type CreateInput struct {
	PlatformID uuid.UUID
	PartnerID  *uuid.UUID
	TenantID   *uuid.UUID
	Email      string
	FullName   string
	MFAEnabled bool
	Actor      *uuid.UUID
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*models.User, error) {
	if in.Email == "" || in.FullName == "" {
		return nil, errors.New("users: email + full_name required")
	}
	u := &models.User{
		ID: uuid.New(), PlatformID: in.PlatformID,
		PartnerID: in.PartnerID, TenantID: in.TenantID,
		Email: in.Email, FullName: in.FullName,
		MFAEnabled: in.MFAEnabled, Status: "active",
	}
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO users(id, platform_id, partner_id, tenant_id, email, full_name,
		    mfa_enabled, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
		u.ID, u.PlatformID, u.PartnerID, u.TenantID, u.Email, u.FullName,
		u.MFAEnabled, u.Status).Scan(&u.CreatedAt); err != nil {
		return nil, fmt.Errorf("users: insert: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: in.PlatformID, PartnerID: in.PartnerID, TenantID: in.TenantID,
		ActorID: in.Actor, Event: audit.EventUserCreated,
		TargetType: "user", TargetID: u.ID.String(),
		Payload: map[string]any{"email": u.Email, "mfa": u.MFAEnabled},
	})
	return u, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, email, full_name,
		       mfa_enabled, status, last_login_at, created_at
		  FROM users WHERE id=$1`, id).
		Scan(&u.ID, &u.PlatformID, &u.PartnerID, &u.TenantID, &u.Email,
			&u.FullName, &u.MFAEnabled, &u.Status, &u.LastLoginAt, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// List returns users in a tenant, or across the partner if tenantID is nil.
func (s *Service) List(ctx context.Context, platformID uuid.UUID,
	partnerID *uuid.UUID, tenantID *uuid.UUID) ([]models.User, error) {
	args := []any{platformID}
	q := `SELECT id, platform_id, partner_id, tenant_id, email, full_name,
	             mfa_enabled, status, last_login_at, created_at
	        FROM users WHERE platform_id=$1`
	if partnerID != nil {
		q += fmt.Sprintf(" AND partner_id=$%d", len(args)+1)
		args = append(args, *partnerID)
	}
	if tenantID != nil {
		q += fmt.Sprintf(" AND tenant_id=$%d", len(args)+1)
		args = append(args, *tenantID)
	}
	q += " ORDER BY created_at DESC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.PlatformID, &u.PartnerID, &u.TenantID,
			&u.Email, &u.FullName, &u.MFAEnabled, &u.Status, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// AssignRole grants the named role to the user, optionally scoped to a
// partner or tenant. Blueprint §23.1 enforces that scope_level must match
// the role's scope_level — we leave that policy to the API layer.
type AssignRoleInput struct {
	UserID, RoleID uuid.UUID
	ScopePartner   *uuid.UUID
	ScopeTenant    *uuid.UUID
	GrantedBy      *uuid.UUID
}

func (s *Service) AssignRole(ctx context.Context, in AssignRoleInput) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_roles(user_id, role_id, scope_partner, scope_tenant, granted_by)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT DO NOTHING`,
		in.UserID, in.RoleID, in.ScopePartner, in.ScopeTenant, in.GrantedBy)
	if err != nil {
		return fmt.Errorf("users: assign role: %w", err)
	}
	var u models.User
	_ = s.pool.QueryRow(ctx,
		`SELECT platform_id, partner_id, tenant_id FROM users WHERE id=$1`, in.UserID).
		Scan(&u.PlatformID, &u.PartnerID, &u.TenantID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: u.PlatformID, PartnerID: u.PartnerID, TenantID: u.TenantID,
		ActorID: in.GrantedBy, Event: audit.EventRoleChanged,
		TargetType: "user", TargetID: in.UserID.String(),
		Payload: map[string]any{
			"role_id": in.RoleID,
			"scope_partner": in.ScopePartner, "scope_tenant": in.ScopeTenant,
		},
	})
}

// RevokeRole drops a (user, role, scope) tuple.
func (s *Service) RevokeRole(ctx context.Context, userID, roleID uuid.UUID,
	scopePartner *uuid.UUID, scopeTenant *uuid.UUID, actor *uuid.UUID) error {
	q := `DELETE FROM user_roles
	       WHERE user_id=$1 AND role_id=$2
	         AND COALESCE(scope_partner, '00000000-0000-0000-0000-000000000000'::uuid)
	             = COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
	         AND COALESCE(scope_tenant,  '00000000-0000-0000-0000-000000000000'::uuid)
	             = COALESCE($4::uuid, '00000000-0000-0000-0000-000000000000'::uuid)`
	if _, err := s.pool.Exec(ctx, q, userID, roleID, scopePartner, scopeTenant); err != nil {
		return err
	}
	var u models.User
	_ = s.pool.QueryRow(ctx,
		`SELECT platform_id FROM users WHERE id=$1`, userID).Scan(&u.PlatformID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: u.PlatformID, ActorID: actor, Event: audit.EventRoleChanged,
		TargetType: "user", TargetID: userID.String(),
		Payload: map[string]any{"role_id": roleID, "action": "revoked"},
	})
}

// RolesForUser returns the role codes granted to a user.
func (s *Service) RolesForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.code FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecordLogin writes both an audit_logs row (immutable, hash-chained) and
// a login_events row (queryable analytics). MFA-verified sessions are
// flagged so downstream consumers can gate sensitive actions.
func (s *Service) RecordLogin(ctx context.Context, in LoginEvent) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO login_events(user_id, email, success, ip, user_agent, mfa_used)
		VALUES ($1,$2,$3,$4::inet,$5,$6)`,
		in.UserID, in.Email, in.Success, ipOrNull(in.IP), nullIfEmpty(in.UserAgent), in.MFAUsed); err != nil {
		return err
	}
	if in.Success && in.UserID != nil {
		// Best-effort: update last_login_at; failure here doesn't block
		// the audit event below.
		_, _ = s.pool.Exec(ctx,
			`UPDATE users SET last_login_at=now() WHERE id=$1`, *in.UserID)
	}
	event := audit.EventLoginSuccess
	if !in.Success {
		event = audit.EventLoginFailed
	}
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: in.PlatformID, ActorID: in.UserID, Event: event,
		TargetType: "session", TargetID: in.Email,
		IP: in.IP, UserAgent: in.UserAgent,
		Payload: map[string]any{"mfa_used": in.MFAUsed, "success": in.Success},
	})
}

type LoginEvent struct {
	UserID     *uuid.UUID
	PlatformID uuid.UUID
	Email      string
	Success    bool
	MFAUsed    bool
	IP         net.IP
	UserAgent  string
	When       time.Time
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
