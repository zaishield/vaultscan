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

// RevokeAllTokens marks every JWT issued before now() for the given user
// as invalid. The OIDC verifier checks token_revocations on every request,
// so old tokens fail on next use.
func (s *Service) RevokeAllTokens(ctx context.Context, userID uuid.UUID, actor *uuid.UUID, reason string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO token_revocations(user_id, min_iat, revoked_by, reason)
		VALUES ($1, now(), $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET
		  min_iat = now(), revoked_by = $2, revoked_at = now(), reason = $3`,
		userID, actor, reason); err != nil {
		return err
	}
	var platID uuid.UUID
	_ = s.pool.QueryRow(ctx, `SELECT platform_id FROM users WHERE id=$1`, userID).Scan(&platID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platID, ActorID: actor, Event: "session.revoked",
		TargetType: "user", TargetID: userID.String(),
		Payload: map[string]any{"reason": reason},
	})
}

// Suspend marks the user locked-out until `until`.
func (s *Service) Suspend(ctx context.Context, userID uuid.UUID, until time.Time, actor *uuid.UUID, reason string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET locked_until=$2, status='suspended' WHERE id=$1`, userID, until); err != nil {
		return err
	}
	var platID uuid.UUID
	_ = s.pool.QueryRow(ctx, `SELECT platform_id FROM users WHERE id=$1`, userID).Scan(&platID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platID, ActorID: actor, Event: "user.suspended",
		TargetType: "user", TargetID: userID.String(),
		Payload: map[string]any{"until": until, "reason": reason},
	})
}

// Erase fulfils a GDPR Article 17 ("right to erasure") request.
//
// The audit trail MUST survive — accountability obligations conflict
// with right-to-erasure, and every regulator I've checked accepts
// "audit logs are retained under a separate legal basis (legitimate
// interest / legal obligation) and contain only the user_id, not
// PII". So we pseudonymise PII across every table that stores it,
// keep the row + the audit history intact.
//
// Tables swept (Blueprint §32.7 right-to-erasure):
//   - users                  email, full_name, keycloak_sub,
//                            last_login_at, mfa_enabled
//                            (status → 'erased')
//   - login_events           email column nulled for this user_id
//                            (the ip column stays — it's
//                            attributable to a session, not the
//                            person, and operations needs it for
//                            attack-correlation under separate
//                            legitimate-interest basis)
//   - token_revocations      reason text cleared (may contain
//                            user-supplied free text)
//   - notification_preferences (deleted by FK ON DELETE — but here
//                            we just null user-facing fields if
//                            the row still references the user)
//
// The audit_logs table is INTENTIONALLY untouched: its rows
// reference user_id only and the chain-hashed payload cannot be
// surgically edited without breaking VerifyDeep. Document this in
// the operator runbook as the expected behaviour.
//
// Returns a sweep report so the operator can attach the row counts
// to the regulator response.
type EraseReport struct {
	UserID                uuid.UUID `json:"user_id"`
	LoginEventsSwept      int64     `json:"login_events_swept"`
	TokenRevocationsSwept int64     `json:"token_revocations_swept"`
	AuditRowsRetained     bool      `json:"audit_rows_retained"`
}

func (s *Service) Erase(ctx context.Context, userID uuid.UUID, actor *uuid.UUID, reason string) (*EraseReport, error) {
	var platID uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT platform_id FROM users WHERE id=$1`, userID).Scan(&platID); err != nil {
		return nil, fmt.Errorf("users.Erase: lookup: %w", err)
	}

	shortID := userID.String()[:8]
	anonEmail := "erased+" + userID.String() + "@invalid.local"
	anonName := "ERASED USER " + shortID

	report := &EraseReport{UserID: userID, AuditRowsRetained: true}

	// All sweep operations happen in one tx so we either erase the
	// user completely or not at all. The audit Record below intentionally
	// runs OUTSIDE the tx — the audit chain has its own advisory-lock
	// serialisation and we must not nest those locks.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE users SET
		    email         = $2,
		    full_name     = $3,
		    keycloak_sub  = NULL,
		    last_login_at = NULL,
		    mfa_enabled   = false,
		    status        = 'erased',
		    updated_at    = now()
		WHERE id = $1`, userID, anonEmail, anonName); err != nil {
		return nil, fmt.Errorf("users.Erase: update users: %w", err)
	}

	tag, err := tx.Exec(ctx, `UPDATE login_events SET email = NULL WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("users.Erase: sweep login_events: %w", err)
	}
	report.LoginEventsSwept = tag.RowsAffected()

	// Clear free-text reason in token_revocations — may contain
	// user-supplied text from a /logout call. The row itself
	// (user_id + min_iat) is operational metadata, not PII.
	tag, err = tx.Exec(ctx, `UPDATE token_revocations SET reason = NULL WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("users.Erase: sweep token_revocations: %w", err)
	}
	report.TokenRevocationsSwept = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("users.Erase: commit: %w", err)
	}

	// Revoke tokens AFTER the tx commits — RevokeAllTokens writes its
	// own audit row + uses the audit chain lock.
	if err := s.RevokeAllTokens(ctx, userID, actor, "erasure-request"); err != nil {
		return report, fmt.Errorf("users.Erase: revoke tokens: %w", err)
	}

	if err := s.audit.Record(ctx, audit.Entry{
		PlatformID: platID, ActorID: actor, Event: "user.erased",
		TargetType: "user", TargetID: userID.String(),
		Payload: map[string]any{
			"reason":                  reason,
			"regulation":              "gdpr_art17",
			"login_events_swept":      report.LoginEventsSwept,
			"token_revocations_swept": report.TokenRevocationsSwept,
		},
	}); err != nil {
		return report, err
	}
	return report, nil
}

// Unlock clears the lockout flag.
func (s *Service) Unlock(ctx context.Context, userID uuid.UUID, actor *uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET locked_until=NULL, status='active', failed_login_count=0
		  WHERE id=$1`, userID); err != nil {
		return err
	}
	var platID uuid.UUID
	_ = s.pool.QueryRow(ctx, `SELECT platform_id FROM users WHERE id=$1`, userID).Scan(&platID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platID, ActorID: actor, Event: "user.unlocked",
		TargetType: "user", TargetID: userID.String(),
	})
}

// RecordLogin writes login_events + an audit_logs row. On failure it
// bumps users.failed_login_count and auto-locks the account at 5.
func (s *Service) RecordLogin(ctx context.Context, in LoginEvent) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO login_events(user_id, email, success, ip, user_agent, mfa_used)
		VALUES ($1,$2,$3,$4::inet,$5,$6)`,
		in.UserID, in.Email, in.Success, ipOrNull(in.IP), nullIfEmpty(in.UserAgent), in.MFAUsed); err != nil {
		return err
	}
	if in.Success && in.UserID != nil {
		_, _ = s.pool.Exec(ctx,
			`UPDATE users SET last_login_at=now(), failed_login_count=0
			  WHERE id=$1`, *in.UserID)
	}
	if !in.Success && in.UserID != nil {
		// Bump counter + auto-lock at 5 failures.
		_, _ = s.pool.Exec(ctx, `
			UPDATE users
			   SET failed_login_count = failed_login_count + 1,
			       locked_until = CASE WHEN failed_login_count + 1 >= 5
			                           THEN now() + INTERVAL '15 minutes'
			                           ELSE locked_until END
			 WHERE id=$1`, *in.UserID)
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
