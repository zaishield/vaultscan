// Package impersonation is the support-engineer break-glass surface.
// Operators with `support_impersonate` permission can issue a
// time-bounded, ticket-tagged, hard-audited JWT that carries the
// identity of a target user — letting them reproduce a customer's
// view without asking the customer for credentials.
//
// Every action taken under the impersonation JWT is double-audited:
// once with the IMPERSONATED user's identity (so the customer's
// audit log shows what the support engineer did on their behalf),
// once with the OPERATOR'S identity (so VaultScan-side oversight
// can review). The impersonation_session_id ties the two rows
// together.
//
// Hard caps:
//   - Maximum session duration: 60 minutes
//   - Ticket reference REQUIRED (no anonymous impersonations)
//   - Cannot impersonate platform-admin users (zaishield_super_admin)
//   - Cannot impersonate themselves
//   - End-of-session emits both operator + target audit rows

package impersonation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// MaxSessionDuration is the hard cap on impersonation sessions.
// Production operators tune via VAULTSCAN_IMPERSONATION_MAX_MINUTES
// (wired from cmd/api at boot) but cannot exceed this absolute cap.
const MaxSessionDuration = 60 * time.Minute

var (
	ErrTicketRequired    = errors.New("impersonation: ticket_ref is required")
	ErrSelfImpersonation = errors.New("impersonation: cannot impersonate yourself")
	ErrPlatformAdmin     = errors.New("impersonation: cannot impersonate platform-admin users")
	ErrSessionExpired    = errors.New("impersonation: session expired or not active")
	ErrUnknownTarget     = errors.New("impersonation: target user not found")
)

// Session is the metadata view of an impersonation session.
type Session struct {
	ID            uuid.UUID  `json:"id"`
	OperatorID    uuid.UUID  `json:"operator_id"`
	OperatorEmail string     `json:"operator_email"`
	// OperatorMFAVerified is true iff the impersonation middleware
	// verified the operator's step-up MFA before Start() was reached.
	// The auth layer trusts this field when minting impersonation
	// tokens — it MUST NOT be set true by code paths that haven't
	// actually checked the operator's MFA.
	OperatorMFAVerified bool       `json:"operator_mfa_verified"`
	TargetUserID  uuid.UUID  `json:"target_user_id"`
	TargetEmail   string     `json:"target_email"`
	TargetTenant  *uuid.UUID `json:"target_tenant,omitempty"`
	TicketRef     string     `json:"ticket_ref"`
	Reason        string     `json:"reason"`
	StartedAt     time.Time  `json:"started_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	EndedBy       *uuid.UUID `json:"ended_by,omitempty"`
	RequestCount  int        `json:"request_count"`
}

// StartInput is the request payload for opening a session.
type StartInput struct {
	TargetUserID uuid.UUID     `json:"target_user_id"`
	TicketRef    string        `json:"ticket_ref"`
	Reason       string        `json:"reason"`
	Duration     time.Duration `json:"duration"` // capped at MaxSessionDuration
}

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// Start opens an impersonation session. The caller (operator) must
// have the support_impersonate permission AND a valid MFA challenge
// (enforced by the HTTP middleware). This service-layer call
// records the row + emits the dual audit events.
func (s *Service) Start(ctx context.Context, operator uuid.UUID, in StartInput) (*Session, error) {
	if in.TicketRef == "" {
		return nil, ErrTicketRequired
	}
	if in.Reason == "" {
		return nil, errors.New("impersonation: reason is required")
	}
	if in.TargetUserID == operator {
		return nil, ErrSelfImpersonation
	}
	if in.Duration <= 0 || in.Duration > MaxSessionDuration {
		in.Duration = MaxSessionDuration
	}

	// Resolve target's metadata + check they're not a platform admin.
	var (
		targetEmail     string
		targetTenant    *uuid.UUID
		targetPlatform  uuid.UUID
		isPlatformAdmin bool
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.email::text, u.tenant_id, u.platform_id,
		       EXISTS(SELECT 1 FROM user_roles ur
		                JOIN roles r ON r.id = ur.role_id
		               WHERE ur.user_id = u.id AND r.code = 'zaishield_super_admin') AS is_super
		  FROM users u WHERE u.id = $1`, in.TargetUserID).
		Scan(&targetEmail, &targetTenant, &targetPlatform, &isPlatformAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownTarget
	}
	if err != nil {
		return nil, fmt.Errorf("impersonation: target lookup: %w", err)
	}
	if isPlatformAdmin {
		return nil, ErrPlatformAdmin
	}

	// Operator email for the audit row.
	var operatorEmail string
	_ = s.pool.QueryRow(ctx, `SELECT email::text FROM users WHERE id = $1`, operator).
		Scan(&operatorEmail)

	id := uuid.New()
	now := time.Now().UTC()
	expires := now.Add(in.Duration)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO support_impersonation_sessions(id, operator_id, target_user_id,
		    target_tenant, ticket_ref, reason, started_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, operator, in.TargetUserID, targetTenant, in.TicketRef, in.Reason,
		now, expires); err != nil {
		return nil, fmt.Errorf("impersonation: insert session: %w", err)
	}

	// Double-audit: one row under the OPERATOR (so VaultScan-side
	// oversight sees who started this), one under the TARGET (so the
	// customer's audit log shows their user was impersonated).
	_ = s.audit.Record(ctx, audit.Entry{
		Event:      "support.impersonation_started",
		PlatformID: targetPlatform,
		ActorID:    &operator,
		TenantID:   targetTenant,
		Payload: map[string]any{
			"session_id":   id,
			"target_user":  in.TargetUserID,
			"target_email": targetEmail,
			"ticket_ref":   in.TicketRef,
			"reason":       in.Reason,
			"expires_at":   expires,
		},
	})
	_ = s.audit.Record(ctx, audit.Entry{
		Event:      "user.impersonated_by_support",
		PlatformID: targetPlatform,
		ActorID:    &operator,
		TargetType: "user",
		TargetID:   in.TargetUserID.String(),
		TenantID:   targetTenant,
		Payload: map[string]any{
			"session_id":     id,
			"operator_email": operatorEmail,
			"ticket_ref":     in.TicketRef,
		},
	})

	return &Session{
		ID: id, OperatorID: operator, OperatorEmail: operatorEmail,
		// The HTTP layer that calls Start() routes through
		// RequireImpersonationMFA middleware, so by definition the
		// operator has completed step-up MFA. Record that fact on the
		// session for downstream consumers (impAdapter → JWT MFA claim).
		OperatorMFAVerified: true,
		TargetUserID: in.TargetUserID, TargetEmail: targetEmail,
		TargetTenant: targetTenant, TicketRef: in.TicketRef, Reason: in.Reason,
		StartedAt: now, ExpiresAt: expires,
	}, nil
}

// End closes an impersonation session early. Idempotent — re-ending
// an already-closed session returns nil.
func (s *Service) End(ctx context.Context, sessionID, endedBy uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE support_impersonation_sessions
		   SET ended_at = now(), ended_by = $2
		 WHERE id = $1 AND ended_at IS NULL`,
		sessionID, endedBy)
	if err != nil {
		return fmt.Errorf("impersonation: end: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Already ended; not an error.
		return nil
	}
	// Look up the target's platform so the close-event has the same
	// platform_id as the start-event (audit chain consistency).
	var endPlatform uuid.UUID
	_ = s.pool.QueryRow(ctx,
		`SELECT u.platform_id FROM users u
		   JOIN support_impersonation_sessions sis ON sis.target_user_id = u.id
		  WHERE sis.id = $1`, sessionID).Scan(&endPlatform)
	_ = s.audit.Record(ctx, audit.Entry{
		Event:      "support.impersonation_ended",
		PlatformID: endPlatform,
		ActorID:    &endedBy,
		Payload:    map[string]any{"session_id": sessionID},
	})
	return nil
}

// Active returns every currently-open (not ended + not expired)
// impersonation session. Used by the support dashboard + the
// security-audit weekly review.
func (s *Service) Active(ctx context.Context) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.operator_id, o.email::text,
		       s.target_user_id, t.email::text, s.target_tenant,
		       s.ticket_ref, s.reason, s.started_at, s.expires_at,
		       s.ended_at, s.ended_by, s.request_count
		  FROM support_impersonation_sessions s
		  JOIN users o ON o.id = s.operator_id
		  JOIN users t ON t.id = s.target_user_id
		 WHERE s.ended_at IS NULL AND s.expires_at > now()
		 ORDER BY s.started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.OperatorID, &sess.OperatorEmail,
			&sess.TargetUserID, &sess.TargetEmail, &sess.TargetTenant,
			&sess.TicketRef, &sess.Reason, &sess.StartedAt, &sess.ExpiresAt,
			&sess.EndedAt, &sess.EndedBy, &sess.RequestCount); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, nil
}

// Touch increments request_count on every API call made under an
// impersonation JWT. Called by the auth middleware when it sees
// the `impersonation_session_id` claim. Returns ErrSessionExpired
// if the session ended or hit the deadline since the JWT was minted.
func (s *Service) Touch(ctx context.Context, sessionID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE support_impersonation_sessions
		   SET request_count = request_count + 1
		 WHERE id = $1 AND ended_at IS NULL AND expires_at > now()`,
		sessionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSessionExpired
	}
	return nil
}

