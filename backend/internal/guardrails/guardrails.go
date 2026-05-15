// Package guardrails implements the operational guardrails from Blueprint
// §36 (HS-05): maintenance mode, break-glass tokens, and the
// never_allow / always_require policy engine.
package guardrails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// ----- Maintenance mode ----------------------------------------------------

type MaintenanceState struct {
	Enabled       bool       `json:"enabled"`
	Reason        string     `json:"reason,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	ExpectedEnd   *time.Time `json:"expected_end_at,omitempty"`
	LastChangedBy *uuid.UUID `json:"last_changed_by,omitempty"`
	LastChangedAt time.Time  `json:"last_changed_at"`
}

func (s *Service) MaintenanceStatus(ctx context.Context) (MaintenanceState, error) {
	var st MaintenanceState
	var reason *string
	err := s.pool.QueryRow(ctx, `
		SELECT enabled, reason, started_at, expected_end_at,
		       last_changed_by, last_changed_at
		  FROM platform_maintenance ORDER BY last_changed_at DESC LIMIT 1`).
		Scan(&st.Enabled, &reason, &st.StartedAt, &st.ExpectedEnd,
			&st.LastChangedBy, &st.LastChangedAt)
	if err != nil {
		return st, err
	}
	if reason != nil {
		st.Reason = *reason
	}
	return st, nil
}

func (s *Service) SetMaintenance(ctx context.Context, actor *uuid.UUID, on bool, reason string, expectedEnd *time.Time, ip net.IP) error {
	if on && reason == "" {
		return errors.New("guardrails: maintenance requires a reason")
	}
	now := time.Now().UTC()
	var startedAt any
	if on {
		startedAt = now
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE platform_maintenance
		   SET enabled         = $1,
		       reason          = $2,
		       started_at      = COALESCE($3, started_at),
		       expected_end_at = $4,
		       last_changed_by = $5,
		       last_changed_at = now()
		 WHERE id = (SELECT id FROM platform_maintenance LIMIT 1)`,
		on, nullIfEmpty(reason), startedAt, expectedEnd, actor)
	if err != nil {
		return err
	}
	event := "platform.maintenance.disabled"
	if on {
		event = "platform.maintenance.enabled"
	}
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		ActorID: actor, Event: event, IP: ip,
		TargetType: "platform", TargetID: "maintenance",
		Payload: map[string]any{
			"on": on, "reason": reason, "expected_end_at": expectedEnd,
		},
	})
}

// IsWriteAllowed is what middleware calls on every write. Returns
// (allowed, reason). `actorPermissions` is the resolved RBAC set —
// presence of `maintenance.override` bypasses the gate.
func (s *Service) IsWriteAllowed(ctx context.Context, actorPermissions map[string]bool) (bool, MaintenanceState, error) {
	st, err := s.MaintenanceStatus(ctx)
	if err != nil {
		return true, st, err // fail open on lookup error — Postgres being down is its own incident
	}
	if !st.Enabled {
		return true, st, nil
	}
	if actorPermissions["maintenance.override"] {
		return true, st, nil
	}
	return false, st, nil
}

// ----- Break-glass tokens --------------------------------------------------

type BreakGlassToken struct {
	ID         uuid.UUID `json:"id"`
	Permission string    `json:"granted_permission"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// IssueBreakGlass mints a one-time token. The returned string is shown
// once to the issuer; only its bcrypt hash is persisted.
func (s *Service) IssueBreakGlass(ctx context.Context, issuer uuid.UUID, permission, reason string, ttl time.Duration) (BreakGlassToken, string, error) {
	if permission == "" || reason == "" {
		return BreakGlassToken{}, "", errors.New("guardrails: permission + reason required")
	}
	if ttl <= 0 || ttl > 4*time.Hour {
		return BreakGlassToken{}, "", errors.New("guardrails: TTL must be in (0, 4h]")
	}
	raw := newToken()
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return BreakGlassToken{}, "", err
	}
	var t BreakGlassToken
	t.Permission = permission
	t.Reason = reason
	t.ExpiresAt = time.Now().UTC().Add(ttl)
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO break_glass_tokens(issuer_id, granted_permission, reason,
		    token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		issuer, permission, reason, string(hash), t.ExpiresAt).
		Scan(&t.ID); err != nil {
		return BreakGlassToken{}, "", err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		ActorID: &issuer, Event: "platform.break_glass.issued",
		TargetType: "break_glass_token", TargetID: t.ID.String(),
		Payload: map[string]any{"permission": permission, "reason": reason,
			"expires_at": t.ExpiresAt},
	})
	return t, raw, nil
}

// RedeemBreakGlass consumes a token. Returns the granted permission +
// the issuer id. Mutates redeemed_at so a second redemption fails.
func (s *Service) RedeemBreakGlass(ctx context.Context, raw string, redeemer *uuid.UUID, ip net.IP) (string, uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT id, issuer_id, granted_permission, reason, token_hash, expires_at
		  FROM break_glass_tokens
		 WHERE redeemed_at IS NULL AND expires_at > now()`)
	if err != nil {
		return "", uuid.Nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id       uuid.UUID
			issuer   uuid.UUID
			perm     string
			reason   string
			hash     string
			expires  time.Time
		)
		if err := rows.Scan(&id, &issuer, &perm, &reason, &hash, &expires); err != nil {
			return "", uuid.Nil, err
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) != nil {
			continue
		}
		rows.Close()
		if _, err := tx.Exec(ctx, `
			UPDATE break_glass_tokens
			   SET redeemed_at=now(), redeemed_by=$2, redeemed_ip=$3::inet
			 WHERE id=$1`, id, redeemer, ipOrNull(ip)); err != nil {
			return "", uuid.Nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", uuid.Nil, err
		}
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
			ActorID: redeemer, Event: "platform.break_glass.redeemed", IP: ip,
			TargetType: "break_glass_token", TargetID: id.String(),
			Payload: map[string]any{"permission": perm, "issuer": issuer, "reason": reason},
		})
		return perm, issuer, nil
	}
	return "", uuid.Nil, errors.New("guardrails: no matching active break-glass token")
}

// ----- Policy rule engine --------------------------------------------------

type Rule struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Class       string    `json:"rule_class"`
	Subject     string    `json:"subject"`
	Condition   map[string]any `json:"condition"`
	Verdict     string    `json:"verdict"`
}

func (s *Service) Rules(ctx context.Context, subject string) ([]Rule, error) {
	q := `SELECT id, name, description, rule_class, subject, condition, verdict
	        FROM platform_policy_rules
	       WHERE enabled = true`
	args := []any{}
	if subject != "" {
		q += " AND subject=$1"
		args = append(args, subject)
	}
	// never_allow rules fire before always_require so an explicit
	// "deny" beats an "and you also forgot to set X" message.
	q += " ORDER BY (CASE rule_class WHEN 'never_allow' THEN 0 ELSE 1 END), name"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var cond []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Class, &r.Subject,
			&cond, &r.Verdict); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cond, &r.Condition)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Decision is what Evaluate returns.
type Decision struct {
	Allowed  bool   `json:"allowed"`
	Rule     string `json:"rule,omitempty"`     // name of the rule that fired
	Verdict  string `json:"verdict,omitempty"`  // deny | require | warn
	Reason   string `json:"reason,omitempty"`
}

// Evaluate matches `facts` against every active rule for the subject.
// `never_allow` rules whose condition fully matches → Decision{Allowed:false}.
// `always_require` rules whose `requires` field is missing from facts →
// Decision{Allowed:false}. First match wins; otherwise allowed.
func (s *Service) Evaluate(ctx context.Context, subject string, facts map[string]any) (Decision, error) {
	rules, err := s.Rules(ctx, subject)
	if err != nil {
		return Decision{Allowed: true}, err
	}
	for _, r := range rules {
		switch r.Class {
		case "never_allow":
			if matchesCondition(r.Condition, facts) {
				return Decision{
					Allowed: false, Rule: r.Name, Verdict: r.Verdict,
					Reason: r.Description,
				}, nil
			}
		case "always_require":
			if req, ok := r.Condition["requires"].(string); ok {
				if !hasFact(facts, req) {
					return Decision{
						Allowed: false, Rule: r.Name, Verdict: r.Verdict,
						Reason: "missing required fact: " + req,
					}, nil
				}
			}
		}
	}
	return Decision{Allowed: true}, nil
}

// matchesCondition returns true when every key/value in cond is present
// in facts with an equal value. nil values in cond match a missing key
// in facts (e.g. {"actor_id":null} matches "no actor in context").
func matchesCondition(cond, facts map[string]any) bool {
	for k, want := range cond {
		got, present := facts[k]
		if want == nil {
			if present && got != nil {
				return false
			}
			continue
		}
		if !present {
			return false
		}
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			return false
		}
	}
	return true
}

func hasFact(facts map[string]any, key string) bool {
	v, ok := facts[key]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	default:
		return true
	}
}

// ----- helpers -------------------------------------------------------------

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

var _ = pgx.ErrNoRows
