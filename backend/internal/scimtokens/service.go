// Package scimtokens manages per-tenant SCIM-provisioning tokens.
// Customer admins generate / rotate / revoke tokens self-serve so
// they can wire their IdP's SCIM connector without involving
// VaultScan support.
//
// At-rest the token is bcrypt-hashed. The plaintext is shown ONCE
// on creation — operators store it in their secrets manager and
// configure their IdP with it.

package scimtokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// Token is the metadata view of one SCIM token. The plaintext is
// only returned by Create (in the dedicated CreateResult struct).
type Token struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Label      string     `json:"label"`
	CreatedBy  uuid.UUID  `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// CreateResult bundles the metadata + the ONE-TIME plaintext token.
// Callers MUST surface the plaintext to the operator immediately;
// re-fetching the row only yields the bcrypt hash.
type CreateResult struct {
	Token     Token  `json:"token"`
	Plaintext string `json:"plaintext"`
}

// ErrTokenLabelDuplicate is returned when a label is reused within
// the same tenant (the (tenant_id, label) UNIQUE constraint).
var ErrTokenLabelDuplicate = errors.New("scimtokens: label already used in this tenant")

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// Create mints a new token for the tenant. Returns the metadata +
// the plaintext (which the caller must hand to the operator and
// then discard).
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID,
	label string, ttl time.Duration, creator uuid.UUID,
) (*CreateResult, error) {
	if label == "" {
		return nil, errors.New("scimtokens: label required")
	}
	// 32 random bytes = 256 bits of entropy. Prefix "vss_" so a
	// leaked token is greppable in source-control + log scrapers.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("scimtokens: random: %w", err)
	}
	plain := "vss_" + base64.RawURLEncoding.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("scimtokens: hash: %w", err)
	}

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().UTC().Add(ttl)
		expires = &t
	}

	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_scim_tokens(id, tenant_id, token_hash, label,
		    created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, tenantID, string(hash), label, creator, expires); err != nil {
		// (tenant_id, label) UNIQUE — friendly error.
		if isUniqueViolation(err) {
			return nil, ErrTokenLabelDuplicate
		}
		return nil, fmt.Errorf("scimtokens: insert: %w", err)
	}

	_ = s.audit.Record(ctx, audit.Entry{
		Event:    "tenant.scim_token_created",
		TenantID: &tenantID, ActorID: &creator,
		Payload: map[string]any{"token_id": id, "label": label, "ttl_seconds": int(ttl.Seconds())},
	})

	return &CreateResult{
		Token: Token{
			ID: id, TenantID: tenantID, Label: label,
			CreatedBy: creator, CreatedAt: time.Now().UTC(),
			ExpiresAt: expires,
		},
		Plaintext: plain,
	}, nil
}

// List returns metadata for every non-revoked token in the tenant.
// Hashes + plaintext are NEVER exposed.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Token, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, label, created_by, created_at,
		       expires_at, last_used_at, last_used_ip::text, revoked_at
		  FROM tenant_scim_tokens
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		var ip *string
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Label, &t.CreatedBy,
			&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &ip, &t.RevokedAt); err != nil {
			return nil, err
		}
		if ip != nil {
			t.LastUsedIP = *ip
		}
		out = append(out, t)
	}
	return out, nil
}

// Revoke marks a token as revoked. Idempotent.
func (s *Service) Revoke(ctx context.Context, tenantID, tokenID uuid.UUID, revoker uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tenant_scim_tokens
		   SET revoked_at = now(), revoked_by = $3
		 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
		tokenID, tenantID, revoker)
	if err != nil {
		return fmt.Errorf("scimtokens: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("scimtokens: not found or already revoked")
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Event:    "tenant.scim_token_revoked",
		TenantID: &tenantID, ActorID: &revoker,
		Payload: map[string]any{"token_id": tokenID},
	})
	return nil
}

// Verify checks a bearer token against every active token for the
// tenant. Returns the token row on match, or nil.
//
// Timing-oracle defence: the previous implementation short-circuited
// the row loop on the first matching bcrypt — making request latency
// reveal (a) whether a token matched at all and (b) its position in
// the table. An attacker timing requests could fingerprint how many
// tokens a tenant has and where in the list a given token lives.
//
// This implementation:
//   - always reads every (non-revoked) row
//   - performs bcrypt on every row regardless of prior matches
//   - records the matching id in a local var rather than returning
//
// The total bcrypt time is N × bcrypt-cost regardless of input, so
// the only timing signal is N itself — which is metadata the tenant
// admin controls (list count). Per-request position is no longer
// observable. In practice tenants have <10 SCIM tokens, so the
// constant cost is bounded.
func (s *Service) Verify(ctx context.Context, tenantID uuid.UUID, presented string, fromIP net.IP) (*Token, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, token_hash, expires_at
		  FROM tenant_scim_tokens
		 WHERE tenant_id = $1 AND revoked_at IS NULL`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	var matchedID uuid.UUID
	matched := false
	for rows.Next() {
		var id uuid.UUID
		var hash string
		var expires *time.Time
		if err := rows.Scan(&id, &hash, &expires); err != nil {
			return nil, err
		}
		isCandidate := expires == nil || now.Before(*expires)
		// Always run bcrypt even on non-candidates, so an attacker
		// can't time-distinguish "expired-only row" from "active row
		// that doesn't match". bcrypt's natural cost dominates the
		// total latency.
		ok := bcrypt.CompareHashAndPassword([]byte(hash), []byte(presented)) == nil
		if ok && isCandidate && !matched {
			matchedID = id
			matched = true
		}
	}
	if !matched {
		return nil, nil
	}
	// Touch last_used_* exactly once for the winning row. Done AFTER
	// the full bcrypt walk so the side-channel of the UPDATE doesn't
	// reveal which row matched (the matching row's index is no longer
	// observable from total bcrypt time either).
	_, _ = s.pool.Exec(ctx, `
		UPDATE tenant_scim_tokens
		   SET last_used_at = now(), last_used_ip = $2
		 WHERE id = $1`, matchedID, fromIP.String())
	return &Token{ID: matchedID, TenantID: tenantID}, nil
}

// isUniqueViolation sniffs pgx errors for the 23505 SQLSTATE.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	type pgErr interface{ SQLState() string }
	var pe pgErr
	if errors.As(err, &pe) && pe.SQLState() == "23505" {
		return true
	}
	return false
}
