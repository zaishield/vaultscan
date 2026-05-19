package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VaultscanClaims is the JWT shape minted by the platform / accepted from Keycloak.
type VaultscanClaims struct {
	jwt.RegisteredClaims
	Email       string   `json:"email"`
	FullName    string   `json:"name"`
	PlatformID  string   `json:"platform_id"`
	PartnerID   string   `json:"partner_id,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Roles       []string `json:"roles"`
	MFA         bool     `json:"mfa"`

	// ImpersonationSessionID identifies a support-engineer
	// impersonation session. When set, the JWT's identity claims
	// reflect the TARGET (so RLS + permissions evaluate as the
	// customer would see), but every audit row also references
	// this session so VaultScan-side oversight can review.
	ImpersonationSessionID string `json:"impersonation_session_id,omitempty"`
	// OperatorID is the VaultScan-side support engineer who opened
	// the impersonation session. Empty for non-impersonated tokens.
	OperatorID string `json:"operator_id,omitempty"`
}

type Verifier struct {
	sharedSecret []byte
	pool         *pgxpool.Pool
	// expectedIssuer pins the JWT `iss` claim. Empty = no check
	// (dev default). Production wires via WithExpectedIssuer.
	expectedIssuer string
	// expectedAudience pins the JWT `aud` claim. Empty = no check.
	expectedAudience string
	// keyManager is optional. When set, tokens with alg=RS256 are
	// verified against jwt_signing_keys (routed by header kid).
	// Tokens with alg=HS256 keep using sharedSecret — production
	// flips to RS256 + JWKS but dev keeps the HS path for tests.
	keyManager *KeyManager
	// refuseHMAC forces Parse() to reject any HS256 token. Set via
	// WithRefuseHMAC() — typically called in production-mode boot so
	// the API only accepts RS256 from the configured KeyManager.
	refuseHMAC bool
}

func NewVerifier(sharedSecret string, pool *pgxpool.Pool) *Verifier {
	return &Verifier{sharedSecret: []byte(sharedSecret), pool: pool}
}

// WithKeyManager wires the RSA verifier path. Returns v for chain.
func (v *Verifier) WithKeyManager(km *KeyManager) *Verifier {
	v.keyManager = km
	return v
}

// WithRefuseHMAC turns on the production-mode lockdown: any HS256
// token is rejected even if sharedSecret would match. Callers wire
// this in production boot so HS256 dev tokens can never grant access
// against a production-configured API.
func (v *Verifier) WithRefuseHMAC(yes bool) *Verifier {
	v.refuseHMAC = yes
	return v
}

// WithExpectedIssuer pins the JWT `iss` claim. A token with a
// different (or missing) iss is rejected. Production deployments
// MUST set this so a token issued by one environment cannot be
// replayed against another that shares the HMAC secret. Empty =
// no check (dev default).
func (v *Verifier) WithExpectedIssuer(iss string) *Verifier {
	v.expectedIssuer = iss
	return v
}

// WithExpectedAudience pins the JWT `aud` claim. Empty = no check.
// Production sets this to the API's canonical URL so a token issued
// for the agent-gateway cannot be used against the public API
// (different audiences).
func (v *Verifier) WithExpectedAudience(aud string) *Verifier {
	v.expectedAudience = aud
	return v
}

func (v *Verifier) Parse(ctx context.Context, raw string) (*Identity, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if raw == "" {
		return nil, errors.New("auth: missing token")
	}
	claims := &VaultscanClaims{}
	// Allow up to 30s leeway on exp/nbf to absorb clock skew between
	// API pods and the issuer (Keycloak). Without leeway a 1ms-stale
	// clock rejects valid tokens at the boundary, surfacing as
	// flaky 401s for users who just refreshed.
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			// In production with a KeyManager wired, HS256 is the
			// dev-only path. Reject it so an attacker who exfiltrated
			// the shared secret (or who is replaying a dev token
			// against a prod env) can't forge identities. The
			// production guard ensures the secret is ≥32 random
			// bytes; this gate is the second line of defense.
			if v.refuseHMAC {
				return nil, errors.New("auth: HS256 disabled in production (use RS256 with kid)")
			}
			return v.sharedSecret, nil
		case *jwt.SigningMethodRSA:
			// jwt.SigningMethodRSA covers RS256, RS384 and RS512.
			// Pin RS256 explicitly — production issues RS256 only,
			// and accepting RS384/RS512 broadens the cross-product of
			// (alg × key) an attacker can confuse a verifier with.
			if t.Method.Alg() != "RS256" {
				return nil, fmt.Errorf("auth: RSA alg %q not allowed (only RS256)", t.Method.Alg())
			}
			if v.keyManager == nil {
				return nil, fmt.Errorf("RS256 token but no key manager wired")
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("RS256 token missing kid header")
			}
			pub, err := v.keyManager.PublicKeyByKID(ctx, kid)
			if err != nil {
				return nil, err
			}
			// Defense in depth: PublicKeyByKID returns *rsa.PublicKey
			// by type, so a nil-ness check is the meaningful guard
			// against a key lookup that succeeded with no key
			// installed (e.g. row in jwt_signing_keys but PEM blank).
			if pub == nil {
				return nil, errors.New("auth: key manager returned nil RSA key")
			}
			return pub, nil
		}
		// PS256/PS384/PS512 (RSA-PSS) and ES256/384/512 (ECDSA) end
		// up here — refuse them. We only issue RS256 and HS256; any
		// other alg in an incoming token is an adversary probe.
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}, jwt.WithLeeway(30*time.Second))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("auth: invalid token: %w", err)
	}
	// Issuer + audience binding. Empty expectedIssuer/Audience =
	// no check (preserves dev behaviour). Production wires both via
	// WithExpectedIssuer/WithExpectedAudience so a token issued for
	// env A cannot be replayed against env B with the same secret.
	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("auth: issuer mismatch: got %q, want %q",
			claims.Issuer, v.expectedIssuer)
	}
	if v.expectedAudience != "" {
		// jwt.MapClaims.GetAudience returns []string; here we use the
		// VaultscanClaims that embeds jwt.RegisteredClaims.Audience
		// which is also []string.
		matched := false
		for _, a := range claims.Audience {
			if a == v.expectedAudience {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("auth: audience mismatch: %v does not contain %q",
				[]string(claims.Audience), v.expectedAudience)
		}
	}
	id := &Identity{
		Email:       claims.Email,
		FullName:    claims.FullName,
		Roles:       claims.Roles,
		MFAVerified: claims.MFA,
		Permissions: map[string]bool{},

		ImpersonationSessionID: claims.ImpersonationSessionID,
		OperatorID:             claims.OperatorID,
	}
	if claims.Subject != "" {
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			return nil, fmt.Errorf("auth: bad subject uuid: %w", err)
		}
		id.UserID = uid
	}
	if claims.PlatformID != "" {
		pid, err := uuid.Parse(claims.PlatformID)
		if err != nil {
			return nil, fmt.Errorf("auth: bad platform_id: %w", err)
		}
		id.PlatformID = pid
	}
	if claims.PartnerID != "" {
		pid, err := uuid.Parse(claims.PartnerID)
		if err == nil {
			id.PartnerID = &pid
		}
	}
	if claims.TenantID != "" {
		tid, err := uuid.Parse(claims.TenantID)
		if err == nil {
			id.TenantID = &tid
		}
	}
	if v.pool != nil {
		if err := v.loadPermissions(ctx, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// IssueDevToken mints a development-only HS256 token. Production must use Keycloak.
func (v *Verifier) IssueDevToken(c VaultscanClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(v.sharedSecret)
}

// ImpersonationSession is the minimal shape IssueImpersonationToken
// needs. Mirrors impersonation.Session to avoid importing that
// package into auth (which would create a cycle).
type ImpersonationSession struct {
	ID           string
	OperatorID   string
	TargetUserID string
	TargetEmail  string
	TargetTenant string
	TargetRoles  []string
	PlatformID   string
	PartnerID    string
}

// IssueImpersonationToken mints a short-lived JWT whose identity
// claims reflect the TARGET user, with the impersonation session ID
// + operator ID embedded so every downstream audit row attributes
// both parties.
//
// Production lockdown: when refuseHMAC is set (production mode), an
// HS256 fallback is refused — impersonation tokens MUST be RS256.
// Otherwise an operator could mint impersonation tokens from a
// process that had no KeyManager wired, bypassing the JWKS path
// every other token goes through.
//
// MFA: the session adapter exposes OperatorMFAVerifiedFlag — the
// impersonation service stamps this to true ONLY after it has
// verified the operator completed their step-up MFA challenge.
// Trusting the session removes the previous hardcode.
//
// The TTL is the session's remaining lifetime; the impersonation
// service caps it at 60 min absolute.
func (v *Verifier) IssueImpersonationToken(s impersonationSessionLike, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("auth: impersonation ttl must be positive")
	}
	now := time.Now().UTC()
	c := VaultscanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   s.TargetUserIDStr(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
		Email:                  s.TargetEmailStr(),
		PlatformID:             s.PlatformIDStr(),
		PartnerID:              s.PartnerIDStr(),
		TenantID:               s.TargetTenantStr(),
		Roles:                  s.TargetRolesList(),
		MFA:                    s.OperatorMFAVerifiedFlag(),
		ImpersonationSessionID: s.IDStr(),
		OperatorID:             s.OperatorIDStr(),
	}
	if v.keyManager != nil {
		return v.IssueRSAToken(context.Background(), c)
	}
	if v.refuseHMAC {
		return "", errors.New("auth: production mode requires KeyManager for impersonation tokens; refusing HS256 fallback")
	}
	return v.IssueDevToken(c)
}

// impersonationSessionLike is the adapter interface. The HTTP
// handler builds it from an impersonation.Session; the indirection
// keeps the auth package import-cycle-free.
type impersonationSessionLike interface {
	IDStr() string
	OperatorIDStr() string
	TargetUserIDStr() string
	TargetEmailStr() string
	TargetTenantStr() string
	TargetRolesList() []string
	PlatformIDStr() string
	PartnerIDStr() string
	// OperatorMFAVerifiedFlag is true iff the impersonation service
	// has verified the operator completed step-up MFA before opening
	// the session. The auth package trusts the session's word here;
	// the impersonation service is responsible for not stamping this
	// without a real check.
	OperatorMFAVerifiedFlag() bool
}

// IssueRSAToken mints an RS256 token signed with the current active
// key from the KeyManager. The kid header is set so downstream
// verifiers (or external consumers) can pick the right JWK from
// /.well-known/jwks.json without trial-and-error.
func (v *Verifier) IssueRSAToken(ctx context.Context, c VaultscanClaims) (string, error) {
	if v.keyManager == nil {
		return "", errors.New("auth: no KeyManager wired; cannot issue RS256")
	}
	kid, priv, err := v.keyManager.ActivePrivateKey(ctx)
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	return tok.SignedString(priv)
}

func (v *Verifier) loadPermissions(ctx context.Context, id *Identity) error {
	if len(id.Roles) == 0 {
		return nil
	}
	rows, err := v.pool.Query(ctx, `
		SELECT DISTINCT p.code
		  FROM roles r
		  JOIN role_permissions rp ON rp.role_id = r.id
		  JOIN permissions p       ON p.id       = rp.permission_id
		 WHERE r.code = ANY($1)`, id.Roles)
	if err != nil {
		return fmt.Errorf("auth: load permissions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err == nil {
			id.Permissions[code] = true
		}
	}
	return rows.Err()
}
