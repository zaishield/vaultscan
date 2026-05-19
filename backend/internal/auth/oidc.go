package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxNoRows is the sentinel for "no row returned" from pgx. We alias
// it here to keep call sites readable.
var pgxNoRows = pgx.ErrNoRows

// OIDCVerifier validates JWTs issued by an external OpenID Connect provider
// (Keycloak by default, but the same code works for Auth0, Okta, Entra,
// any provider that publishes a JWKS endpoint at .well-known).
//
// Verification rules:
//   1. Signature against a key from the issuer's JWKS (refreshed at most
//      once per cacheTTL).
//   2. `iss` matches the configured issuer.
//   3. `aud` contains the configured audience.
//   4. `exp` is in the future, `nbf` (if present) is in the past.
//   5. The user is not in token_revocations with min_iat > token.iat.
//   6. The user is not locked (users.locked_until > now()).
//   7. The user's tenant is not suspended.
type OIDCVerifier struct {
	issuer       string
	audience     string
	jwksURL      string
	pool         *pgxpool.Pool
	httpClient   *http.Client
	cacheTTL     time.Duration
	// allowedACR is the per-tenant allowlist of `acr` values that
	// satisfy MFA. Default {"mfa"} (the prior hardcode). Operators
	// can override via WithACRValues for IdPs that use a different
	// authentication-context vocabulary (e.g. ISO 29115 "loa3").
	allowedACR []string

	mu           sync.RWMutex
	keys         map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	keysFetchedAt time.Time
}

// NewOIDCVerifier constructs a verifier for the issuer.
//
// jwksPath is the relative URL path to the issuer's JWKS endpoint. If
// empty, the OIDC discovery default (/.well-known/jwks.json) is used.
// Callers that wire Keycloak can pass "/protocol/openid-connect/certs"
// explicitly. This replaces the previous Keycloak-only hardcode that
// made Auth0/Okta/Entra unusable without a code change.
func NewOIDCVerifier(issuer, audience string, pool *pgxpool.Pool, jwksPath ...string) *OIDCVerifier {
	canonicalIssuer := strings.TrimRight(issuer, "/")
	relPath := "/.well-known/jwks.json"
	if len(jwksPath) > 0 && jwksPath[0] != "" {
		relPath = jwksPath[0]
		if !strings.HasPrefix(relPath, "/") {
			relPath = "/" + relPath
		}
	}
	return &OIDCVerifier{
		issuer:     canonicalIssuer,
		audience:   audience,
		jwksURL:    canonicalIssuer + relPath,
		pool:       pool,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		cacheTTL:   10 * time.Minute,
		keys:       map[string]any{},
		allowedACR: []string{"mfa"},
	}
}

// WithACRValues replaces the allowed `acr` MFA values. Callers should
// pass the canonical strings their IdP emits (Keycloak: "mfa"; Entra:
// "mfa"; Okta: "phr"; ISO 29115 ranges like "loa3"). Tokens whose
// `acr` matches ANY listed value are considered MFA-verified.
func (v *OIDCVerifier) WithACRValues(values ...string) *OIDCVerifier {
	v.allowedACR = append([]string{}, values...)
	return v
}

// Parse validates the raw bearer token and returns the platform Identity.
// Returns a hard error on any failure; the API gateway maps to 401.
func (v *OIDCVerifier) Parse(ctx context.Context, raw string) (*Identity, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if raw == "" {
		return nil, errors.New("oidc: missing token")
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("oidc: token missing kid header")
		}
		key, err := v.lookupKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		// Lock the signing alg to what the JWKS advertises so we don't
		// silently accept HS256-with-public-key downgrade attacks.
		switch t.Method.Alg() {
		case "RS256", "RS384", "RS512":
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, errors.New("oidc: alg/key type mismatch (RSA)")
			}
		case "ES256", "ES384", "ES512":
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, errors.New("oidc: alg/key type mismatch (ECDSA)")
			}
		default:
			return nil, fmt.Errorf("oidc: unsupported alg %s", t.Method.Alg())
		}
		return key, nil
	}, jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("oidc: invalid token: %w", err)
	}
	// Manual issuer compare: jwt-go's WithIssuer does an exact string
	// match. Some IdPs publish their issuer with a trailing slash in
	// discovery but emit tokens WITHOUT it (and vice versa). Normalise
	// both sides before comparison so a legitimate token isn't
	// rejected just because the IdP's metadata vs. token emitter
	// disagree on a slash. The audience check that follows is the
	// rest of the binding.
	claims0, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("oidc: unexpected claims type")
	}
	tokIss := strings.TrimRight(stringClaim(claims0, "iss"), "/")
	if tokIss != v.issuer {
		return nil, fmt.Errorf("oidc: issuer %q does not match expected %q", tokIss, v.issuer)
	}
	claims := claims0
	// Audience: jwt-go's standard parsing already checks if WithAudience was
	// configured; we want a wider match so allow either string or []string.
	if !audienceMatches(claims, v.audience) {
		return nil, fmt.Errorf("oidc: audience %q not present", v.audience)
	}
	id := &Identity{Permissions: map[string]bool{}}
	if s, ok := claims["sub"].(string); ok {
		id.Email = stringClaim(claims, "preferred_username")
		if id.Email == "" {
			id.Email = stringClaim(claims, "email")
		}
		id.FullName = stringClaim(claims, "name")
		id.MFAVerified = boolClaim(claims, "mfa") || v.claimsHaveAllowedACR(claims)
		_ = s
	}
	// Map issuer-specific claims into our identity. Keycloak puts platform /
	// partner / tenant IDs into custom claims; we accept both flat and
	// realm_access-nested role lists.
	id.Roles = rolesFromClaims(claims)
	if platID, err := parseUUIDClaim(claims, "platform_id"); err == nil {
		id.PlatformID = uuid.UUID(platID)
	}
	if partID, err := parseUUIDClaim(claims, "partner_id"); err == nil {
		u := uuid.UUID(partID)
		id.PartnerID = &u
	}
	if tenID, err := parseUUIDClaim(claims, "tenant_id"); err == nil {
		u := uuid.UUID(tenID)
		id.TenantID = &u
	}
	if subID, err := parseUUIDClaim(claims, "sub"); err == nil {
		id.UserID = uuid.UUID(subID)
	}

	// Revocation + lockout + tenant-suspension checks.
	if v.pool != nil {
		if err := v.checkRevoked(ctx, id, claims); err != nil {
			return nil, err
		}
		if err := v.loadPermissions(ctx, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// lookupKey returns the cached JWKS key for kid, refreshing the JWKS once
// per cacheTTL or whenever an unknown kid lands.
func (v *OIDCVerifier) lookupKey(ctx context.Context, kid string) (any, error) {
	v.mu.RLock()
	if k, ok := v.keys[kid]; ok && time.Since(v.keysFetchedAt) < v.cacheTTL {
		v.mu.RUnlock()
		return k, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	// double-check after acquiring the write lock
	if k, ok := v.keys[kid]; ok && time.Since(v.keysFetchedAt) < v.cacheTTL {
		return k, nil
	}
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("oidc: unknown kid %q (refreshed JWKS)", kid)
}

// refreshJWKS pulls the issuer's JWKS endpoint and parses every key it
// returns into the cache.
//
// The JWKS URL must be https. http JWKS exposes us to MITM
// substitution of the issuer's public keys (an on-path attacker
// returns their own JWK; we now trust forged tokens). Localhost
// http is allowed for dev/testing — that's the documented escape
// hatch, and the production guard refuses to boot with a localhost
// issuer.
func (v *OIDCVerifier) refreshJWKS(ctx context.Context) error {
	if !strings.HasPrefix(v.jwksURL, "https://") && !isLocalJWKS(v.jwksURL) {
		return fmt.Errorf("oidc: jwks URL must be https (got %q)", v.jwksURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("oidc: jwks %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return err
	}
	var doc struct {
		Keys []struct {
			Kty, Kid, Alg, Use string
			N, E              string // RSA
			Crv, X, Y         string // ECDSA
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc: jwks parse: %w", err)
	}
	v.keys = map[string]any{}
	for _, k := range doc.Keys {
		switch strings.ToUpper(k.Kty) {
		case "RSA":
			pub, err := jwkRSAPublicKey(k.N, k.E)
			if err == nil && k.Kid != "" {
				v.keys[k.Kid] = pub
			}
		case "EC":
			pub, err := jwkECPublicKey(k.Crv, k.X, k.Y)
			if err == nil && k.Kid != "" {
				v.keys[k.Kid] = pub
			}
		}
	}
	v.keysFetchedAt = time.Now()
	return nil
}

func (v *OIDCVerifier) checkRevoked(ctx context.Context, id *Identity, claims jwt.MapClaims) error {
	iat, _ := claims["iat"].(float64)
	tokenIssuedAt := time.Unix(int64(iat), 0)

	// Fail-CLOSED on every Scan path here. The previous code used
	// `_ = pool.QueryRow(...).Scan(...)` which swallowed errors:
	// a DB outage silently bypassed the revocation/lockout/tenant-
	// suspension checks and let any token in. The right behavior
	// when the gating store is unavailable is to refuse — pgx returns
	// ErrNoRows when there's no row, which we map to "not revoked /
	// not locked / not suspended"; any OTHER error is treated as
	// "gating store unhealthy, refuse to let through".

	var minIAT *time.Time
	err := v.pool.QueryRow(ctx,
		`SELECT min_iat FROM token_revocations WHERE user_id=$1`, id.UserID).Scan(&minIAT)
	if err != nil && !errors.Is(err, pgxNoRows) {
		return fmt.Errorf("oidc: revocation lookup failed: %w", err)
	}
	if minIAT != nil && tokenIssuedAt.Before(*minIAT) {
		return errors.New("oidc: token revoked (issued before min_iat)")
	}

	// Lockout check.
	var locked *time.Time
	err = v.pool.QueryRow(ctx,
		`SELECT locked_until FROM users WHERE id=$1`, id.UserID).Scan(&locked)
	if err != nil && !errors.Is(err, pgxNoRows) {
		return fmt.Errorf("oidc: lockout lookup failed: %w", err)
	}
	if locked != nil && time.Now().Before(*locked) {
		return fmt.Errorf("oidc: account locked until %s", locked.Format(time.RFC3339))
	}

	// Tenant suspension.
	if id.TenantID != nil {
		var status string
		err = v.pool.QueryRow(ctx,
			`SELECT status FROM tenants WHERE id=$1`, *id.TenantID).Scan(&status)
		if err != nil && !errors.Is(err, pgxNoRows) {
			return fmt.Errorf("oidc: tenant status lookup failed: %w", err)
		}
		if status == "suspended" {
			return errors.New("oidc: tenant is suspended")
		}
	}
	return nil
}

// isLocalJWKS allows http://localhost / http://127.0.0.1 JWKS URLs
// in DEV ONLY. Production refuses regardless of host — a misconfigured
// production node that points jwks at localhost would otherwise let
// an attacker-served local JWKS forge identities.
//
// We check VAULTSCAN_ENV at the moment refreshJWKS is called rather
// than at NewOIDCVerifier construction so a test harness that flips
// the env later still gets dev semantics.
func isLocalJWKS(u string) bool {
	env := strings.ToLower(os.Getenv("VAULTSCAN_ENV"))
	if env == "production" || env == "prod" {
		return false
	}
	return strings.HasPrefix(u, "http://localhost") ||
		strings.HasPrefix(u, "http://127.0.0.1") ||
		strings.HasPrefix(u, "http://[::1]")
}

func (v *OIDCVerifier) loadPermissions(ctx context.Context, id *Identity) error {
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
		return fmt.Errorf("oidc: load permissions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err == nil {
			id.Permissions[c] = true
		}
	}
	return rows.Err()
}

// ----- claim plumbing ------------------------------------------------------

func audienceMatches(claims jwt.MapClaims, want string) bool {
	if want == "" {
		return true
	}
	switch a := claims["aud"].(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func stringClaim(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func boolClaim(claims jwt.MapClaims, key string) bool {
	if v, ok := claims[key].(bool); ok {
		return v
	}
	return false
}

// claimsHaveAllowedACR honours the verifier's allowedACR list (set
// via WithACRValues, default {"mfa"}). It additionally accepts
// `amr` containing canonical method codes — those are method-
// presence claims, not auth-context-class claims, so they're checked
// regardless of allowedACR.
func (v *OIDCVerifier) claimsHaveAllowedACR(claims jwt.MapClaims) bool {
	if a, ok := claims["acr"].(string); ok {
		for _, want := range v.allowedACR {
			if a == want {
				return true
			}
		}
	}
	if a, ok := claims["amr"].([]any); ok {
		for _, val := range a {
			if s, ok := val.(string); ok && (s == "mfa" || s == "totp" || s == "hwk") {
				return true
			}
		}
	}
	return false
}

func rolesFromClaims(claims jwt.MapClaims) []string {
	// Flat "roles" array.
	if r, ok := claims["roles"].([]any); ok {
		return stringSlice(r)
	}
	// Keycloak nests under realm_access.roles.
	if r, ok := claims["realm_access"].(map[string]any); ok {
		if rr, ok := r["roles"].([]any); ok {
			return stringSlice(rr)
		}
	}
	return nil
}

func stringSlice(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func parseUUIDClaim(claims jwt.MapClaims, key string) ([16]byte, error) {
	// Local minimal UUID parser avoids importing the uuid package in this
	// file. Returns the canonical 16-byte representation as a fixed array
	// so the caller can convert to uuid.UUID via a copy.
	s, _ := claims[key].(string)
	if s == "" {
		return [16]byte{}, errors.New("claim missing")
	}
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return [16]byte{}, errors.New("not a uuid")
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := clean[i*2+j]
			var nibble byte
			switch {
			case c >= '0' && c <= '9':
				nibble = c - '0'
			case c >= 'a' && c <= 'f':
				nibble = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				nibble = c - 'A' + 10
			default:
				return [16]byte{}, errors.New("uuid contains non-hex char")
			}
			b = b<<4 | nibble
		}
		out[i] = b
	}
	return out, nil
}

// ----- JWK decoding --------------------------------------------------------

func jwkRSAPublicKey(nB64u, eB64u string) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(nB64u)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64URLDecode(eB64u)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func jwkECPublicKey(crv, xB64u, yB64u string) (*ecdsa.PublicKey, error) {
	curve, err := curveByName(crv)
	if err != nil {
		return nil, err
	}
	x, err := base64URLDecode(xB64u)
	if err != nil {
		return nil, err
	}
	y, err := base64URLDecode(yB64u)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
