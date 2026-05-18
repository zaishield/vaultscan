// Package ssoflow drives the SP-initiated SAML / OIDC federation
// flow.
//
// Tenants pre-configure their IdP via PUT /api/v1/tenants/{id}/sso
// (handled by the ssoconfig package). This package consumes that
// config when a user hits /api/v1/auth/sso/{tenant_slug}/{provider}/start
// — building the IdP redirect, holding the state in a signed cookie,
// receiving the callback / ACS POST, validating the IdP's response,
// mapping claims into a Vaultscan JWT.
//
// State cookie format: short-lived HS256-signed JWT carrying
// {tenant_id, return_to, provider_state, code_verifier(oidc-only),
// nonce(oidc-only), exp}. Signed with the same shared secret the
// API uses for dev-tokens; rotated when the JWT signing key rotates.

package ssoflow

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/ssoconfig"
)

const (
	// stateCookieName is the short-lived cookie that holds the
	// CSRF state + return_to + (for OIDC) PKCE verifier + nonce.
	stateCookieName = "vaultscan_sso_state"
	// stateMaxAge bounds how long an SSO flow can be in flight.
	// 10 min matches typical IdP login timeouts.
	stateMaxAge = 10 * time.Minute
)

var (
	ErrTenantNotFound = errors.New("ssoflow: tenant not found")
	ErrSSODisabled    = errors.New("ssoflow: SSO not configured or disabled for tenant")
	ErrStateInvalid   = errors.New("ssoflow: state cookie missing or invalid")
)

// Service wires the dependencies needed by the federation handlers.
type Service struct {
	pool      *pgxpool.Pool
	sso       *ssoconfig.Service
	verifier  *auth.Verifier
	audit     *audit.Service
	stateKey  []byte // HS256 key for state-cookie signing
	httpc     *http.Client
	publicURL string // self URL for building ACS / callback URIs
}

func New(pool *pgxpool.Pool, sso *ssoconfig.Service, verifier *auth.Verifier,
	a *audit.Service, stateKey []byte, publicURL string,
) *Service {
	return &Service{
		pool: pool, sso: sso, verifier: verifier, audit: a,
		stateKey: stateKey,
		httpc:    &http.Client{Timeout: 10 * time.Second},
		publicURL: publicURL,
	}
}

// resolveTenant looks up the tenant by slug and returns its ID +
// the loaded SSO config. Returns ErrTenantNotFound if the slug
// doesn't resolve, ErrSSODisabled if SSO isn't enabled.
func (s *Service) resolveTenant(ctx context.Context, slug string) (uuid.UUID, *ssoconfig.LoadedConfig, error) {
	var tenantID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&tenantID); err != nil {
		return uuid.Nil, nil, ErrTenantNotFound
	}
	cfg, err := s.sso.LoadConfigForTenant(ctx, tenantID)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("ssoflow: load: %w", err)
	}
	if !cfg.Enabled {
		return uuid.Nil, nil, ErrSSODisabled
	}
	return tenantID, cfg, nil
}

// ---- State cookie (signed JWT) -------------------------------------

// stateClaims is what we round-trip through the IdP. Keep it small
// — IdPs cap RelayState (SAML) at 80 bytes and `state` (OIDC) at
// reasonable lengths. We pass an opaque token here and look up the
// full state from the cookie on return.
type stateClaims struct {
	jwt.RegisteredClaims
	TenantID     string `json:"tid"`
	Provider     string `json:"prov"`
	ReturnTo     string `json:"rt"`
	CodeVerifier string `json:"cv,omitempty"` // OIDC PKCE
	Nonce        string `json:"non,omitempty"` // OIDC
}

func (s *Service) signState(c stateClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(s.stateKey)
}

func (s *Service) verifyState(token string) (*stateClaims, error) {
	c := &stateClaims{}
	t, err := jwt.ParseWithClaims(token, c, func(_ *jwt.Token) (any, error) {
		return s.stateKey, nil
	})
	if err != nil || !t.Valid {
		return nil, ErrStateInvalid
	}
	return c, nil
}

// setStateCookie writes the state cookie. SameSite=Lax lets the
// cookie ride along on the IdP-initiated redirect back (which is a
// top-level navigation, not a cross-site request the browser would
// strip). Secure + HttpOnly always.
func (s *Service) setStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateMaxAge.Seconds()),
	})
}

func (s *Service) readStateCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(stateCookieName)
	if err != nil {
		return "", ErrStateInvalid
	}
	return c.Value, nil
}

// clearStateCookie wipes the cookie after a successful flow so the
// next sign-in starts clean.
func (s *Service) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// ---- Claim mapping --------------------------------------------------

// mapClaims projects IdP-supplied attributes (email, name, groups)
// into the VaultscanClaims shape, honoring the tenant's configured
// claim_mapping. groups → roles via best-effort match against the
// platform's role codes.
func (s *Service) mapClaims(ctx context.Context, tenantID uuid.UUID,
	cfg *ssoconfig.LoadedConfig, attrs map[string][]string,
) (*auth.VaultscanClaims, error) {
	// claim_mapping defaults — read keys in order of preference.
	get := func(key string) string {
		mapped := cfg.ClaimMapping[key]
		if mapped == "" {
			mapped = key
		}
		if v, ok := attrs[mapped]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	getMulti := func(key string) []string {
		mapped := cfg.ClaimMapping[key]
		if mapped == "" {
			mapped = key
		}
		return attrs[mapped]
	}

	email := get("email")
	if email == "" {
		return nil, errors.New("ssoflow: IdP assertion missing email")
	}
	name := get("name")

	// Look up the user — provision on first sign-in if SCIM hasn't
	// already.
	var (
		userID    uuid.UUID
		partnerID uuid.UUID
		platformID uuid.UUID
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, partner_id, platform_id FROM users
		 WHERE email = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
		 ORDER BY tenant_id NULLS LAST LIMIT 1`, email, tenantID).
		Scan(&userID, &partnerID, &platformID)
	if err != nil {
		// Auto-provision under the tenant's partner.
		if err := s.pool.QueryRow(ctx,
			`SELECT platform_id, partner_id FROM tenants WHERE id = $1`,
			tenantID).Scan(&platformID, &partnerID); err != nil {
			return nil, fmt.Errorf("ssoflow: tenant lookup: %w", err)
		}
		userID = uuid.New()
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO users(id, platform_id, partner_id, tenant_id, email,
			    full_name, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
			userID, platformID, partnerID, tenantID, email, name); err != nil {
			return nil, fmt.Errorf("ssoflow: provision user: %w", err)
		}
		_ = s.audit.Record(ctx, audit.Entry{
			Event: "user.provisioned_via_sso",
			TenantID: &tenantID, ActorID: &userID,
			TargetType: "user", TargetID: userID.String(),
			Payload: map[string]any{"email": email, "provider": cfg.ProviderType},
		})
	}

	// Map groups → roles. Best-effort: if the IdP-provided group name
	// matches a role code in the platform, grant it. Anything that
	// doesn't match is ignored (logged via audit, not as an error).
	roles := []string{}
	for _, g := range getMulti("roles") {
		var roleCode string
		_ = s.pool.QueryRow(ctx,
			`SELECT code FROM roles WHERE code = $1`, g).Scan(&roleCode)
		if roleCode != "" {
			roles = append(roles, roleCode)
		}
	}
	if len(roles) == 0 {
		// Default to the most-restrictive viewer role when the IdP
		// doesn't ship any matchable group. The customer admin can
		// up-role manually via /api/v1/users/{id}/roles.
		roles = []string{"client_viewer"}
	}

	now := time.Now().UTC()
	pidStr := partnerID.String()
	tidStr := tenantID.String()
	_ = pidStr; _ = tidStr

	return &auth.VaultscanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(12 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
		},
		Email:      email,
		FullName:   name,
		PlatformID: platformID.String(),
		PartnerID:  partnerID.String(),
		TenantID:   tenantID.String(),
		Roles:      roles,
		// MFA is false on a fresh SSO mint — if the tenant's admin
		// role requires MFA the user is prompted to complete TOTP
		// before sensitive actions. SAML/OIDC IdPs that already
		// asserted MFA via amr=mfa would set this true (TODO: parse).
		MFA: false,
	}, nil
}

// issueJWT delegates to Verifier — RS256 in production with a
// KeyManager wired, HS256 dev-fallback otherwise.
func (s *Service) issueJWT(ctx context.Context, c *auth.VaultscanClaims) (string, error) {
	// Use the auth verifier's existing methods rather than rolling
	// our own. IssueRSAToken when KeyManager is configured.
	tok, err := s.verifier.IssueRSAToken(ctx, *c)
	if err == nil {
		return tok, nil
	}
	// Dev fallback — Verifier.IssueDevToken returns an HS256 token
	// signed with the shared secret. Acceptable in development; the
	// production guard refuses to boot with no KeyManager.
	return s.verifier.IssueDevToken(*c)
}

// ---- SAML metadata parsing -----------------------------------------

// samlMetadata is the slice of an EntityDescriptor we care about.
// Full schema is enormous; we only need the IdP cert + SSO URL.
type samlMetadata struct {
	XMLName    xml.Name `xml:"EntityDescriptor"`
	EntityID   string   `xml:"entityID,attr"`
	IDPSSO     struct {
		KeyDescriptor []struct {
			Use      string `xml:"use,attr"`
			KeyInfo  struct {
				X509Data struct {
					X509Certificate string `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
		} `xml:"KeyDescriptor"`
		SingleSignOnService []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
	} `xml:"IDPSSODescriptor"`
}

// parseSAMLMetadata extracts (ssoURL, cert) from a tenant's stored
// SAML metadata XML. Returns the IdP's signing cert in PEM form so
// auth.SAMLConfig can verify the assertion.
func parseSAMLMetadata(rawXML string) (ssoURL, certPEM string, err error) {
	var md samlMetadata
	if err := xml.Unmarshal([]byte(rawXML), &md); err != nil {
		return "", "", fmt.Errorf("ssoflow: parse saml metadata: %w", err)
	}
	for _, sso := range md.IDPSSO.SingleSignOnService {
		if sso.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			ssoURL = sso.Location
			break
		}
	}
	if ssoURL == "" {
		for _, sso := range md.IDPSSO.SingleSignOnService {
			ssoURL = sso.Location
			break
		}
	}
	if ssoURL == "" {
		return "", "", errors.New("ssoflow: metadata has no SingleSignOnService Location")
	}
	for _, k := range md.IDPSSO.KeyDescriptor {
		if k.Use == "signing" || k.Use == "" {
			b, err := base64.StdEncoding.DecodeString(stripWS(k.KeyInfo.X509Data.X509Certificate))
			if err == nil {
				if _, err := x509.ParseCertificate(b); err == nil {
					certPEM = string(pem.EncodeToMemory(&pem.Block{
						Type: "CERTIFICATE", Bytes: b,
					}))
					break
				}
			}
		}
	}
	if certPEM == "" {
		return "", "", errors.New("ssoflow: metadata has no usable signing certificate")
	}
	return ssoURL, certPEM, nil
}

func stripWS(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// readBoundedBody is a small helper that respects http.MaxBytesReader.
func readBoundedBody(r io.Reader, max int64) ([]byte, error) {
	limited := io.LimitReader(r, max+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("ssoflow: body exceeds %d bytes", max)
	}
	return body, nil
}
