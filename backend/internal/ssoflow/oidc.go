// oidc.go — SP-initiated OIDC Authorization Code + PKCE flow.
//
// Two endpoints:
//   GET /api/v1/auth/sso/{tenant_slug}/oidc/start
//     - resolves tenant + loads stored discovery_url + client_id
//     - fetches the IdP's discovery doc (cached)
//     - generates a state, nonce, PKCE verifier + challenge
//     - drops a signed state cookie carrying tenant_id + return_to
//       + the PKCE verifier + nonce
//     - 302 redirects to the IdP's authorization_endpoint with
//       response_type=code, scope=openid profile email, state,
//       nonce, code_challenge, code_challenge_method=S256
//
//   GET /api/v1/auth/sso/{tenant_slug}/oidc/callback
//     - reads the state cookie + the ?code+state from the IdP
//     - POSTs to the IdP's token_endpoint to exchange code for tokens
//     - verifies the id_token signature + audience + nonce via the
//       OIDCVerifier
//     - maps claims into VaultscanClaims
//     - mints a JWT
//     - redirects to state.return_to with the JWT in a session cookie

package ssoflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oidcDiscovery is the small slice of the OIDC discovery doc we use.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
}

// discoveryCache memoises fetches by discovery URL. The OIDC spec
// says clients SHOULD cache for at least 24h; we cache for 12h to
// pick up IdP-side rotations sooner.
type discoveryCache struct {
	mu sync.RWMutex
	v  map[string]discoveryEntry
}

type discoveryEntry struct {
	doc oidcDiscovery
	exp time.Time
}

var discCache = &discoveryCache{v: map[string]discoveryEntry{}}

func (s *Service) discoverOIDC(ctx context.Context, discoveryURL string) (*oidcDiscovery, error) {
	discCache.mu.RLock()
	if e, ok := discCache.v[discoveryURL]; ok && e.exp.After(time.Now()) {
		discCache.mu.RUnlock()
		return &e.doc, nil
	}
	discCache.mu.RUnlock()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssoflow: discovery GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssoflow: discovery returned %d", resp.StatusCode)
	}
	body, err := readBoundedBody(resp.Body, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("ssoflow: discovery body: %w", err)
	}
	var doc oidcDiscovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("ssoflow: discovery parse: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, errors.New("ssoflow: discovery missing required endpoints")
	}
	discCache.mu.Lock()
	discCache.v[discoveryURL] = discoveryEntry{doc: doc, exp: time.Now().Add(12 * time.Hour)}
	discCache.mu.Unlock()
	return &doc, nil
}

// OIDCStart handles GET /oidc/start.
func (s *Service) OIDCStart(w http.ResponseWriter, r *http.Request, tenantSlug string) {
	tenantID, cfg, err := s.resolveTenant(r.Context(), tenantSlug)
	if err != nil {
		s.respondFlowError(w, err)
		return
	}
	if cfg.ProviderType != "oidc" {
		http.Error(w, `{"error":"provider_mismatch"}`, http.StatusBadRequest)
		return
	}
	if cfg.DiscoveryURL == "" || cfg.ClientID == "" {
		http.Error(w, `{"error":"oidc_not_configured"}`, http.StatusBadRequest)
		return
	}

	disc, err := s.discoverOIDC(r.Context(), cfg.DiscoveryURL)
	if err != nil {
		http.Error(w, `{"error":"discovery_failed"}`, http.StatusBadGateway)
		return
	}

	// PKCE: generate a verifier + S256 challenge.
	verifier, err := randString(64)
	if err != nil {
		http.Error(w, `{"error":"random_failed"}`, http.StatusInternalServerError)
		return
	}
	challenge := codeChallengeS256(verifier)

	nonce, err := randString(32)
	if err != nil {
		http.Error(w, `{"error":"random_failed"}`, http.StatusInternalServerError)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	stateTok, err := s.signState(stateClaims{
		TenantID: tenantID.String(), Provider: "oidc",
		ReturnTo: returnTo, CodeVerifier: verifier, Nonce: nonce,
		RegisteredClaims: registeredExp(stateMaxAge),
	})
	if err != nil {
		http.Error(w, `{"error":"state_sign_failed"}`, http.StatusInternalServerError)
		return
	}
	s.setStateCookie(w, stateTok)

	// Build authorize URL.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", s.publicURL+"/api/v1/auth/sso/"+tenantSlug+"/oidc/callback")
	q.Set("scope", "openid profile email groups")
	q.Set("state", stateTok)        // IdP echoes — we re-verify in callback
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, disc.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
}

// OIDCCallback handles GET /oidc/callback.
func (s *Service) OIDCCallback(w http.ResponseWriter, r *http.Request, tenantSlug string) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		http.Error(w, `{"error":"missing_code_or_state"}`, http.StatusBadRequest)
		return
	}

	// CSRF check: state param must match the signed cookie value.
	cookieState, err := s.readStateCookie(r)
	if err != nil {
		http.Error(w, `{"error":"state_cookie_missing"}`, http.StatusBadRequest)
		return
	}
	if cookieState != stateParam {
		http.Error(w, `{"error":"state_mismatch"}`, http.StatusBadRequest)
		return
	}
	state, err := s.verifyState(stateParam)
	if err != nil {
		http.Error(w, `{"error":"state_invalid"}`, http.StatusBadRequest)
		return
	}
	if state.Provider != "oidc" {
		http.Error(w, `{"error":"provider_mismatch"}`, http.StatusBadRequest)
		return
	}
	// Single-use consumption — INSERT the jti so a replay trips the
	// unique constraint and fails-closed. Done BEFORE the token
	// exchange so we don't make an outbound IdP call for a replay.
	if err := s.consumeState(r.Context(), state); err != nil {
		http.Error(w, `{"error":"state_replayed_or_invalid"}`, http.StatusBadRequest)
		return
	}

	tenantID, cfg, err := s.resolveTenant(r.Context(), tenantSlug)
	if err != nil {
		s.respondFlowError(w, err)
		return
	}
	if tenantID.String() != state.TenantID {
		http.Error(w, `{"error":"tenant_mismatch"}`, http.StatusBadRequest)
		return
	}

	disc, err := s.discoverOIDC(r.Context(), cfg.DiscoveryURL)
	if err != nil {
		http.Error(w, `{"error":"discovery_failed"}`, http.StatusBadGateway)
		return
	}

	// Exchange the code for tokens.
	tokens, err := s.oidcTokenExchange(r.Context(), disc, cfg, state, code, tenantSlug)
	if err != nil {
		http.Error(w, `{"error":"token_exchange_failed"}`, http.StatusBadGateway)
		return
	}

	// Validate the id_token end-to-end: signature against the IdP's
	// JWKS (kid-routed, alg-pinned), iss matches discovery doc,
	// aud contains our client_id, nonce matches the state cookie,
	// iat within replay window, exp not past. See verifyIDToken in
	// jwks_verify.go for the full check list.
	claims, err := s.verifyIDToken(r.Context(), tokens.IDToken,
		disc.JWKSURI, disc.Issuer, cfg.ClientID, state.Nonce)
	if err != nil {
		// Surface the specific category so the operator can debug
		// "did the IdP rotate" vs "did we deploy a different
		// client_id" vs "is the IdP clock skewed".
		http.Error(w,
			fmt.Sprintf(`{"error":"id_token_invalid","detail":%q}`, err.Error()),
			http.StatusUnauthorized)
		return
	}

	// Map claims → VaultscanClaims.
	attrs := oidcClaimsToMap(claims)
	mapped, err := s.mapClaims(r.Context(), tenantID, cfg, attrs)
	if err != nil {
		http.Error(w, `{"error":"claim_mapping_failed"}`, http.StatusBadRequest)
		return
	}
	tok, err := s.issueJWT(r.Context(), mapped)
	if err != nil {
		http.Error(w, `{"error":"jwt_mint_failed"}`, http.StatusInternalServerError)
		return
	}

	s.clearStateCookie(w)
	s.finishFlow(w, r, state.ReturnTo, tok)
}

// oidcTokenResponse is the token endpoint's reply.
type oidcTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func (s *Service) oidcTokenExchange(ctx context.Context, disc *oidcDiscovery,
	cfg interface {
		// keep this loose so we don't import ssoconfig in this file
		// beyond the receiver's needs
	}, state *stateClaims, code, tenantSlug string,
) (*oidcTokenResponse, error) {
	// Cast cfg back; we know the caller passes a *ssoconfig.LoadedConfig.
	type lc interface{}
	_ = lc(cfg)
	// Inline-build via reflection-free Get on the receiver.
	// Simpler: take ClientID + ClientSecret via the closure helper.
	clientID, clientSecret := s.oidcClientCreds(state.TenantID)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.publicURL+"/api/v1/auth/sso/"+tenantSlug+"/oidc/callback")
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	form.Set("code_verifier", state.CodeVerifier)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		disc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint POST: %w", err)
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, 32<<10)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	var tr oidcTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint parse: %w", err)
	}
	if tr.IDToken == "" {
		return nil, errors.New("token endpoint response missing id_token")
	}
	return &tr, nil
}

// oidcClientCreds re-reads the tenant's stored client_id +
// client_secret. The exchange flow needs the secret, which we
// intentionally don't carry in the state cookie (so a leaked cookie
// can't impersonate the SP).
func (s *Service) oidcClientCreds(tenantID string) (clientID, clientSecret string) {
	tid := tenantID
	_ = s.pool.QueryRow(context.Background(), `
		SELECT COALESCE(client_id,''), COALESCE(client_secret,'')
		  FROM tenant_sso_config WHERE tenant_id = $1`, tid).
		Scan(&clientID, &clientSecret)
	return
}

// oidcClaimsToMap flattens jwt.MapClaims for mapClaims.
func oidcClaimsToMap(c jwt.MapClaims) map[string][]string {
	out := map[string][]string{}
	put := func(k string, v any) {
		switch t := v.(type) {
		case string:
			out[k] = append(out[k], t)
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok {
					out[k] = append(out[k], s)
				}
			}
		}
	}
	for k, v := range c {
		put(k, v)
	}
	// Common synonyms so claim_mapping defaults work across IdPs.
	if v, ok := c["preferred_username"]; ok {
		put("name", v)
	}
	if v, ok := c["given_name"]; ok {
		put("name", v)
	}
	if v, ok := c["groups"]; ok {
		put("roles", v)
	}
	return out
}

// ---- helpers --------------------------------------------------------

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// registeredExp returns jwt.RegisteredClaims with NotBefore=now and
// ExpiresAt=now+ttl. Used for state-cookie JWTs.
func registeredExp(ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now().UTC()
	return jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
}
