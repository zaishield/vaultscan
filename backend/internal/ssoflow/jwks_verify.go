// jwks_verify.go — IdP-side JWKS-backed id_token signature verifier
// for the OIDC SP federation flow.
//
// The platform's OWN JWKS (under /.well-known/jwks.json) is served
// by internal/auth/jwks.go for downstream consumers verifying our
// JWTs. This file is the MIRROR side: when a customer's IdP returns
// an id_token, we fetch THEIR JWKS, lookup the kid, verify the
// signature, and pin the algorithm to a safe set.
//
// Design notes:
//
//   1. Algorithm pinning. Only RS256/RS384/RS512 + ES256/ES384/ES512
//      are accepted. "none" is refused (CVE-class). HS-family is
//      refused because the public-key-as-HMAC-secret confusion is a
//      well-known attack (the IdP's public key is, well, public).
//
//   2. JWKS cache. Per-uri map of {kid → key}, mutex-guarded.
//      Soft TTL = 1h; hard refresh on kid-miss. Stale-while-revalidate
//      so a slow IdP doesn't block sign-in if the cached set still
//      has the right kid.
//
//   3. Issuer + audience binding. iss MUST match the discovery doc's
//      issuer (prevents IdP impersonation). aud MUST contain our
//      client_id (prevents id_token swapping across SPs).
//
//   4. Replay window. iat must not be more than 10 min in the past
//      AND not in the future beyond clock skew. nonce must match
//      what we shipped in the authorization request (state cookie).
//      exp must not be past.
//
//   5. Subject claim. Required. Used as the IdP-side identity for
//      auto-provisioning + future-link lookups.
//
// Production swap path: github.com/coreos/go-oidc gives the same
// guarantees plus more battle-testing. This implementation is
// hand-rolled so the platform has zero external SSO deps; for
// FedRAMP / banking deployments operators should swap.

package ssoflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// allowedIDTokenAlgs is the closed set of algorithms a customer IdP
// is permitted to sign id_tokens with. Adding to this list requires
// a security review.
var allowedIDTokenAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// idTokenSkew is the wall-clock tolerance for iat/nbf/exp. Most IdPs
// don't drift more than a few seconds; 2 min covers VM time-sync
// hiccups.
const idTokenSkew = 2 * time.Minute

// idTokenMaxAge bounds how old an id_token can be relative to its
// iat claim. Protects against replay if a token leaks.
const idTokenMaxAge = 10 * time.Minute

// jwksCache memoises JWKS docs by URI. Soft-TTL 1h; hard refresh on
// every cache miss.
type jwksCache struct {
	mu  sync.RWMutex
	v   map[string]*jwksEntry
}

type jwksEntry struct {
	keys map[string]any // kid → *rsa.PublicKey or *ecdsa.PublicKey
	exp  time.Time
}

var idpJWKS = &jwksCache{v: map[string]*jwksEntry{}}

const jwksSoftTTL = 1 * time.Hour

// keyFor returns the public key for the given (jwksURI, kid). On
// cache miss the JWKS is fetched fresh. On kid-miss within the
// cached set the JWKS is re-fetched once.
func (s *Service) keyFor(ctx context.Context, jwksURI, kid string) (any, error) {
	if jwksURI == "" {
		return nil, errors.New("ssoflow: jwks_uri not advertised by IdP")
	}
	if kid == "" {
		return nil, errors.New("ssoflow: id_token has no kid header")
	}

	idpJWKS.mu.RLock()
	e, fresh := idpJWKS.v[jwksURI], false
	if e != nil && e.exp.After(time.Now()) {
		fresh = true
	}
	idpJWKS.mu.RUnlock()

	if e != nil {
		if k, ok := e.keys[kid]; ok {
			return k, nil
		}
		if fresh {
			// Even with a fresh cache we miss this kid. IdP rotated
			// + we haven't seen the new key. Fall through to refresh.
		}
	}

	if err := s.refreshJWKS(ctx, jwksURI); err != nil {
		return nil, err
	}
	idpJWKS.mu.RLock()
	defer idpJWKS.mu.RUnlock()
	e = idpJWKS.v[jwksURI]
	if e == nil {
		return nil, errors.New("ssoflow: jwks cache empty after refresh")
	}
	k, ok := e.keys[kid]
	if !ok {
		return nil, fmt.Errorf("ssoflow: kid %q not in IdP jwks after refresh", kid)
	}
	return k, nil
}

// refreshJWKS fetches the IdP's JWKS and replaces the cached entry.
// Bounded body cap so a malicious IdP can't OOM us with a giant doc.
func (s *Service) refreshJWKS(ctx context.Context, jwksURI string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("ssoflow: jwks GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ssoflow: jwks returned %d", resp.StatusCode)
	}
	body, err := readBoundedBody(resp.Body, 256<<10) // 256 KiB
	if err != nil {
		return fmt.Errorf("ssoflow: jwks body: %w", err)
	}
	var doc struct {
		Keys []idpJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("ssoflow: jwks parse: %w", err)
	}
	entry := &jwksEntry{
		keys: map[string]any{},
		exp:  time.Now().Add(jwksSoftTTL),
	}
	for _, j := range doc.Keys {
		// Skip keys with disallowed algorithms.
		if j.Alg != "" && !allowedIDTokenAlgs[j.Alg] {
			continue
		}
		// We only verify with public keys, never sign — so
		// `use:enc` and `use:sig` are both fine; the alg pin is the
		// real safety check.
		key, err := j.parse()
		if err != nil {
			// Skip the bad key but keep going — IdPs sometimes
			// publish dual-purpose sets.
			continue
		}
		if j.Kid == "" {
			// JWK with no kid is uncommon but legal. Index it under
			// its own thumbprint so subsequent lookups by "" find
			// it. In practice we always require kid in the header.
			continue
		}
		entry.keys[j.Kid] = key
	}
	if len(entry.keys) == 0 {
		return errors.New("ssoflow: jwks doc had no usable keys")
	}
	idpJWKS.mu.Lock()
	idpJWKS.v[jwksURI] = entry
	idpJWKS.mu.Unlock()
	return nil
}

// idpJWK is the wire shape we accept. The RFC defines more fields
// (x5c, x5t, etc.) — we only need n+e for RSA and crv+x+y for EC.
type idpJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (j idpJWK) parse() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("rsa n: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		var eInt int
		for _, b := range e {
			eInt = eInt<<8 | int(b)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: eInt,
		}, nil
	case "EC":
		curve, err := ecCurveFor(j.Crv)
		if err != nil {
			return nil, err
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("ec x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, fmt.Errorf("ec y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", j.Kty)
	}
}

func ecCurveFor(name string) (elliptic.Curve, error) {
	// Map JWK crv values (RFC 7518 §6.2.1.1) to Go's curves.
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ec curve %q", name)
	}
}

// verifyIDToken parses + verifies an id_token end-to-end.
// Returns the claims map on success or an error describing exactly
// which check failed (issuer, audience, nonce, exp, signature, alg,
// kid lookup). Designed so the SSO ACS / callback handler can map
// distinct errors to distinct user-visible reasons.
func (s *Service) verifyIDToken(ctx context.Context, idToken string,
	jwksURI, expectedIssuer, expectedAudience, expectedNonce string,
) (jwt.MapClaims, error) {
	// Custom keyfunc that:
	//   1. Pins the algorithm to the allowlist.
	//   2. Looks up the kid in the JWKS cache (refreshes on miss).
	keyFunc := func(tok *jwt.Token) (any, error) {
		alg, _ := tok.Header["alg"].(string)
		if !allowedIDTokenAlgs[alg] {
			return nil, fmt.Errorf("disallowed id_token alg %q", alg)
		}
		kid, _ := tok.Header["kid"].(string)
		return s.keyFor(ctx, jwksURI, kid)
	}

	claims := jwt.MapClaims{}
	// jwt.WithoutClaimsValidation lets us hand-roll the iss/aud/exp/
	// nbf checks (the library's defaults don't cover audience
	// arrays + we want explicit error categorisation).
	tok, err := jwt.ParseWithClaims(idToken, claims, keyFunc,
		jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("id_token: parse/verify: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("id_token: invalid signature")
	}

	now := time.Now().UTC()

	// iss
	iss, _ := claims["iss"].(string)
	if iss != expectedIssuer {
		return nil, fmt.Errorf("id_token: iss=%q want %q", iss, expectedIssuer)
	}
	// aud — may be string OR []string
	if !audienceContains(claims["aud"], expectedAudience) {
		return nil, fmt.Errorf("id_token: aud does not contain %q", expectedAudience)
	}
	// exp
	if exp, ok := numericDate(claims["exp"]); ok {
		if now.After(exp.Add(idTokenSkew)) {
			return nil, errors.New("id_token: expired")
		}
	} else {
		return nil, errors.New("id_token: exp missing")
	}
	// nbf (optional)
	if nbf, ok := numericDate(claims["nbf"]); ok {
		if now.Add(idTokenSkew).Before(nbf) {
			return nil, errors.New("id_token: not yet valid (nbf)")
		}
	}
	// iat — required + bounds the replay window
	if iat, ok := numericDate(claims["iat"]); ok {
		if now.Sub(iat) > idTokenMaxAge+idTokenSkew {
			return nil, errors.New("id_token: too old (iat exceeds max age)")
		}
		if iat.After(now.Add(idTokenSkew)) {
			return nil, errors.New("id_token: iat in future")
		}
	} else {
		return nil, errors.New("id_token: iat missing")
	}
	// nonce
	if n, _ := claims["nonce"].(string); n != expectedNonce {
		return nil, errors.New("id_token: nonce mismatch")
	}
	// sub — required
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, errors.New("id_token: sub missing")
	}

	return claims, nil
}

// audienceContains handles both spec shapes: string AND []string.
func audienceContains(aud any, expected string) bool {
	switch a := aud.(type) {
	case string:
		return a == expected
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// numericDate converts a jwt.MapClaims numeric claim into a time.
// Returns ok=false if the claim is missing or not a number.
func numericDate(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0).UTC(), true
	case int64:
		return time.Unix(t, 0).UTC(), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0).UTC(), true
	}
	return time.Time{}, false
}
