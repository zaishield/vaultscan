package ssoflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// startJWKSServer spins up an http.Server that serves a JWKS at /jwks
// for the supplied key. Returns the server + the kid the test should
// reference. Caller is responsible for Close().
func startJWKSServer(t *testing.T, kid string, pub any) *httptest.Server {
	t.Helper()
	var jwk idpJWK
	jwk.Kid = kid
	switch k := pub.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.Alg = "RS256"
		jwk.N = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		// E is small; jwt-go's RSA pubkey uses int; encode as bytes
		// truncated to its used length.
		eBytes := []byte{0x01, 0x00, 0x01}
		jwk.E = base64.RawURLEncoding.EncodeToString(eBytes)
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.Alg = "ES256"
		switch k.Curve {
		case elliptic.P256():
			jwk.Crv = "P-256"
		case elliptic.P384():
			jwk.Crv = "P-384"
		case elliptic.P521():
			jwk.Crv = "P-521"
		}
		jwk.X = base64.RawURLEncoding.EncodeToString(k.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	default:
		t.Fatalf("unsupported pub type %T", pub)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{jwk},
		})
	}))
}

func newSvcForTest() *Service {
	return &Service{httpc: &http.Client{Timeout: 5 * time.Second}}
}

// Mints an id_token signed with RS256 + a real RSA key, exposes the
// JWKS, and asserts verifyIDToken returns the claims.
func TestVerifyIDToken_RS256_HappyPath(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "client-abc",
		"sub":   "user-123",
		"email": "user@example.com",
		"nonce": "nonce-xyz",
		"iat":   now,
		"exp":   now + 600,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "kid-1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "nonce-xyz")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["sub"] != "user-123" {
		t.Errorf("sub mismatch: %v", got["sub"])
	}
}

// Asserts the verifier REFUSES tokens signed with the "none" algorithm.
func TestVerifyIDToken_RefusesNoneAlg(t *testing.T) {
	t.Parallel()
	// Hand-craft an unsigned token (alg=none).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","aud":"client-abc","exp":9999999999}`))
	unsigned := header + "." + payload + "."

	_, err := newSvcForTest().verifyIDToken(context.Background(), unsigned,
		"http://does-not-matter", "x", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted alg=none — that's a CVE-class bug")
	}
	if !strings.Contains(err.Error(), "disallowed") && !strings.Contains(err.Error(), "alg") {
		t.Errorf("expected alg-pinning error, got %q", err)
	}
}

// Asserts the verifier REFUSES HS-family algorithms (public-key-as-HMAC-secret attack).
func TestVerifyIDToken_RefusesHSFamily(t *testing.T) {
	t.Parallel()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"aud": "client-abc"})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString([]byte("attacker-supplied-secret"))

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		"http://x", "x", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted HS256 — public-key confusion attack possible")
	}
}

// Wrong audience must fail even with a valid signature.
func TestVerifyIDToken_AudienceMismatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "OTHER-CLIENT",
		"sub":   "user-1",
		"nonce": "n",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted wrong audience")
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Errorf("expected aud error, got %q", err)
	}
}

// Wrong issuer must fail (prevents IdP impersonation: a different IdP
// signs with their key but claims to be Okta).
func TestVerifyIDToken_IssuerMismatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://attacker.example",
		"aud":   "client-abc",
		"sub":   "user-1",
		"nonce": "n",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted spoofed iss")
	}
	if !strings.Contains(err.Error(), "iss") {
		t.Errorf("expected iss error, got %q", err)
	}
}

// Nonce mismatch must fail (catches state-cookie / replay attacks).
func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "client-abc",
		"sub":   "user-1",
		"nonce": "DIFFERENT",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "expected-nonce")
	if err == nil {
		t.Fatal("verifier accepted wrong nonce")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected nonce error, got %q", err)
	}
}

// Expired token must fail.
func TestVerifyIDToken_Expired(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	past := time.Now().Add(-2 * time.Hour).Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "client-abc",
		"sub":   "user-1",
		"nonce": "n",
		"iat":   past,
		"exp":   past + 60, // expired 2h ago
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %q", err)
	}
}

// iat too old (>10 min ago) must fail — replay protection.
func TestVerifyIDToken_IATTooOld(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	old := time.Now().Add(-30 * time.Minute).Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "client-abc",
		"sub":   "user-1",
		"nonce": "n",
		"iat":   old,
		"exp":   time.Now().Add(time.Hour).Unix(), // valid exp
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted stale iat")
	}
	if !strings.Contains(err.Error(), "iat") && !strings.Contains(err.Error(), "old") {
		t.Errorf("expected iat-too-old error, got %q", err)
	}
}

// Audience-as-array shape: aud may be []string per OIDC spec.
func TestVerifyIDToken_AudienceArray(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   []string{"other-client", "client-abc"},
		"sub":   "user-1",
		"nonce": "n",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid-1"
	signed, _ := tok.SignedString(key)

	got, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["sub"] != "user-1" {
		t.Errorf("sub mismatch: %v", got["sub"])
	}
}

// kid not in JWKS must fail (even with an otherwise-valid signature
// signed with a different key).
func TestVerifyIDToken_UnknownKid(t *testing.T) {
	t.Parallel()
	served, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := startJWKSServer(t, "kid-1", &served.PublicKey)
	defer srv.Close()
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://idp.example",
		"aud":   "client-abc",
		"sub":   "user-1",
		"nonce": "n",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "rogue-kid"
	signed, _ := tok.SignedString(attacker)

	_, err := newSvcForTest().verifyIDToken(context.Background(), signed,
		srv.URL, "https://idp.example", "client-abc", "n")
	if err == nil {
		t.Fatal("verifier accepted token with kid not in JWKS")
	}
}

// Algorithm allowlist sanity — all listed algs are HMAC-or-asymmetric;
// none of HS family should be in the allowlist.
func TestAllowedIDTokenAlgs_NoHMAC(t *testing.T) {
	for k := range allowedIDTokenAlgs {
		if strings.HasPrefix(k, "HS") {
			t.Errorf("allowedIDTokenAlgs contains HS-family alg %q — CVE-class risk", k)
		}
	}
	if allowedIDTokenAlgs["none"] {
		t.Error("allowedIDTokenAlgs accepts 'none'")
	}
	if len(allowedIDTokenAlgs) == 0 {
		t.Error("allowedIDTokenAlgs is empty")
	}
}

// EC curve mapping covers the three RFC 7518 curves.
func TestECCurveFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}
	for _, c := range cases {
		got, err := ecCurveFor(c.name)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: wrong curve", c.name)
		}
	}
	if _, err := ecCurveFor("P-999"); err == nil {
		t.Error("expected error for unsupported curve")
	}
}
