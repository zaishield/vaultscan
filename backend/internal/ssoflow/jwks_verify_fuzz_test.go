package ssoflow

import (
	"encoding/json"
	"testing"
)

// FuzzJWKParse exercises the JWK wire-shape parser with adversarial
// input. The IdP's JWKS endpoint is attacker-controllable in the
// SSO threat model — a malicious IdP (or an attacker who can MITM
// the JWKS fetch) can serve any bytes.
//
// What we're proving:
//   * Parser never panics on malformed input
//   * Unsupported key types and curves return errors, not crashes
//   * Malformed base64 returns errors
//   * Empty / huge / negative fields don't trip integer overflow
//
// A panic here in production would crash the auth path → DoS.
func FuzzJWKParse(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"kty":"RSA","kid":"k1","alg":"RS256","n":"AQAB","e":"AQAB"}`),
		[]byte(`{"kty":"EC","kid":"k2","alg":"ES256","crv":"P-256","x":"AA","y":"BB"}`),
		[]byte(`{"kty":"EC","kid":"k3","alg":"ES512","crv":"P-521","x":"AA","y":"BB"}`),
		// edge cases
		[]byte(`{}`),
		[]byte(`{"kty":"none"}`),
		[]byte(`{"kty":"RSA","n":"","e":""}`),
		[]byte(`{"kty":"RSA","n":"!!!not base64!!!","e":"AQAB"}`),
		[]byte(`{"kty":"EC","crv":"P-999","x":"AA","y":"BB"}`),
		[]byte(`{"kty":"oct","k":"AA"}`), // symmetric — must be rejected
		[]byte(`{"kty":"RSA","n":null,"e":null}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		// Recover from any panic — that itself is the failure
		// condition: production must never crash on attacker-
		// controlled JWK bytes.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JWK parse PANICKED on input %q: %v", body, r)
			}
		}()

		var jwk idpJWK
		if err := json.Unmarshal(body, &jwk); err != nil {
			// Bad JSON → fine; the upstream JWKS fetcher would
			// reject this too.
			return
		}
		// parse() may return an error — that's expected. We only
		// care that it doesn't panic AND doesn't produce a key
		// that's somehow valid for unsupported types.
		key, perr := jwk.parse()
		if perr == nil && key == nil {
			t.Fatalf("JWK parse: nil key with nil error from %q", body)
		}
		if perr == nil && jwk.Kty != "RSA" && jwk.Kty != "EC" {
			t.Fatalf("JWK parse: accepted unsupported kty %q (input %q)", jwk.Kty, body)
		}
	})
}

// FuzzIDTokenStructure exercises the upstream parser with
// mutations of legitimate-looking id_token strings. The point
// isn't to forge a valid signature (impossible without the
// private key) but to ensure no parse stage panics or hangs on
// adversarial inputs.
//
// In production, every callback hits this code path with an IdP-
// supplied token; a crash here = SSO callback DoS = lockout.
func FuzzIDTokenStructure(f *testing.F) {
	seeds := []string{
		"a.b.c",                                             // 3 dotted segments, garbage
		"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjB9.AAAA",            // legal JWT shape, bad sig
		"eyJhbGciOiJub25lIn0.eyJleHAiOjB9.",                 // alg=none attack
		"....",                                              // empty segments
		"AAAAAAA",                                           // no dots
		"......" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // many dots
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Use a minimal Service stub — we're not testing the network
	// JWKS fetch, just the parser surface.
	svc := &Service{}

	f.Fuzz(func(t *testing.T, tok string) {
		if len(tok) > 4096 {
			t.Skip()
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("verifyIDToken PANICKED on input len=%d: %v", len(tok), r)
			}
		}()
		// We expect an error (we don't have a real JWKS to verify
		// against) but NOT a panic. Pass empty strings for the
		// expected fields; the verifier should still parse the
		// token structure and fail cleanly.
		_, _ = svc.verifyIDToken(nil, tok, "", "", "", "")
	})
}
