package auth

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
)

// base64URLDecode handles JWK's URL-safe base64 with optional missing
// padding (RFC 7515 §2).
func base64URLDecode(s string) ([]byte, error) {
	// Pad to multiple of 4 because Go's RawURLEncoding can also fail on
	// some IdP outputs; URLEncoding-with-padding is the safer fallback.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func curveByName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("oidc: unsupported curve %q", crv)
}
