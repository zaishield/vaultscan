package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Production lockdown: when WithRefuseHMAC(true) is set, an HS256
// token signed with the configured shared secret must be rejected,
// while an RS256 token signed by the wired key manager still
// validates. This is the second-line-of-defense against a leaked
// shared secret in a prod environment where RS256 is the only
// blessed alg.
func TestVerifier_RefuseHMACBlocksHS256(t *testing.T) {
	t.Parallel()
	secret := "test-shared-secret-must-be-at-least-thirty-two-bytes-long"
	v := NewVerifier(secret, nil).WithRefuseHMAC(true)

	// Mint a valid HS256 token with the very secret we know matches.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &VaultscanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Subject:   "00000000-0000-0000-0000-000000000001",
		},
		Email: "ops@vaultscan.test",
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Parse(context.Background(), signed); err == nil {
		t.Fatal("HS256 token should be refused in prod-lockdown mode")
	}
}

// When WithRefuseHMAC is NOT set (dev/staging default), HS256 still
// works. Guards against the lockdown accidentally being default-on.
func TestVerifier_HS256WorksWithoutLockdown(t *testing.T) {
	t.Parallel()
	secret := "test-shared-secret-must-be-at-least-thirty-two-bytes-long"
	v := NewVerifier(secret, nil) // no WithRefuseHMAC

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &VaultscanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Subject:   "00000000-0000-0000-0000-000000000001",
		},
		Email: "dev@vaultscan.test",
	})
	signed, _ := tok.SignedString([]byte(secret))
	if _, err := v.Parse(context.Background(), signed); err != nil {
		t.Fatalf("dev HS256 must still verify: %v", err)
	}
}

// Algorithm confusion: an HS256 token forged using a public key as
// the HMAC secret must NOT be accepted even when the verifier has an
// RSA key configured.
func TestVerifier_RejectsAlgorithmConfusion(t *testing.T) {
	t.Parallel()
	// Generate a real RSA key whose public half could be abused.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := encodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Verifier with HS256 disabled — RSA-only mode.
	v := NewVerifier("never-used", nil).WithRefuseHMAC(true)

	// Forge an HS256 token where the "secret" is the RSA public key
	// material — the classic alg-confusion attack.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &VaultscanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "attacker@evil",
	})
	forged, _ := tok.SignedString(pubPEM)
	if _, err := v.Parse(context.Background(), forged); err == nil {
		t.Fatal("algorithm-confusion forged token should be refused")
	}
}

// Helper for the alg-confusion test — encode an RSA public key as PEM.
func encodePublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
