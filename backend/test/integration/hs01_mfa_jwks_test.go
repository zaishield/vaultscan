//go:build integration

// HS-01: real TOTP/MFA + RSA JWT signing with rotation + JWKS endpoint.

package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

const testKEK = "ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA=" // shared with harness

// computeTOTP mirrors the algorithm in auth/totp.go so we can produce a
// valid code given the user's enrolment secret.
func computeTOTP(secretB32 string, now time.Time) string {
	// pad to multiple of 8 for std base32
	for len(secretB32)%8 != 0 {
		secretB32 += "="
	}
	secret, _ := base32.StdEncoding.DecodeString(secretB32)
	counter := uint64(now.Unix()) / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, secret)
	h.Write(buf[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", val%1000000)
}

// TestHS01_MFA_EnrollVerifyDisable: full happy path.
func TestHS01_MFA_EnrollVerifyDisable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc, err := auth.NewMFAService(h.pool, testKEK)
	if err != nil {
		t.Fatal(err)
	}

	// Use the harness admin user (already in `users`).
	userID := adminID

	secret, err := svc.StartEnrollment(ctx, userID, "ops@vaultscan.test", "VAULTSCAN")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if secret.Secret == "" || !strings.HasPrefix(secret.OtpAuthURI, "otpauth://totp/") {
		t.Fatalf("bad secret: %+v", secret)
	}
	if len(secret.RecoveryCodes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(secret.RecoveryCodes))
	}

	// Confirm with the right code.
	code := computeTOTP(secret.Secret, time.Now())
	if err := svc.ConfirmEnrollment(ctx, userID, code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	enrolled, _ := svc.IsEnrolled(ctx, userID)
	if !enrolled {
		t.Fatal("expected enrolled=true after confirm")
	}

	// users.mfa_status flipped.
	var status string
	_ = h.pool.QueryRow(ctx,
		`SELECT mfa_status FROM users WHERE id=$1`, userID).Scan(&status)
	if status != "enrolled" {
		t.Fatalf("expected mfa_status=enrolled, got %q", status)
	}

	// Verify with a fresh code (might be the same window, but window-tolerance handles both sides).
	if err := svc.Verify(ctx, userID, computeTOTP(secret.Secret, time.Now())); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Verify with a recovery code.
	if err := svc.Verify(ctx, userID, secret.RecoveryCodes[0]); err != nil {
		t.Fatalf("recovery verify: %v", err)
	}
	// Re-using the same recovery code MUST fail (consumed).
	if err := svc.Verify(ctx, userID, secret.RecoveryCodes[0]); err == nil {
		t.Fatal("recovery code must be single-use")
	}

	// Disable wipes the row.
	if err := svc.Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	enrolled, _ = svc.IsEnrolled(ctx, userID)
	if enrolled {
		t.Fatal("expected enrolled=false after disable")
	}
}

// TestHS01_MFA_BadCodeRejected: a wrong 6-digit code never accepts.
func TestHS01_MFA_BadCodeRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc, _ := auth.NewMFAService(h.pool, testKEK)

	tenantID, _ := h.makeTenant(t, "mfa-bad")
	var userID uuid.UUID
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO users(platform_id, partner_id, tenant_id, email, full_name,
		    mfa_enabled, status)
		VALUES ($1, $2, $3, 'mfa-bad@example', 'mfa bad', false, 'active')
		RETURNING id`, platformID, directID, tenantID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	secret, _ := svc.StartEnrollment(ctx, userID, "x@y", "VAULTSCAN")
	if err := svc.ConfirmEnrollment(ctx, userID, "000000"); err == nil {
		t.Fatal("000000 must be rejected (overwhelmingly unlikely to be the right code)")
	}
	// Then with a code three windows ago — beyond the ±1 tolerance.
	stale := computeTOTP(secret.Secret, time.Now().Add(-5*time.Minute))
	if err := svc.ConfirmEnrollment(ctx, userID, stale); err == nil {
		t.Fatal("5-minute-old code must be rejected (drift tolerance ±1 window)")
	}
}

// TestHS01_JWKS_RotationWithoutInvalidation: a token minted under k1
// keeps verifying after k1 is rotated to verify_only; a new token
// minted post-rotation is signed by k2 and verifies under k2.
func TestHS01_JWKS_RotationWithoutInvalidation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	km, err := auth.NewKeyManager(h.pool, testKEK)
	if err != nil {
		t.Fatal(err)
	}
	kid1, err := km.Bootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewVerifier("dev-shared-secret", h.pool).WithKeyManager(km)

	// Mint a token under k1.
	claims := auth.VaultscanClaims{
		Email:      "ops@vaultscan.test",
		PlatformID: platformID.String(),
		PartnerID:  directID.String(),
		Roles:      []string{"zaishield_super_admin"},
		MFA:        true,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   adminID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok1, err := verifier.IssueRSAToken(ctx, claims)
	if err != nil {
		t.Fatalf("issue under k1: %v", err)
	}
	id, err := verifier.Parse(ctx, "Bearer "+tok1)
	if err != nil || id == nil {
		t.Fatalf("parse k1 token: %v", err)
	}

	// Rotate to k2 (k1 becomes verify_only).
	kid2, err := km.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kid1 == kid2 {
		t.Fatal("rotated kid must differ from old kid")
	}

	// k1 token still works (verify_only).
	if _, err := verifier.Parse(ctx, "Bearer "+tok1); err != nil {
		t.Fatalf("k1 token must keep verifying post-rotation: %v", err)
	}

	// New token uses k2.
	tok2, err := verifier.IssueRSAToken(ctx, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok2, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["kid"] != kid2 {
		t.Fatalf("new token kid = %v, want %s", parsed.Header["kid"], kid2)
	}

	// Retire keys older than 0s → k1 goes to retired.
	n, err := km.RetireOld(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least one key retired, got %d", n)
	}
	// k1 token now fails (kid retired).
	if _, err := verifier.Parse(ctx, "Bearer "+tok1); err == nil {
		t.Fatal("retired-kid token must NOT verify")
	}
}

// TestHS01_JWKS_PublicSetIsValid: PublicSet contains kid + n + e for
// every active + verify_only row in the expected RFC 7517 shape.
func TestHS01_JWKS_PublicSetIsValid(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	km, _ := auth.NewKeyManager(h.pool, testKEK)
	_, _ = km.Bootstrap(ctx)
	_, _ = km.Rotate(ctx) // give us 1 active + 1 verify_only

	set, err := km.PublicSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) < 2 {
		t.Fatalf("expected >= 2 keys in JWKS, got %d", len(set.Keys))
	}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
			t.Fatalf("bad JWK shape: %+v", k)
		}
		if k.Kid == "" || k.N == "" || k.E == "" {
			t.Fatalf("missing JWK fields: %+v", k)
		}
	}
}
