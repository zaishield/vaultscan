//go:build integration

package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/integrations"
)

// TestIntegrations_VerifyInboundEndToEnd exercises the full inbound
// webhook signature verification pipeline against a live DB:
//   1. Operator creates an integration via Service.Create
//   2. SetSigningSecret stores a wrapped secret
//   3. A "partner" computes HMAC-SHA256(secret, "<ts>.<body>")
//   4. VerifyInbound returns nil for the valid signature
//   5. VerifyInbound returns ErrSignatureMismatch for tampered bodies
//   6. integration_inbound_log records each callback (verified + rejected)
func TestIntegrations_VerifyInboundEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, _ := h.makeTenant(t, "inbound-webhook")
	intID, err := h.integrations.Create(ctx, integrations.CreateInput{
		TenantID:  &tenantID,
		PartnerID: &directID,
		Type:      "webhook",
		Name:      "test-inbound",
		Config:    map[string]any{"url": "https://example.invalid/in"},
		CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}

	// Rotate the signing secret to a known value via SetSigningSecret;
	// the vault.WrapBytes/UnwrapBlob round-trip seals it at rest.
	secret := "topsecret-do-not-leak"
	if err := h.integrations.SetSigningSecret(ctx, intID, secret, h.vault); err != nil {
		t.Fatalf("SetSigningSecret: %v", err)
	}

	body := []byte(`{"event":"ping","tenant_id":"x"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	// Good signature passes.
	if err := h.integrations.VerifyInbound(ctx, intID, ts, body, sig,
		"10.0.0.42", true, h.vault); err != nil {
		t.Fatalf("VerifyInbound valid sig: %v", err)
	}

	// Tampered body rejected.
	err = h.integrations.VerifyInbound(ctx, intID, ts, []byte(`{"event":"tampered"}`), sig,
		"10.0.0.42", true, h.vault)
	if !errors.Is(err, integrations.ErrSignatureMismatch) {
		t.Errorf("tampered body: want ErrSignatureMismatch, got %v", err)
	}

	// Old timestamp rejected.
	oldTs := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	err = h.integrations.VerifyInbound(ctx, intID, oldTs, body, sig,
		"10.0.0.42", true, h.vault)
	if !errors.Is(err, integrations.ErrTimestampSkew) {
		t.Errorf("old timestamp: want ErrTimestampSkew, got %v", err)
	}

	// Cleared secret + require=true → ErrSecretNotConfigured.
	if err := h.integrations.SetSigningSecret(ctx, intID, "", h.vault); err != nil {
		t.Fatalf("clear secret: %v", err)
	}
	err = h.integrations.VerifyInbound(ctx, intID, ts, body, sig, "10.0.0.42", true, h.vault)
	if !errors.Is(err, integrations.ErrSecretNotConfigured) {
		t.Errorf("no secret + require: want ErrSecretNotConfigured, got %v", err)
	}

	// Cleared secret + require=false → nil (dev / migration window).
	if err := h.integrations.VerifyInbound(ctx, intID, ts, body, sig, "10.0.0.42", false, h.vault); err != nil {
		t.Errorf("no secret + require=false: should pass, got %v", err)
	}

	// integration_inbound_log row written for each call (verified + rejected).
	var verified, rejected int
	if err := h.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE verified = true),
		  COUNT(*) FILTER (WHERE verified = false)
		FROM integration_inbound_log WHERE integration_id = $1`, intID).
		Scan(&verified, &rejected); err != nil {
		t.Fatalf("read inbound_log: %v", err)
	}
	if verified < 2 {
		// One for the valid call, one for the no-secret-but-require=false call
		t.Errorf("expected >=2 verified rows, got %d", verified)
	}
	if rejected < 3 {
		// Tampered + skew + no_secret-required
		t.Errorf("expected >=3 rejected rows, got %d", rejected)
	}

	_ = uuid.Nil // build tag silencer
}
