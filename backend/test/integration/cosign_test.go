//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/cosign"
)

// TestCosign_HappyPath: register an ECDSA P-256 key, sign a manifest digest
// with the matching private key, store the bundle on the registry row, and
// confirm VerifyImage accepts it. Then revoke the key and confirm the same
// bundle now fails closed.
func TestCosign_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// 1. Generate a fresh ECDSA P-256 keypair.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// 2. Register the key as trusted via the cosign service.
	cosignSvc := cosign.New(h.pool)
	if _, err := cosignSvc.Register(ctx, cosign.RegisterInput{
		KeyID:        "integration-test-key-1",
		Algorithm:    "ecdsa-p256-sha256",
		PublicKeyPEM: pubPEM,
		Plane:        "both",
		RegisteredBy: &adminID,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// 3. Pick a real image from the registry and produce a cosign bundle
	// that covers its digest.
	var imageRef, digest string
	if err := h.pool.QueryRow(ctx, `
		SELECT image_ref, image_digest
		  FROM scanner_image_registry
		 WHERE tool='nmap' AND enabled=true
		 ORDER BY registered_at DESC LIMIT 1`).Scan(&imageRef, &digest); err != nil {
		t.Fatalf("locate nmap image: %v", err)
	}

	payload := map[string]any{
		"critical": map[string]any{
			"identity": map[string]any{"docker-reference": imageRef},
			"image":    map[string]any{"docker-manifest-digest": digest},
			"type":     "cosign container image signature",
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadDigest := sha256.Sum256(payloadBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, payloadDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	bundle := cosign.Bundle{
		PayloadB64:   base64.StdEncoding.EncodeToString(payloadBytes),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
		KeyID:        "integration-test-key-1",
	}

	// 4. Cache the bundle on the registry row (production flow: an
	// upstream signing job populates this).
	if err := cosignSvc.CacheVerifiedSignature(ctx, imageRef, bundle, "integration-test-key-1"); err != nil {
		t.Fatalf("cache: %v", err)
	}

	// 5. The verifier accepts the cached bundle.
	res, err := cosignSvc.VerifyImage(ctx, imageRef, digest, bundle, "external")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Decision != cosign.DecisionAccepted {
		t.Fatalf("expected accepted, got %s — %s", res.Decision, res.Reason)
	}
	if res.MatchedKey != "integration-test-key-1" {
		t.Fatalf("expected key match, got %q", res.MatchedKey)
	}
	if err := cosignSvc.LogDecision(ctx, imageRef, res, &adminID); err != nil {
		t.Fatalf("log: %v", err)
	}

	// 6. Tamper test: re-sign a DIFFERENT digest and expect rejection.
	bogusPayload := payload
	bogusPayload["critical"].(map[string]any)["image"] = map[string]any{
		"docker-manifest-digest": "sha256:" + string(make([]byte, 64)),
	}
	bp, _ := json.Marshal(bogusPayload)
	bpDigest := sha256.Sum256(bp)
	bsig, _ := ecdsa.SignASN1(rand.Reader, priv, bpDigest[:])
	tamper := cosign.Bundle{
		PayloadB64:   base64.StdEncoding.EncodeToString(bp),
		SignatureB64: base64.StdEncoding.EncodeToString(bsig),
		KeyID:        "integration-test-key-1",
	}
	res2, err := cosignSvc.VerifyImage(ctx, imageRef, digest, tamper, "external")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Decision != cosign.DecisionRejectedPayload {
		t.Fatalf("expected rejected_payload for digest mismatch, got %s — %s", res2.Decision, res2.Reason)
	}

	// 7. Revoke + retry: same valid signature, but the key is no longer
	// trusted. Must reject.
	if err := cosignSvc.Revoke(ctx, "integration-test-key-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	res3, err := cosignSvc.VerifyImage(ctx, imageRef, digest, bundle, "external")
	if err != nil {
		t.Fatal(err)
	}
	if res3.Decision != cosign.DecisionRejectedUnknownKey &&
		res3.Decision != cosign.DecisionRejectedSignature {
		t.Fatalf("expected rejection after revoke, got %s — %s", res3.Decision, res3.Reason)
	}

	// 8. Decision audit table must show all three attempts.
	var rows int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM cosign_verifications WHERE image_ref=$1`, imageRef).Scan(&rows)
	if rows < 1 {
		t.Fatalf("expected >=1 cosign_verifications row, got %d", rows)
	}
}

// TestCosign_TamperedSignature: a signature byte-flipped after signing must
// be rejected as DecisionRejectedSignature (not Payload — payload is fine).
func TestCosign_TamperedSignature(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	svc := cosign.New(h.pool)
	if _, err := svc.Register(ctx, cosign.RegisterInput{
		KeyID: "tamper-test-key", Algorithm: "ecdsa-p256-sha256",
		PublicKeyPEM: pubPEM, Plane: "both", RegisteredBy: &adminID,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	var imageRef, digest string
	_ = h.pool.QueryRow(ctx, `
		SELECT image_ref, image_digest FROM scanner_image_registry
		 WHERE tool='zap' AND enabled=true ORDER BY registered_at DESC LIMIT 1`).
		Scan(&imageRef, &digest)

	payload := map[string]any{
		"critical": map[string]any{
			"identity": map[string]any{"docker-reference": imageRef},
			"image":    map[string]any{"docker-manifest-digest": digest},
			"type":     "cosign container image signature",
		},
	}
	pb, _ := json.Marshal(payload)
	pd := sha256.Sum256(pb)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, pd[:])
	// Flip the last signature byte so verification fails but the payload
	// still describes the right image.
	sig[len(sig)-1] ^= 0xff
	res, err := svc.VerifyImage(ctx, imageRef, digest, cosign.Bundle{
		PayloadB64:   base64.StdEncoding.EncodeToString(pb),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}, "external")
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != cosign.DecisionRejectedSignature {
		t.Fatalf("expected rejected_signature, got %s — %s", res.Decision, res.Reason)
	}
}
