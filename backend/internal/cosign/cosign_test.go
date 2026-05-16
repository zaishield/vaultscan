package cosign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// TestVerifyPubKey_ECDSARoundTrip ensures the ECDSA-P256 verifier accepts
// a signature it produces itself and rejects a tampered payload.
func TestVerifyPubKey_ECDSARoundTrip(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPubKey(&priv.PublicKey, "ecdsa-p256-sha256", digest[:], sig) {
		t.Fatal("verifier should accept a freshly-signed payload")
	}

	// Tamper with one byte of the payload → must reject.
	bad := []byte(`{"hello":"WORLD"}`)
	badDigest := sha256.Sum256(bad)
	if verifyPubKey(&priv.PublicKey, "ecdsa-p256-sha256", badDigest[:], sig) {
		t.Fatal("verifier accepted a tampered payload")
	}
}

// TestParsePublicKey accepts PKIX and PKCS1 PEM encodings.
func TestParsePublicKey(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pub, err := ParsePublicKey(string(pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

// TestVerifyImage_PayloadShape covers the JSON envelope checks: wrong type,
// wrong digest, malformed b64 all reject before crypto runs.
func TestVerifyImage_PayloadShape(t *testing.T) {
	t.Parallel()
	s := &Service{}
	// Build a payload covering a different digest than we ask about.
	payload := map[string]any{
		"critical": map[string]any{
			"identity": map[string]any{"docker-reference": "registry/foo:1"},
			"image":    map[string]any{"docker-manifest-digest": "sha256:other"},
			"type":     "cosign container image signature",
		},
	}
	pb, _ := json.Marshal(payload)
	bundle := Bundle{
		PayloadB64:   base64.StdEncoding.EncodeToString(pb),
		SignatureB64: base64.StdEncoding.EncodeToString([]byte("not a real signature")),
	}
	r, err := s.VerifyImage(nil, "registry/foo:1", "sha256:expected", bundle, "external")
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != DecisionRejectedPayload {
		t.Fatalf("expected rejected_payload, got %s (%s)", r.Decision, r.Reason)
	}

	// Wrong critical.type.
	payload["critical"].(map[string]any)["type"] = "spdx attestation"
	pb, _ = json.Marshal(payload)
	bundle.PayloadB64 = base64.StdEncoding.EncodeToString(pb)
	r, _ = s.VerifyImage(nil, "registry/foo:1", "sha256:other", bundle, "external")
	if r.Decision != DecisionRejectedPayload {
		t.Fatalf("expected rejected_payload for wrong type, got %s", r.Decision)
	}

	// Malformed base64.
	bundle.PayloadB64 = "@@@not base64@@@"
	r, _ = s.VerifyImage(nil, "registry/foo:1", "sha256:other", bundle, "external")
	if r.Decision != DecisionRejectedPayload {
		t.Fatalf("expected rejected_payload for bad b64, got %s", r.Decision)
	}
}
