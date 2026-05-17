package cosign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

func TestParseRekorEntry_HappyPath(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"logID":          "abc123",
		"logIndex":       42,
		"uuid":           "ent-1",
		"integratedTime": 1700000000,
		"body":           base64.StdEncoding.EncodeToString([]byte("hello")),
		"verification": map[string]any{
			"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("sig")),
			"inclusionProof":       map[string]any{"rootHash": base64.StdEncoding.EncodeToString([]byte("root"))},
		},
	}
	b, _ := json.Marshal(doc)
	envelope := base64.StdEncoding.EncodeToString(b)
	entry, err := ParseRekorEntry(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if entry.LogID != "abc123" {
		t.Errorf("LogID=%q want abc123", entry.LogID)
	}
	if entry.LogIndex != 42 {
		t.Errorf("LogIndex=%d want 42", entry.LogIndex)
	}
	if entry.UUID != "ent-1" {
		t.Errorf("UUID=%q want ent-1", entry.UUID)
	}
	if string(entry.Body) != "hello" {
		t.Errorf("Body=%q want hello", string(entry.Body))
	}
}

func TestParseRekorEntry_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := ParseRekorEntry(""); err == nil {
		t.Error("expected error for empty envelope")
	}
}

func TestParseRekorEntry_RejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := ParseRekorEntry("not-base64-at-all-!!!"); err == nil {
		t.Error("expected error for non-base64 envelope")
	}
}

func TestParseRekorEntry_RejectsNegativeIndex(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"logIndex":       -1,
		"integratedTime": 1700000000,
	}
	b, _ := json.Marshal(doc)
	_, err := ParseRekorEntry(base64.StdEncoding.EncodeToString(b))
	if err == nil {
		t.Error("expected error on negative log index")
	}
}

func TestParseRekorEntry_RejectsMissingIntegratedTime(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"logIndex": 1, "logID": "x"}
	b, _ := json.Marshal(doc)
	_, err := ParseRekorEntry(base64.StdEncoding.EncodeToString(b))
	if err == nil {
		t.Error("expected error when integratedTime missing")
	}
}

// Without a configured public key the SET verify is impossible —
// nil receiver must error rather than panic.
func TestVerifySET_NilKeyRejects(t *testing.T) {
	t.Parallel()
	var rk *RekorPublicKey
	err := rk.VerifySignedEntryTimestamp(&RekorEntry{}, []byte("x"))
	if err == nil {
		t.Error("nil RekorPublicKey should return an error, not panic")
	}
}

// Empty SthSignature is rejected (an entry without a SET can't be
// verified).
func TestVerifySET_NoSignatureRejected(t *testing.T) {
	t.Parallel()
	// Use a real ECDSA P-256 key so we get past the parse step
	// and reach the "missing signature" check we want to exercise.
	rk := mustNewRekorPublicKey(t)
	err := rk.VerifySignedEntryTimestamp(&RekorEntry{SthSignature: nil}, []byte("x"))
	if err == nil {
		t.Error("missing SET signature should produce an error")
	}
}

// Garbage signature against a real key fails verification cleanly
// (vs panicking on bad input).
func TestVerifySET_GarbageSignatureRejectsCleanly(t *testing.T) {
	t.Parallel()
	rk := mustNewRekorPublicKey(t)
	err := rk.VerifySignedEntryTimestamp(&RekorEntry{
		SthSignature: []byte{0x30, 0x00}, // empty ASN.1 SEQUENCE
		LogID:        "x",
		LogIndex:     1,
		IntegratedAt: time.Now(),
	}, []byte("x"))
	if err == nil {
		t.Error("garbage signature should fail verification, not pass silently")
	}
}

func mustNewRekorPublicKey(t *testing.T) *RekorPublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	rk, err := ParseRekorPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return rk
}
