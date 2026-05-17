package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"
)

func computeSig(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(ts))
	_, _ = m.Write([]byte("."))
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"event":"ping"}`)
	sig := computeSig("topsecret", ts, body)

	err := Verify("topsecret", ts, body, sig, VerifyOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := computeSig("topsecret", ts, []byte(`{"a":1}`))

	err := Verify("topsecret", ts, []byte(`{"a":2}`), sig, VerifyOptions{
		Now: func() time.Time { return now },
	})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("want ErrSignatureMismatch, got %v", err)
	}
}

func TestVerifyRejectsOldTimestamp(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	oldTs := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	body := []byte(`x`)
	sig := computeSig("s", oldTs, body)

	err := Verify("s", oldTs, body, sig, VerifyOptions{
		Tolerance: 5 * time.Minute,
		Now:       func() time.Time { return now },
	})
	if !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("want ErrTimestampSkew, got %v", err)
	}
}

func TestVerifyMissingSignature(t *testing.T) {
	if err := Verify("s", "1", []byte(""), "", VerifyOptions{}); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("want ErrMissingSignature, got %v", err)
	}
}

func TestVerifyAcceptsSHA256Prefix(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`payload`)
	sig := "sha256=" + computeSig("s", ts, body)
	if err := Verify("s", ts, body, sig, VerifyOptions{Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestParseStripe(t *testing.T) {
	ts, sig := ParseStripe("t=1492774577,v1=abc123,v0=zzz")
	if ts != "1492774577" {
		t.Errorf("ts = %q", ts)
	}
	if sig != "abc123" {
		t.Errorf("sig = %q", sig)
	}
}
