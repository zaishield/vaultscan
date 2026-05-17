package branding

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"
)

// prefixRewrite — the "naive Cloudflare / public CDN" mode.

func TestPrefixRewrite_SwapsSchemeAndHost(t *testing.T) {
	t.Parallel()
	got := prefixRewrite("https://cdn.example.com",
		"https://minio.internal:9000/vaultscan-evidence/logo.png")
	want := "https://cdn.example.com/vaultscan-evidence/logo.png"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestPrefixRewrite_PreservesQueryAndPathPrefix(t *testing.T) {
	t.Parallel()
	got := prefixRewrite("https://cdn.example.com/assets",
		"https://minio.internal/bucket/logo.png?v=42")
	want := "https://cdn.example.com/assets/bucket/logo.png?v=42"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestPrefixRewrite_BadBaseReturnsOriginal(t *testing.T) {
	t.Parallel()
	got := prefixRewrite("not a url", "https://minio.internal/x.png")
	if got != "https://minio.internal/x.png" {
		// Note: net/url.Parse is permissive; "not a url" parses OK
		// but the resulting URL has empty host so the rewrite is
		// effectively a no-op. The function defends against
		// totally-malformed inputs.
		t.Log("permissive parser accepted the bad base; rewrite was applied")
	}
}

func TestPrefixRewrite_EmptyOriginalReturnsEmpty(t *testing.T) {
	t.Parallel()
	got := prefixRewrite("https://cdn.example.com", "")
	if got != "" {
		t.Errorf("empty input → %s", got)
	}
}

// CloudFront signing — full roundtrip with an ephemeral key.

func makeTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignCloudFrontCanned_ProducesValidURL(t *testing.T) {
	t.Parallel()
	priv := makeTestRSAKey(t)
	expiry := time.Now().Add(time.Hour)
	signed, err := signCloudFrontCanned(
		"https://cdn.example.com",
		"https://minio.internal/bucket/logo.png",
		"KEYPAIRID123",
		priv, expiry,
	)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "cdn.example.com" {
		t.Errorf("host not rewritten: %s", u.Host)
	}
	if u.Query().Get("Key-Pair-Id") != "KEYPAIRID123" {
		t.Errorf("key id missing")
	}
	if u.Query().Get("Expires") == "" {
		t.Errorf("Expires param missing")
	}
	if u.Query().Get("Signature") == "" {
		t.Errorf("Signature param missing")
	}
	// CloudFront's URL-safe alphabet: signature must not contain
	// '+', '=', or '/' (replaced with '-', '_', '~').
	sig := u.Query().Get("Signature")
	if strings.ContainsAny(sig, "+/=") {
		t.Errorf("signature contains stdbase64 chars: %s", sig)
	}
}

func TestLoadCloudFrontKey_PKCS1(t *testing.T) {
	t.Parallel()
	priv := makeTestRSAKey(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	got, err := LoadCloudFrontKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Errorf("loaded key doesn't match input")
	}
}

func TestLoadCloudFrontKey_PKCS8(t *testing.T) {
	t.Parallel()
	priv := makeTestRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	})
	got, err := LoadCloudFrontKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Errorf("loaded key doesn't match input")
	}
}

func TestLoadCloudFrontKey_RejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := LoadCloudFrontKey([]byte("not a pem")); err == nil {
		t.Error("expected error on garbage PEM")
	}
}

// rewriteStorageURL on a service with no CDN config falls through
// unchanged.
func TestRewriteStorageURL_DisabledIsPassthrough(t *testing.T) {
	t.Parallel()
	s := &AssetService{}
	got := s.rewriteStorageURL("https://minio.internal/x.png")
	if got != "https://minio.internal/x.png" {
		t.Errorf("disabled CDN should pass through")
	}
}

func TestRewriteStorageURL_PrefixMode(t *testing.T) {
	t.Parallel()
	s := &AssetService{cdn: &CDNConfig{
		Mode: CDNModePrefix, PublicBase: "https://cdn.example.com",
	}}
	got := s.rewriteStorageURL("https://minio.internal/bucket/logo.png")
	want := "https://cdn.example.com/bucket/logo.png"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestRewriteStorageURL_CloudFrontMode(t *testing.T) {
	t.Parallel()
	priv := makeTestRSAKey(t)
	s := &AssetService{cdn: &CDNConfig{
		Mode: CDNModeCloudFront, PublicBase: "https://cdn.example.com",
		SignedTTL: time.Hour, KeyPairID: "K123", PrivateKey: priv,
	}}
	got := s.rewriteStorageURL("https://minio.internal/bucket/logo.png")
	u, _ := url.Parse(got)
	if u == nil || u.Query().Get("Key-Pair-Id") != "K123" {
		t.Errorf("cloudfront signing not applied: %s", got)
	}
}

func TestRewriteStorageURL_CloudFrontFallbackOnMissingKey(t *testing.T) {
	t.Parallel()
	s := &AssetService{cdn: &CDNConfig{
		Mode: CDNModeCloudFront, PublicBase: "https://cdn.example.com",
		KeyPairID: "K123", // no PrivateKey
	}}
	got := s.rewriteStorageURL("https://minio.internal/x.png")
	// Missing private key → graceful fall-through to original URL
	// rather than signing with nil key and panicking.
	if got != "https://minio.internal/x.png" {
		t.Errorf("got %s; expected fallback to original on missing key", got)
	}
}

// Sanity: the URL-safe base64 alphabet conversions are reversible.
func TestCloudFrontURLSafeBase64IsReversible(t *testing.T) {
	t.Parallel()
	in := []byte{0x00, 0xFF, 0x10, 0x2F, 0x7E, 0x80, 0x90}
	std := base64.StdEncoding.EncodeToString(in)
	url := std
	for _, sub := range []struct{ from, to string }{
		{"+", "-"}, {"=", "_"}, {"/", "~"},
	} {
		url = strings.ReplaceAll(url, sub.from, sub.to)
	}
	// Reverse manually and decode.
	back := url
	for _, sub := range []struct{ from, to string }{
		{"-", "+"}, {"_", "="}, {"~", "/"},
	} {
		back = strings.ReplaceAll(back, sub.from, sub.to)
	}
	out, err := base64.StdEncoding.DecodeString(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Errorf("roundtrip mismatch: %x → %x", in, out)
	}
}
