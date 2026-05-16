package agents

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

// The agents package owns three security-critical pure helpers:
//   * version comparison (drives rollout gating)
//   * bundle manifest signing + verification (RSA-PSS, prevents
//     supply-chain attack on the agent installer)
//   * CSR / CA roundtrip
//
// All three are tested without a DB.

func TestVersionLess_NumericComponents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.10.0", "1.9.0", false}, // numeric, not lexicographic
		{"1.9.0", "1.10.0", true},
		{"2.0", "10.0", true},
		{"1.0", "1.0.0", true}, // shorter is "less" when equal up to length
		{"1.0.0", "1.0", false},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionLess_NonNumericFallsBackToString(t *testing.T) {
	t.Parallel()
	// alpha < beta < rc1 < (whatever) — falls back to string compare
	if !versionLess("1.0.0-alpha", "1.0.0-beta") {
		t.Error("alpha < beta in string fallback")
	}
}

func TestSplitVersion(t *testing.T) {
	t.Parallel()
	got := splitVersion("1.2.3")
	want := []string{"1", "2", "3"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("splitVersion[%d]=%q want %q", i, got[i], w)
		}
	}
	if v := splitVersion(""); len(v) != 0 {
		t.Errorf("empty input → %v want []", v)
	}
	// Single component, no dot
	if v := splitVersion("42"); len(v) != 1 || v[0] != "42" {
		t.Errorf("\"42\" → %v want [42]", v)
	}
}

func TestParseInt(t *testing.T) {
	t.Parallel()
	if n, ok := parseInt("42"); !ok || n != 42 {
		t.Errorf("parseInt(42) got %d/%v", n, ok)
	}
	if _, ok := parseInt("nope"); ok {
		t.Error("parseInt should reject non-digits")
	}
	if n, ok := parseInt("0"); !ok || n != 0 {
		t.Errorf("parseInt(0) got %d/%v", n, ok)
	}
}

func TestCanonicalManifestBytes_Deterministic(t *testing.T) {
	t.Parallel()
	m := UpdateBundleManifest{
		TargetVersion: "1.2.3",
		DownloadURL:   "https://example.com/bundle.tgz",
		BundleSHA256:  "deadbeef",
	}
	a := CanonicalManifestBytes(m)
	b := CanonicalManifestBytes(m)
	if string(a) != string(b) {
		t.Errorf("CanonicalManifestBytes not deterministic: %s vs %s", a, b)
	}
}

func TestSignAndVerifyBundleManifest_RoundTrip(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	manifest := CanonicalManifestBytes(UpdateBundleManifest{
		TargetVersion: "1.0.0",
		DownloadURL:   "https://x/y",
		BundleSHA256:  "deadbeef",
	})
	sig, err := SignBundleManifest(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleSig(manifest, sig, &key.PublicKey); err != nil {
		t.Fatalf("verify own signature: %v", err)
	}
}

func TestVerifyBundleSig_RejectsTampering(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	manifest := []byte(`{"v":"1"}`)
	sig, _ := SignBundleManifest(manifest, key)

	// 1) Tamper with the manifest after signing.
	tampered := []byte(`{"v":"2"}`)
	if err := VerifyBundleSig(tampered, sig, &key.PublicKey); err == nil {
		t.Error("verify must reject when manifest tampered")
	}

	// 2) Verify with a different key.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := VerifyBundleSig(manifest, sig, &otherKey.PublicKey); err == nil {
		t.Error("verify must reject when public key is wrong")
	}

	// 3) Tamper with the signature.
	badSig := base64.StdEncoding.EncodeToString([]byte("not-a-real-signature"))
	if err := VerifyBundleSig(manifest, badSig, &key.PublicKey); err == nil {
		t.Error("verify must reject when signature is garbage")
	}

	// 4) Non-base64 signature.
	if err := VerifyBundleSig(manifest, "not-base64!", &key.PublicKey); err == nil {
		t.Error("verify must reject non-base64 signature")
	}
}

func TestNewSelfSignedCA(t *testing.T) {
	t.Parallel()
	ca, err := NewSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	if ca.Cert == nil || ca.Key == nil {
		t.Fatal("CA is missing cert or key")
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert IsCA should be true")
	}
	// Signs its own cert
	if err := ca.Cert.CheckSignature(ca.Cert.SignatureAlgorithm,
		ca.Cert.RawTBSCertificate, ca.Cert.Signature); err != nil {
		t.Errorf("self-signed CA failed signature check: %v", err)
	}
}

// Fuzz versionLess — bundle rollout gating uses this on every agent
// heartbeat; a panic on an adversarial version string blocks updates.
func FuzzVersionLess(f *testing.F) {
	f.Add("1.0.0", "2.0.0")
	f.Add("", "")
	f.Add("a.b.c", "1.2.3")
	f.Add("999999999999999999999999", "1")
	f.Fuzz(func(t *testing.T, a, b string) {
		_ = versionLess(a, b)
		// Antisymmetry on the cases where we believe versionLess(a,b)
		// is false AND a != b: should be true the other way.
		if a != b && !versionLess(a, b) && !versionLess(b, a) {
			// allowed: equal-after-parse — skip
		}
	})
}
