package auth

import (
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestAuthnRequestURL_Shape(t *testing.T) {
	t.Parallel()
	c := &SAMLConfig{
		SPEntityID: "urn:vaultscan:sp:tenant-XYZ",
		SPACSURL:   "https://api.vaultscan.zaishield.com/saml/acs",
		IdPSSOURL:  "https://idp.example.com/sso",
	}
	uStr, err := c.AuthnRequestURL("post-login=/findings")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uStr)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "idp.example.com" || u.Path != "/sso" {
		t.Errorf("wrong IdP URL: %s", uStr)
	}
	q := u.Query()
	if q.Get("RelayState") != "post-login=/findings" {
		t.Errorf("relay state not preserved: %s", q.Get("RelayState"))
	}
	enc := q.Get("SAMLRequest")
	if enc == "" {
		t.Fatal("no SAMLRequest")
	}
	// Decode + inflate the AuthnRequest body and verify it carries
	// our SP entity ID + ACS URL.
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	zr := flate.NewReader(strings.NewReader(string(raw)))
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	bs := string(body)
	if !strings.Contains(bs, "urn:vaultscan:sp:tenant-XYZ") {
		t.Errorf("entity ID missing from AuthnRequest: %s", bs)
	}
	if !strings.Contains(bs, "AssertionConsumerServiceURL=\"https://api.vaultscan.zaishield.com/saml/acs\"") {
		t.Errorf("ACS URL missing: %s", bs)
	}
}

func TestAuthnRequestURL_RejectsEmptyConfig(t *testing.T) {
	t.Parallel()
	if _, err := (&SAMLConfig{}).AuthnRequestURL(""); err == nil {
		t.Error("empty config should error")
	}
}

func TestAudienceMatches(t *testing.T) {
	t.Parallel()
	if !samlAudienceMatches("urn:x", "urn:x") {
		t.Error("equal should match")
	}
	if samlAudienceMatches("", "") {
		t.Error("both-empty must NOT match (audience is required)")
	}
	if samlAudienceMatches("urn:a", "urn:b") {
		t.Error("differing should not match")
	}
	if !samlAudienceMatches(" urn:x ", "urn:x") {
		t.Error("trim should make 'urn:x' = ' urn:x '")
	}
}

func TestIsEmailAttr(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"mail":            true,
		"email":           true,
		"emailAddress":    true,
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": true,
		"upn":             false,
		"displayName":     false,
	}
	for in, want := range cases {
		if got := isEmailAttr(in); got != want {
			t.Errorf("isEmailAttr(%q)=%v want %v", in, got, want)
		}
	}
}

func TestParseAndValidateResponse_RejectsNoCert(t *testing.T) {
	t.Parallel()
	c := &SAMLConfig{SPEntityID: "x"}
	if _, err := c.ParseAndValidateResponse(base64.StdEncoding.EncodeToString(
		[]byte(`<Response><Assertion></Assertion></Response>`))); err == nil {
		t.Error("no cert configured → must error")
	}
}

// TestStripWhitespace removed — the helper it tested was replaced
// by goxmldsig's c14n implementation.

// TestSAMLSignedAssertion_RoundTrip generates a key + signed SAML
// Assertion via goxmldsig, hands it to ParseAndValidateResponse,
// and asserts the verifier accepts it. Catches any regression in
// our Exclusive C14N wiring against the same library the IdPs we
// integrate with use under the hood.
func TestSAMLSignedAssertion_RoundTrip(t *testing.T) {
	t.Parallel()
	// Generate a 2048-bit RSA key + self-signed cert.
	priv, certPEM := makeSAMLTestCert(t)
	signedXML := signedSAMLResponse(t, priv, certPEM, "alice@example.com")

	cfg := &SAMLConfig{
		SPEntityID: "urn:vaultscan:sp:test-tenant",
		IdPCertPEM: certPEM,
	}
	a, err := cfg.ParseAndValidateResponse(base64.StdEncoding.EncodeToString(signedXML))
	if err != nil {
		t.Fatalf("validate signed assertion: %v", err)
	}
	if a.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %q", a.Email)
	}
}

// TestSAMLTamperedAssertion_RejectedByDigest mutates the signed
// Assertion's NameID after signing; the validator MUST refuse.
func TestSAMLTamperedAssertion_RejectedByDigest(t *testing.T) {
	t.Parallel()
	priv, certPEM := makeSAMLTestCert(t)
	signedXML := signedSAMLResponse(t, priv, certPEM, "alice@example.com")
	tampered := strings.Replace(string(signedXML), "alice@example.com",
		"attacker@example.com", 1)

	cfg := &SAMLConfig{SPEntityID: "urn:vaultscan:sp:test-tenant", IdPCertPEM: certPEM}
	if _, err := cfg.ParseAndValidateResponse(base64.StdEncoding.EncodeToString(
		[]byte(tampered))); err == nil {
		t.Fatal("expected tampered Assertion to be rejected by digest mismatch")
	}
}
