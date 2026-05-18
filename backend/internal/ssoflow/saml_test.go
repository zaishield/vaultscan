package ssoflow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// buildSampleMetadata generates a fresh self-signed cert and embeds
// it in a realistic-looking IdP metadata blob. Using a real cert lets
// parseSAMLMetadata's x509.ParseCertificate check pass.
func buildSampleMetadata(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	return fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/sso/saml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="https://idp.example/sso/saml/redirect"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://idp.example/sso/saml/post"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, b64)
}

func TestParseSAMLMetadata_FindsRedirectBindingAndCert(t *testing.T) {
	ssoURL, certPEM, err := parseSAMLMetadata(buildSampleMetadata(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ssoURL != "https://idp.example/sso/saml/redirect" {
		t.Errorf("ssoURL=%q want HTTP-Redirect binding location", ssoURL)
	}
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certPEM not PEM-encoded:\n%s", certPEM)
	}
}

func TestParseSAMLMetadata_Errors(t *testing.T) {
	cases := []string{
		``,
		`<EntityDescriptor/>`,
		`<EntityDescriptor><IDPSSODescriptor/></EntityDescriptor>`, // no SSO location
		`<EntityDescriptor>
		   <IDPSSODescriptor>
		     <SingleSignOnService Binding="x" Location="https://idp/x"/>
		   </IDPSSODescriptor>
		 </EntityDescriptor>`, // SSO location but no cert
	}
	for _, c := range cases {
		_, _, err := parseSAMLMetadata(c)
		if err == nil {
			t.Errorf("expected error for input: %.40q", c)
		}
	}
}

func TestSamlAttributesToMap_HandlesCommonSynonyms(t *testing.T) {
	a := &auth.SAMLAssertion{
		Email:   "user@example.com",
		Subject: "user@example.com",
		Attributes: map[string][]string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": {"Test User"},
			"http://schemas.xmlsoap.org/claims/Group":                    {"client_admin", "auditor"},
		},
	}
	m := samlAttributesToMap(a)
	if m["email"][0] != "user@example.com" {
		t.Errorf("email missing: %v", m["email"])
	}
	if len(m["name"]) == 0 || m["name"][0] != "Test User" {
		t.Errorf("name not projected: %v", m["name"])
	}
	if len(m["roles"]) != 2 {
		t.Errorf("roles not projected: %v", m["roles"])
	}
}

func TestCodeChallengeS256_IsDeterministic(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c := codeChallengeS256(v)
	// RFC 7636 example.
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if c != expected {
		t.Errorf("got %q want %q", c, expected)
	}
}

func TestRandString_Length(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		s, err := randString(n)
		if err != nil {
			t.Fatalf("randString(%d): %v", n, err)
		}
		// base64.RawURLEncoding has no padding; len ≈ ceil(n*4/3).
		decoded, _ := base64.RawURLEncoding.DecodeString(s)
		if len(decoded) != n {
			t.Errorf("randString(%d) decoded to %d bytes", n, len(decoded))
		}
	}
}
