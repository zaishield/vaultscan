package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// makeSAMLTestCert generates a fresh RSA-2048 key + self-signed
// cert for use in SAML signing tests. Returns the private key + the
// PEM the verifier should trust.
func makeSAMLTestCert(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "saml-test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return priv, string(pemBytes)
}

// signedSAMLResponse builds a minimal SAML 2.0 Response containing
// a signed Assertion. Mirrors what real IdPs (Okta, Entra, Keycloak,
// Auth0) emit at the Assertion level; uses goxmldsig directly so
// the signing path matches the verification path.
func signedSAMLResponse(t *testing.T, priv *rsa.PrivateKey, certPEM, email string) []byte {
	t.Helper()
	doc := etree.NewDocument()
	resp := doc.CreateElement("Response")
	resp.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:protocol")

	assertion := resp.CreateElement("Assertion")
	assertion.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", "_assertion-1")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))

	issuer := assertion.CreateElement("Issuer")
	issuer.SetText("https://idp.example.com/")

	subject := assertion.CreateElement("Subject")
	nameID := subject.CreateElement("NameID")
	nameID.SetText(email)

	conds := assertion.CreateElement("Conditions")
	conds.CreateAttr("NotBefore", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	conds.CreateAttr("NotOnOrAfter", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	audr := conds.CreateElement("AudienceRestriction")
	aud := audr.CreateElement("Audience")
	aud.SetText("urn:vaultscan:sp:test-tenant")

	attrStmt := assertion.CreateElement("AttributeStatement")
	emailAttr := attrStmt.CreateElement("Attribute")
	emailAttr.CreateAttr("Name", "email")
	emailV := emailAttr.CreateElement("AttributeValue")
	emailV.SetText(email)

	// Sign the Assertion with goxmldsig.
	store := &keyStore{priv: priv, certPEM: certPEM}
	signingCtx := dsig.NewDefaultSigningContext(store)
	signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signingCtx.SignEnveloped(assertion)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}
	resp.RemoveChild(assertion)
	resp.AddChild(signed)

	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("doc.WriteToBytes: %v", err)
	}
	return out
}

// keyStore implements dsig.X509KeyStore for the test fixture.
type keyStore struct {
	priv    *rsa.PrivateKey
	certPEM string
}

func (k *keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	block, _ := pem.Decode([]byte(k.certPEM))
	if block == nil {
		return nil, nil, errSAMLTestCertBad
	}
	return k.priv, block.Bytes, nil
}

var errSAMLTestCertBad = &samlTestErr{msg: "could not decode test cert PEM"}

type samlTestErr struct{ msg string }

func (e *samlTestErr) Error() string { return e.msg }

// _ silences `strings` import when only used in test bodies.
var _ = strings.Contains
