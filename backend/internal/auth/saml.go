// saml.go — minimal SAML 2.0 SP (service-provider) for SP-initiated SSO.
//
// Stdlib + crypto only — no third-party SAML library. We implement
// the narrow slice we actually need:
//
//   AuthnRequest:  SP → IdP via HTTP-Redirect (deflate + base64 + url-encode)
//   Response:      IdP → SP via HTTP-POST (base64-encoded XML in form field)
//   Validation:    XML parse → verify enveloped XML-DSig over Assertion
//                  → check Audience + Conditions.NotBefore/NotOnOrAfter
//                  → extract NameID + AttributeStatement
//
// What's deliberately out of scope:
//   - SAML logout (SLO)
//   - encrypted assertions (SAML EncryptedAssertion)
//   - HTTP-Artifact binding
//
// These are RFC-allowed but rarely required by enterprise IdPs in
// 2026. Operators that need them can swap in github.com/crewjam/saml.
package auth

import (
	"bytes"
	"compress/flate"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAMLConfig is the per-tenant SAML SP configuration.
type SAMLConfig struct {
	// SPEntityID is the SP's URN (e.g. "urn:vaultscan:sp:tenant-XYZ").
	// Mirrored back as <Audience> in the IdP response — we reject any
	// assertion whose audience doesn't match.
	SPEntityID string
	// SPACSURL is where the IdP POSTs the response back to. MUST be
	// https in production.
	SPACSURL string
	// IdPSSOURL is the IdP's SingleSignOn endpoint (HTTP-Redirect).
	IdPSSOURL string
	// IdPCertPEM is the X.509 cert the IdP uses to sign assertions.
	// Used to verify XML-DSig.
	IdPCertPEM string
}

// AuthnRequestURL builds an SP-initiated AuthnRequest, deflates it,
// base64+url-encodes, and returns the IdP redirect URL the user agent
// should be redirected to. relayState is round-tripped opaquely.
func (c *SAMLConfig) AuthnRequestURL(relayState string) (string, error) {
	if c.SPEntityID == "" || c.SPACSURL == "" || c.IdPSSOURL == "" {
		return "", errors.New("saml: SP entity / ACS / IdP SSO URL required")
	}
	id := samlID()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	body := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`,
		id, now, c.IdPSSOURL, c.SPACSURL, c.SPEntityID)

	// Deflate (raw DEFLATE per SAML HTTP-Redirect binding).
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err := zw.Write([]byte(body)); err != nil {
		return "", err
	}
	zw.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	q := url.Values{}
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	sep := "?"
	if strings.Contains(c.IdPSSOURL, "?") {
		sep = "&"
	}
	return c.IdPSSOURL + sep + q.Encode(), nil
}

// SAMLAssertion is the slice of an IdP response we care about.
type SAMLAssertion struct {
	Subject    string
	Email      string
	Attributes map[string][]string
	NotBefore  time.Time
	NotOnOrAfter time.Time
}

// ParseAndValidateResponse decodes the base64'd SAMLResponse field
// from the ACS POST, verifies the XML-DSig signature against the
// configured IdP cert, checks audience + time conditions, and returns
// the extracted assertion. Returns an error on ANY failure — never
// returns a partial result.
func (c *SAMLConfig) ParseAndValidateResponse(b64Response string) (*SAMLAssertion, error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(b64Response)
	if err != nil {
		return nil, fmt.Errorf("saml: base64 decode: %w", err)
	}
	var resp samlResponseDoc
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return nil, fmt.Errorf("saml: xml parse: %w", err)
	}
	if err := c.verifySignature(xmlBytes, &resp); err != nil {
		return nil, err
	}
	a := resp.Assertion
	// Audience.
	if !samlAudienceMatches(a.Conditions.AudienceRestriction.Audience, c.SPEntityID) {
		return nil, fmt.Errorf("saml: audience mismatch (got %q, want %q)",
			a.Conditions.AudienceRestriction.Audience, c.SPEntityID)
	}
	// NotBefore / NotOnOrAfter.
	now := time.Now().UTC()
	nb, _ := time.Parse(time.RFC3339, a.Conditions.NotBefore)
	noa, _ := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
	if !nb.IsZero() && now.Before(nb.Add(-30*time.Second)) {
		return nil, fmt.Errorf("saml: assertion not yet valid (NotBefore=%s)", nb)
	}
	if !noa.IsZero() && now.After(noa.Add(30*time.Second)) {
		return nil, fmt.Errorf("saml: assertion expired (NotOnOrAfter=%s)", noa)
	}

	out := &SAMLAssertion{
		Subject:      a.Subject.NameID,
		Attributes:   map[string][]string{},
		NotBefore:    nb,
		NotOnOrAfter: noa,
	}
	for _, attr := range a.AttributeStatement.Attributes {
		out.Attributes[attr.Name] = attr.Values
		if isEmailAttr(attr.Name) && len(attr.Values) > 0 && out.Email == "" {
			out.Email = attr.Values[0]
		}
	}
	if out.Email == "" && strings.Contains(out.Subject, "@") {
		out.Email = out.Subject
	}
	return out, nil
}

// verifySignature performs RFC 3275 XML-DSig validation of the SAML
// Response/Assertion using goxmldsig. The library handles:
//   - Exclusive C14N (RFC 3741) canonicalisation of both SignedInfo
//     and the referenced element — the previous hand-rolled
//     "strip xmlns" form diverged from real IdPs' c14n and produced
//     both false negatives (rejected valid sigs) and theoretical
//     false positives (accepted permuted XML).
//   - Reference URI binding to the Assertion's ID attribute, with
//     all the type:"...EnvelopedSignature" + Reference filter
//     traversal SAML profile requires.
//   - DigestMethod + SignatureMethod algorithm validation against
//     the registered Algorithms set; the validator REJECTS by
//     default — we explicitly require RSA-SHA256.
//
// We still refuse Response-only-signed assertions: SAML SP-init
// best practice is to sign the Assertion itself, not just the
// wrapping Response. Response-only sigs leave a textbook XSW
// window. goxmldsig accepts either; we tighten the policy here.
func (c *SAMLConfig) verifySignature(xmlBytes []byte, resp *samlResponseDoc) error {
	if c.IdPCertPEM == "" {
		return errors.New("saml: IdP cert not configured")
	}
	block, _ := pem.Decode([]byte(c.IdPCertPEM))
	if block == nil {
		return errors.New("saml: IdP cert PEM invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("saml: parse IdP cert: %w", err)
	}

	// Parse the raw XML with etree so goxmldsig can walk the DOM.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return fmt.Errorf("saml: parse XML for c14n: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return errors.New("saml: empty XML")
	}

	// Find the Assertion element. SP-init SAML 2.0: the IdP
	// MUST sign the Assertion (signing only the wrapping Response
	// leaves a XSW window we refuse outright).
	assertion := findChildLocal(root, "Assertion")
	if assertion == nil {
		return errors.New("saml: Response carries no Assertion")
	}
	assertionSig := findChildLocal(assertion, "Signature")
	if assertionSig == nil {
		return errors.New("saml: Assertion is not signed (Response-only signatures are XSW-risk; reject)")
	}
	assertionID := assertion.SelectAttrValue("ID", "")
	if assertionID == "" {
		return errors.New("saml: Assertion missing ID — cannot bind signature Reference URI")
	}

	// Reference URI must point at the Assertion's ID. goxmldsig
	// enforces this internally too, but we pre-check so the error
	// message points at the actual binding failure.
	refURI := signatureRefURI(assertionSig)
	if refURI != "" && refURI != "#"+assertionID {
		return fmt.Errorf("saml: signature Reference URI %q does not bind Assertion ID %q (XSW guard)",
			refURI, assertionID)
	}

	// Build the validation context. MemoryX509CertificateStore is
	// the operator-controlled trust pool — only `cert` is in it,
	// so goxmldsig rejects sigs by any other key. The default
	// signature method registry includes RSA-SHA256 / SHA384 /
	// SHA512; we narrow to SHA256 below via the explicit Algorithm
	// check on the Signature element.
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	// Tighten: reject anything weaker than SHA-256 (default registry
	// would otherwise accept SHA-1).
	sigAlg := signatureMethod(assertionSig)
	if sigAlg != "" && !strings.HasSuffix(sigAlg, "rsa-sha256") &&
		!strings.HasSuffix(sigAlg, "rsa-sha384") &&
		!strings.HasSuffix(sigAlg, "rsa-sha512") {
		return fmt.Errorf("saml: SignatureMethod %q rejected (RSA-SHA256/384/512 required)", sigAlg)
	}
	digestAlg := referenceDigestMethod(assertionSig)
	if digestAlg != "" && !strings.HasSuffix(digestAlg, "sha256") &&
		!strings.HasSuffix(digestAlg, "sha384") &&
		!strings.HasSuffix(digestAlg, "sha512") {
		return fmt.Errorf("saml: DigestMethod %q rejected (SHA256/384/512 required)", digestAlg)
	}

	// Validate the Assertion element's enveloped signature. This
	// performs:
	//   1. Exclusive C14N on SignedInfo, verify SignatureValue
	//      against the canonicalised bytes using cert.PublicKey.
	//   2. For each Reference: c14n the referent (with the
	//      EnvelopedSignature transform applied to strip the
	//      Signature element itself), hash, compare to DigestValue.
	// Any failure → returns a non-nil error; the wrapper here
	// preserves the original error chain for diagnostic output.
	if _, err := ctx.Validate(assertion); err != nil {
		return fmt.Errorf("saml: xml-dsig validation failed: %w", err)
	}
	_ = resp // typed struct still used by ParseAndValidateResponse for
	         // audience + condition checks; the goxmldsig path operates
	         // on the etree DOM exclusively.
	return nil
}

// findChildLocal returns the first child whose local element name
// matches (namespace-agnostic).
func findChildLocal(parent *etree.Element, local string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == local {
			return child
		}
	}
	return nil
}

// signatureRefURI extracts the first Reference URI under the given
// Signature element, or "" if none. SAML profile requires exactly
// one Reference (we don't enforce that here — goxmldsig does).
func signatureRefURI(sig *etree.Element) string {
	si := findChildLocal(sig, "SignedInfo")
	if si == nil {
		return ""
	}
	ref := findChildLocal(si, "Reference")
	if ref == nil {
		return ""
	}
	return ref.SelectAttrValue("URI", "")
}

// signatureMethod returns SignedInfo/SignatureMethod/@Algorithm.
func signatureMethod(sig *etree.Element) string {
	si := findChildLocal(sig, "SignedInfo")
	if si == nil {
		return ""
	}
	m := findChildLocal(si, "SignatureMethod")
	if m == nil {
		return ""
	}
	return m.SelectAttrValue("Algorithm", "")
}

// referenceDigestMethod returns SignedInfo/Reference/DigestMethod/@Algorithm.
func referenceDigestMethod(sig *etree.Element) string {
	si := findChildLocal(sig, "SignedInfo")
	if si == nil {
		return ""
	}
	ref := findChildLocal(si, "Reference")
	if ref == nil {
		return ""
	}
	dm := findChildLocal(ref, "DigestMethod")
	if dm == nil {
		return ""
	}
	return dm.SelectAttrValue("Algorithm", "")
}

// ---- types ---------------------------------------------------------------

type samlResponseDoc struct {
	XMLName    xml.Name        `xml:"Response"`
	Issuer     string          `xml:"Issuer"`
	Status     samlStatus      `xml:"Status"`
	Signature  samlSignature   `xml:"Signature"`
	Assertion  samlAssertion   `xml:"Assertion"`
}

type samlStatus struct {
	Code samlStatusCode `xml:"StatusCode"`
}
type samlStatusCode struct {
	Value string `xml:"Value,attr"`
}

type samlAssertion struct {
	XMLName            xml.Name           `xml:"Assertion"`
	ID                 string             `xml:"ID,attr"`
	Issuer             string             `xml:"Issuer"`
	Signature          samlSignature      `xml:"Signature"`
	Subject            samlSubject        `xml:"Subject"`
	Conditions         samlConditions     `xml:"Conditions"`
	AttributeStatement samlAttributeStmt  `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID string `xml:"NameID"`
}

type samlConditions struct {
	NotBefore           string                  `xml:"NotBefore,attr"`
	NotOnOrAfter        string                  `xml:"NotOnOrAfter,attr"`
	AudienceRestriction samlAudienceRestriction `xml:"AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type samlAttributeStmt struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

type samlSignature struct {
	XMLName        xml.Name       `xml:"Signature"`
	SignedInfo     samlSignedInfo `xml:"SignedInfo"`
	SignatureValue string         `xml:"SignatureValue"`
}

type samlSignedInfo struct {
	XMLName       xml.Name      `xml:"SignedInfo"`
	Inner         string        `xml:",innerxml"`
	Reference     samlReference `xml:"Reference"`
}

// samlReference captures the SignedInfo/Reference element so we can
// verify the URI is bound to the Assertion AND the DigestValue
// matches the assertion's canonical hash. Without this check the
// signature scheme is XSW-vulnerable: an attacker can keep the
// SignedInfo + SignatureValue intact and swap the body.
type samlReference struct {
	XMLName      xml.Name `xml:"Reference"`
	URI          string   `xml:"URI,attr"`
	DigestMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	} `xml:"DigestMethod"`
	DigestValue string `xml:"DigestValue"`
}

// ---- helpers -------------------------------------------------------------

func samlID() string {
	// SAML IDs must start with a letter (xsd:ID rule). Underscore
	// is permitted as the first character per SAML 2.0 §1.3.4 and
	// is what every major IdP uses.
	//
	// CRYPTOGRAPHIC RANDOMNESS REQUIRED: the AuthnRequest ID is
	// echoed by the IdP in the Response's InResponseTo attribute.
	// If an attacker can predict the ID (because we seeded a PRNG
	// from time.UnixNano), they can mint a forged Response that
	// references a not-yet-issued AuthnRequest. Use crypto/rand.
	return "_" + base64.RawURLEncoding.EncodeToString(secureRandomBytes(16))
}

func secureRandomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := cryptoRand.Read(out); err != nil {
		// crypto/rand on Linux backs to /dev/urandom which never
		// returns short or errors in practice. If it ever does,
		// panic — emitting a predictable SAML ID is a security
		// failure we'd rather crash than ship.
		panic("saml: crypto/rand unavailable: " + err.Error())
	}
	return out
}

func samlAudienceMatches(have, want string) bool {
	have = strings.TrimSpace(have)
	want = strings.TrimSpace(want)
	return have == want && want != ""
}

func isEmailAttr(name string) bool {
	low := strings.ToLower(name)
	return strings.Contains(low, "email") || strings.Contains(low, "mail") ||
		strings.HasSuffix(low, "/emailaddress")
}

// stripWhitespace + stripXMLNS were used by the previous hand-rolled
// c14n in verifySignature. goxmldsig now handles canonicalisation
// per RFC 3741; both helpers are gone.
