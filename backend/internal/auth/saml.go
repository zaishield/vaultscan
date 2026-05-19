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
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
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

// verifySignature walks the SignedInfo element, computes the canonical
// digest, and verifies the SignatureValue against the IdP cert.
//
// This is a minimal implementation that handles the common shape:
// enveloped signature on either Response or Assertion, RSA-SHA256.
// verifySignature performs RSA-SHA256 verification of a SAML Response
// / Assertion signature. The XML-DSig profile requires TWO checks:
//
//   1. SignatureValue verifies against SignedInfo via the IdP's RSA
//      public key — proves the IdP produced THIS SignedInfo.
//   2. SignedInfo/Reference/DigestValue equals the canonical hash of
//      the element the Reference URI points at — proves the signed
//      content has not been swapped (XML Signature Wrapping).
//
// The previous implementation only did step (1), which is a textbook
// XSW vulnerability — an attacker keeps SignedInfo+SignatureValue
// intact and substitutes the Assertion body. CVE-class.
//
// This implementation does both. Canonicalisation here is the
// approximate "strip xmlns" form used by the previous code — that
// remains a divergence from RFC 3275 Exclusive C14N and may fail
// against IdPs that include attribute reordering or namespace
// inheritance. For those, an operator should pull goxmldsig.
//
// Air-gap-safe (no external libs added).
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
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("saml: IdP cert is not RSA")
	}
	// Locate the signature. Prefer the Assertion-level signature —
	// signing only the wrapping Response leaves a XSW window where
	// the Assertion can be swapped beneath a valid Response sig.
	// We refuse "Response-signed but Assertion-unsigned" outright;
	// SAML 2.0 best practice requires the Assertion itself to be
	// signed for SP-initiated SSO.
	sig := &resp.Assertion.Signature
	if sig.SignatureValue == "" {
		return errors.New("saml: Assertion is not signed (Response-only signatures are XSW-risk; reject)")
	}
	if resp.Assertion.ID == "" {
		return errors.New("saml: Assertion missing ID — cannot bind signature Reference URI")
	}
	// The signature's Reference URI must point at this Assertion.
	// `URI="#&lt;assertion_id&gt;"` is the SAML convention; bare empty URI
	// (meaning "the entire document") is permitted by XML-DSig but
	// NOT by the SAML profile.
	expectURI := "#" + resp.Assertion.ID
	if sig.SignedInfo.Reference.URI != expectURI {
		return fmt.Errorf("saml: signature Reference URI %q does not bind Assertion ID %q (XSW guard)",
			sig.SignedInfo.Reference.URI, resp.Assertion.ID)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(stripWhitespace(sig.SignatureValue))
	if err != nil {
		return fmt.Errorf("saml: signature base64: %w", err)
	}

	// (1) Verify SignatureValue against SignedInfo bytes.
	signedInfoXML, err := xml.Marshal(sig.SignedInfo)
	if err != nil {
		return err
	}
	signedInfoXML = stripXMLNS(signedInfoXML)
	siDigest := sha256.Sum256(signedInfoXML)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, siDigest[:], sigBytes); err != nil {
		return fmt.Errorf("saml: SignatureValue verification failed: %w", err)
	}

	// (2) Verify the Reference DigestValue against the Assertion's
	// canonical hash. Without this, signature scheme is XSW-vulnerable.
	// Algorithm must be SHA-256; refuse anything weaker.
	if !strings.HasSuffix(sig.SignedInfo.Reference.DigestMethod.Algorithm, "sha256") &&
		sig.SignedInfo.Reference.DigestMethod.Algorithm != "" {
		return fmt.Errorf("saml: unsupported DigestMethod %q (sha256 required)",
			sig.SignedInfo.Reference.DigestMethod.Algorithm)
	}
	declaredDigest, err := base64.StdEncoding.DecodeString(
		stripWhitespace(sig.SignedInfo.Reference.DigestValue))
	if err != nil {
		return fmt.Errorf("saml: DigestValue base64: %w", err)
	}
	if len(declaredDigest) == 0 {
		return errors.New("saml: empty Reference DigestValue")
	}
	// Hash the actual Assertion element bytes. We re-marshal the typed
	// struct and apply the same canonicalisation as for SignedInfo.
	// IMPORTANT: this is an approximation of Exclusive C14N (RFC 3275).
	// If you observe a real IdP whose hash doesn't match, do NOT just
	// disable the check — pull in goxmldsig.
	assertionXML, err := xml.Marshal(&resp.Assertion)
	if err != nil {
		return fmt.Errorf("saml: marshal Assertion for digest: %w", err)
	}
	assertionXML = stripXMLNS(assertionXML)
	bodyDigest := sha256.Sum256(assertionXML)
	if subtle.ConstantTimeCompare(declaredDigest, bodyDigest[:]) != 1 {
		return errors.New("saml: Reference DigestValue does not match Assertion canonical hash (XSW detected or canonicalisation mismatch)")
	}
	return nil
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

func stripWhitespace(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\n' && r != '\r' && r != '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripXMLNS(b []byte) []byte {
	// Drop xmlns="..." attributes. Naive but effective for this scope.
	s := string(b)
	for {
		idx := strings.Index(s, " xmlns=\"")
		if idx < 0 {
			break
		}
		end := strings.Index(s[idx+8:], "\"")
		if end < 0 {
			break
		}
		s = s[:idx] + s[idx+8+end+1:]
	}
	return []byte(s)
}
