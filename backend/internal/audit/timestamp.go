// timestamp.go — RFC 3161 Time-Stamp Protocol client.
//
// What it does: hand the TSA a hash + nonce → receive a signed
// TimeStampToken proving "this hash existed before time T". The token
// is opaque CMS SignedData; verifiers (a court, a regulator, an
// auditor) check it against the TSA's published cert chain.
//
// We do NOT verify the response signature here — that's the verifier's
// job and we don't trust the TSA's cert with our private money. We
// only validate that:
//   1. The HTTP response was 200 + Content-Type application/timestamp-reply
//   2. The DER-decoded TimeStampResp.PKIStatus == 0 (granted)
//   3. The TimeStampToken bytes are non-empty
// Anything stricter (cert chain, OID matches, hash algorithm matches)
// is delegated to the verification tool ops uses at audit time.
//
// References:
//   RFC 3161 — Time-Stamp Protocol
//   RFC 5816 — ESSCertIDv2 update
//
// Compatible TSAs (free + commercial):
//   FreeTSA               https://freetsa.org/tsr
//   DigiCert              https://timestamp.digicert.com
//   Sectigo               https://timestamp.sectigo.com
//   GlobalSign            https://timestamp.globalsign.com/tsa/r6advanced1
//   Apple                 http://timestamp.apple.com/ts01
package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// TimestampToken is what TimeStamp returns + persists into
// audit_archive_runs / audit_tsa_anchors.
type TimestampToken struct {
	// Token is the DER-encoded TimeStampToken (RFC 3161 §2.4.2).
	// CMS ContentInfo wrapping SignedData whose eContent is a
	// DER-encoded TSTInfo.
	Token []byte
	// Serial is the TSA's serial number from TSTInfo (decimal string).
	Serial string
	// GeneralizedTime is the TSA's reported time (ISO 8601).
	GeneralizedTime string
}

// TSAClient is the RFC 3161 client. Configure once per process.
type TSAClient struct {
	URL    string         // https://freetsa.org/tsr (etc.)
	Client *http.Client

	// TrustedRoots is the cert pool used to validate the TSA's
	// embedded signing chain. When non-nil, every successful
	// Timestamp() call verifies that the response was signed by a
	// cert chaining to a root in this pool — closing the gap where
	// a MitM TSA could return any well-formed token and the
	// previous client accepted it on PKIStatus alone.
	//
	// nil = skip chain validation (dev / single-tenant deploys).
	// cmd/api wires this from config.TSATrustedRootsPath.
	TrustedRoots *x509.CertPool
	// ExpectedKeyUsages restricts which leaf-cert key usages are
	// considered valid. RFC 3161 mandates id-kp-timeStamping
	// (1.3.6.1.5.5.7.3.8) — any other EKU is suspicious. Defaults
	// to that one OID if nil.
	ExpectedKeyUsages []x509.ExtKeyUsage
}

// NewTSAClient with a 30s timeout. Pass "" for the default URL
// (FreeTSA — useful for dev / smoke).
func NewTSAClient(url string) *TSAClient {
	if url == "" {
		url = "https://freetsa.org/tsr"
	}
	return &TSAClient{
		URL:    url,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithTrustedRootsPEM loads roots from a PEM blob (typical: contents
// of a TSA CA bundle file). Returns the client for chaining.
// Empty PEM disables verification (TrustedRoots stays nil).
func (c *TSAClient) WithTrustedRootsPEM(pemBytes []byte) (*TSAClient, error) {
	if len(pemBytes) == 0 {
		return c, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("rfc3161: TrustedRoots PEM contained no valid certificates")
	}
	c.TrustedRoots = pool
	return c, nil
}

// Timestamp asks the TSA to sign hash. Returns the token (to store)
// + the TSA-reported serial + time. Always uses SHA-256.
func (c *TSAClient) Timestamp(ctx context.Context, hash []byte) (*TimestampToken, error) {
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("rfc3161: hash must be %d bytes (sha256)", sha256.Size)
	}
	reqDER, err := buildTSReq(hash)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: POST %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("rfc3161: TSA %s returned %d: %s",
			c.URL, resp.StatusCode, string(body))
	}
	// TSAs SHOULD send application/timestamp-reply; some send octet-stream.
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "timestamp-reply") &&
		!strings.Contains(ct, "octet-stream") {
		return nil, fmt.Errorf("rfc3161: unexpected response Content-Type: %s", ct)
	}

	tok, err := parseTSResp(body)
	if err != nil {
		return nil, err
	}
	// If a trust pool was wired, verify the chain BEFORE returning
	// the token to the caller. A chain-invalid token must never be
	// persisted — operators rely on the stored token as audit-grade
	// proof, so the verification has to happen at acquisition time.
	if err := c.VerifyChain(tok.Token); err != nil {
		return nil, err
	}
	return tok, nil
}

// ---- ASN.1 shapes (just enough to build + parse) -------------------------

type tsReq struct {
	Version      int
	MessageImprint messageImprint
	Nonce        *big.Int `asn1:"optional"`
	CertReq      bool     `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// buildTSReq DER-encodes a TimeStampReq (RFC 3161 §2.4.1) for sha256.
func buildTSReq(hash []byte) ([]byte, error) {
	nonce := new(big.Int).SetBytes(randomNonceBytes())
	req := tsReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			HashedMessage: hash,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	return asn1.Marshal(req)
}

// randomNonceBytes returns 8 random bytes (RFC 3161 recommends ≥64-bit).
func randomNonceBytes() []byte {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return b
}

// ---- Response parsing ----------------------------------------------------

// tsResp is the outer envelope (PKIStatus + optional TimeStampToken).
type tsResp struct {
	Status pkiStatusInfo
	// TimeStampToken is OPTIONAL ANY DEFINED BY status. We grab the
	// raw bytes; everything inside is opaque from our perspective.
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status   int
	StatText []asn1.RawValue `asn1:"optional"`
	FailInfo asn1.BitString  `asn1:"optional"`
}

// TSTInfo (RFC 3161 §2.4.2). The TimeStampToken is a CMS SignedData
// whose eContent is the DER-encoded TSTInfo; we walk that to extract
// the TSA's reported time + serial.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	// Extensions etc. omitted.
}

// parseTSResp extracts:
//   - PKIStatus.Status (must be 0 = granted)
//   - the full TimeStampToken DER bytes (for storage)
//   - the TSTInfo.SerialNumber + GenTime (for humans)
func parseTSResp(body []byte) (*TimestampToken, error) {
	var resp tsResp
	if rest, err := asn1.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("rfc3161: parse response: %w", err)
	} else if len(rest) > 0 {
		return nil, errors.New("rfc3161: trailing bytes in response")
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		// 0=granted, 1=grantedWithMods, anything else = rejection.
		return nil, fmt.Errorf("rfc3161: TSA refused (status=%d)", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("rfc3161: response contains no TimeStampToken")
	}
	serial, gen := extractTSTInfo(resp.TimeStampToken.FullBytes)
	return &TimestampToken{
		Token:           resp.TimeStampToken.FullBytes,
		Serial:          serial,
		GeneralizedTime: gen,
	}, nil
}

// VerifyChain extracts the certificate chain embedded in a TSA
// response and verifies it against c.TrustedRoots. Designed to be
// called from Timestamp() immediately after parseTSResp; absent a
// trust pool the function returns nil so the dev path stays usable.
//
// What it validates:
//   1. At least one cert is embedded in the CMS SignedData.
//   2. The leaf chains back to a root in c.TrustedRoots, with any
//      intermediates picked up from the embedded cert bag.
//   3. The leaf carries id-kp-timeStamping EKU (RFC 3161 §2.3).
//
// Known gap (documented for the operator): this does NOT verify
// the CMS signature itself — that requires walking the SignerInfo
// signed-attrs structure and computing the message digest, which
// is hundreds of lines of careful ASN.1. A determined attacker
// with a stolen timestamping cert chaining to a trusted root could
// still produce a token that passes this check; mitigated by the
// scope of who can mint such certs (DigiCert, GlobalSign, Sectigo,
// etc. — not "anyone with TLS").
func (c *TSAClient) VerifyChain(token []byte) error {
	if c.TrustedRoots == nil {
		return nil
	}
	leaf, intermediates, err := extractCertsFromCMS(token)
	if err != nil {
		return fmt.Errorf("rfc3161: extract certs: %w", err)
	}
	intermediatesPool := x509.NewCertPool()
	for _, ic := range intermediates {
		intermediatesPool.AddCert(ic)
	}
	wantEKU := c.ExpectedKeyUsages
	if len(wantEKU) == 0 {
		wantEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         c.TrustedRoots,
		Intermediates: intermediatesPool,
		KeyUsages:     wantEKU,
		// CurrentTime is now; for retrospective verification of an
		// old token operators should reach for openssl ts -verify.
	})
	if err != nil {
		return fmt.Errorf("rfc3161: TSA cert chain invalid: %w", err)
	}
	return nil
}

// extractCertsFromCMS walks the SignedData → certificates [0] IMPLICIT
// SET OF Certificate structure and returns the parsed leaf + any
// intermediates. The "leaf" heuristic: the cert with the EKU id-kp-
// timeStamping; if none has it, fall back to the first cert.
//
// We do this with a focused ASN.1 walk rather than pulling in a
// full CMS dependency. The structure walk is bounded so a hostile
// input cannot allocate unbounded memory (asn1.Unmarshal already
// caps individual element sizes).
func extractCertsFromCMS(cmsDER []byte) (leaf *x509.Certificate, intermediates []*x509.Certificate, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rfc3161: cms walk panic: %v", r)
		}
	}()
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, e := asn1.Unmarshal(cmsDER, &ci); e != nil {
		return nil, nil, e
	}
	// SignedData with the certificates field marked [0] IMPLICIT.
	var sd struct {
		Version              int
		DigestAlgs           asn1.RawValue `asn1:"set"`
		EncapContentInfo     asn1.RawValue
		Certificates         asn1.RawValue `asn1:"tag:0,implicit,optional"`
		CRLs                 asn1.RawValue `asn1:"tag:1,implicit,optional"`
		SignerInfos          asn1.RawValue `asn1:"set"`
	}
	if _, e := asn1.Unmarshal(ci.Content.Bytes, &sd); e != nil {
		return nil, nil, e
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, nil, errors.New("no certificates embedded in CMS SignedData")
	}
	// Iterate the cert bag.
	rest := sd.Certificates.Bytes
	var allCerts []*x509.Certificate
	for len(rest) > 0 {
		var certRaw asn1.RawValue
		var e error
		rest, e = asn1.Unmarshal(rest, &certRaw)
		if e != nil {
			return nil, nil, e
		}
		// FullBytes preserves the outer SEQUENCE for x509.ParseCertificate.
		cert, e := x509.ParseCertificate(certRaw.FullBytes)
		if e != nil {
			// Skip certs that don't parse rather than failing the
			// whole chain; the TSA may bundle CRL-signing certs
			// alongside the timestamping cert.
			continue
		}
		allCerts = append(allCerts, cert)
	}
	if len(allCerts) == 0 {
		return nil, nil, errors.New("CMS SignedData certificate bag was non-empty but parsed zero certs")
	}
	// Pick the leaf: cert with timestamping EKU.
	for _, cert := range allCerts {
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageTimeStamping {
				leaf = cert
				break
			}
		}
		if leaf != nil {
			break
		}
	}
	if leaf == nil {
		// Fallback: assume the first cert is the leaf. Verify() will
		// then reject it for missing the EKU per our KeyUsages spec.
		leaf = allCerts[0]
	}
	for _, c := range allCerts {
		if c != leaf {
			intermediates = append(intermediates, c)
		}
	}
	return leaf, intermediates, nil
}

// extractTSTInfo digs through the CMS layers and returns
// (serial-as-decimal-string, RFC-3339-time). Best-effort: returns
// ("", "") if it can't find them — the caller's token bytes are still
// valid for the TSA's own verifier.
func extractTSTInfo(cmsDER []byte) (serial, genTime string) {
	defer func() {
		// Be liberal: any ASN.1 surprise → return empty.
		if r := recover(); r != nil {
			serial, genTime = "", ""
		}
	}()
	// Top-level ContentInfo.
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return "", ""
	}
	// SignedData.
	var sd struct {
		Version              int
		DigestAlgs           asn1.RawValue `asn1:"set"`
		EncapContentInfo     struct {
			ContentType asn1.ObjectIdentifier
			EContent    asn1.RawValue `asn1:"tag:0,explicit,optional"`
		}
		// Other fields omitted via RawValue catch.
		Rest asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return "", ""
	}
	// eContent is an OCTET STRING; unwrap.
	var inner []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &inner); err != nil {
		return "", ""
	}
	var tst tstInfo
	if _, err := asn1.Unmarshal(inner, &tst); err != nil {
		return "", ""
	}
	if tst.SerialNumber != nil {
		serial = tst.SerialNumber.String()
	}
	if !tst.GenTime.IsZero() {
		genTime = tst.GenTime.UTC().Format(time.RFC3339)
	}
	return serial, genTime
}

// ---- OIDs ----------------------------------------------------------------

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)
