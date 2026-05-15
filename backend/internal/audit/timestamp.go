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

	return parseTSResp(body)
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
	// Walk the CMS structure to pull out TSTInfo. CMS shape:
	//   ContentInfo {
	//     contentType: id-signedData,
	//     content:     SignedData {
	//       version:  ..., digestAlgorithms: ...,
	//       encapContentInfo: { contentType: id-ct-TSTInfo, eContent: <TSTInfo DER> },
	//       certificates: ..., signerInfos: ...,
	//     }
	//   }
	// We don't want to import a full CMS lib; do a narrow walk.
	serial, gen := extractTSTInfo(resp.TimeStampToken.FullBytes)
	return &TimestampToken{
		Token:           resp.TimeStampToken.FullBytes,
		Serial:          serial,
		GeneralizedTime: gen,
	}, nil
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
