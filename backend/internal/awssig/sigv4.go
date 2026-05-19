// Package awssig is a stdlib-only AWS Signature Version 4 implementation.
// Used by both the cloud-posture adapters (which call AWS APIs to read
// CIS controls) and the evidence vault's S3 backend (PUT/GET/DELETE
// against S3-compatible object stores).
//
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//
// Algorithm:
//
//   1. Build CanonicalRequest:
//        HTTPMethod\n
//        CanonicalURI\n
//        CanonicalQueryString\n
//        CanonicalHeaders\n   (sorted, lowercase, trimmed)
//        SignedHeaders\n      (semicolon-joined header names)
//        HexSHA256(payload)
//
//   2. Build StringToSign:
//        AWS4-HMAC-SHA256\n
//        ISO8601 timestamp (yyyymmddThhmmssZ)\n
//        CredentialScope (yyyymmdd/region/service/aws4_request)\n
//        HexSHA256(CanonicalRequest)
//
//   3. Derive SigningKey:
//        kDate    = HMAC("AWS4"+SecretKey, yyyymmdd)
//        kRegion  = HMAC(kDate, region)
//        kService = HMAC(kRegion, service)
//        kSigning = HMAC(kService, "aws4_request")
//
//   4. Signature = HexHMAC(kSigning, StringToSign)
//
//   5. Authorization header:
//        AWS4-HMAC-SHA256 Credential=<key>/<scope>,
//          SignedHeaders=<list>, Signature=<hex>
package awssig

import (
	"crypto/hmac"
	"crypto/sha256"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials are the per-account secrets used to sign requests.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional; used for STS-assumed roles
}

// EmptyPayloadSHA256 is the SHA256 of an empty body, used by GET /
// HEAD / DELETE that have no payload.
const EmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// MaxBodyBytes caps the SigV4 body buffer at 16 MiB. The payload
// hash for AWS signature v4 requires the full body, so we must read
// it in memory before signing — but a request with a multi-gigabyte
// body would OOM the signer. AWS recommends STREAMING-AWS4-HMAC-
// SHA256-PAYLOAD for large objects; this package targets KMS / SES /
// other small-body APIs where 16 MiB is plenty. Callers that need
// large-object signing should use the streaming path (out of scope
// here).
const MaxBodyBytes = 16 << 20

// Sign mutates req to carry the Authorization + X-Amz-Date headers
// required by AWS API endpoints. Body is read once (and reset) so the
// payload hash is computed correctly.
//
// Buffer hardening (vs. the previous implementation):
//   - Cap body read at MaxBodyBytes via io.LimitReader.
//   - Reuse the same []byte buffer for both the hash and the body
//     reset (bytes.NewReader), avoiding the prior `string(body)`
//     intermediate copy. Halves the peak heap during signing of
//     medium-sized payloads.
func Sign(req *http.Request, region, service string, creds Credentials) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := EmptyPayloadSHA256
	if req.Body != nil {
		// LimitReader caps at MaxBodyBytes+1 so we can detect "too big"
		// without a separate check on req.ContentLength (which is often
		// -1 / unknown for chunked encodings).
		body, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyBytes+1))
		if err != nil {
			return fmt.Errorf("sigv4: read body: %w", err)
		}
		_ = req.Body.Close()
		if int64(len(body)) > MaxBodyBytes {
			return fmt.Errorf("sigv4: body exceeds %d bytes; use streaming signing for large objects", MaxBodyBytes)
		}
		payloadHash = SHA256Hex(body)
		// bytes.NewReader wraps the EXISTING slice without copying;
		// strings.NewReader(string(body)) used to allocate a second
		// copy of the body in immutable string form.
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.URL.Host)
	}

	canonURI := canonicalURI(req.URL.Path)
	canonQS := canonicalQueryString(req.URL.Query())
	canonHeaders, signedHeaders := canonicalHeaders(req.Header, req.URL.Host)
	canonReq := strings.Join([]string{
		req.Method, canonURI, canonQS, canonHeaders, signedHeaders, payloadHash,
	}, "\n")

	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credScope, SHA256Hex([]byte(canonReq)),
	}, "\n")

	kDate := HmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp))
	kRegion := HmacSHA256(kDate, []byte(region))
	kService := HmacSHA256(kRegion, []byte(service))
	kSigning := HmacSHA256(kService, []byte("aws4_request"))

	sig := hex.EncodeToString(HmacSHA256(kSigning, []byte(stringToSign)))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credScope, signedHeaders, sig)
	req.Header.Set("Authorization", auth)
	return nil
}

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func HmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// CanonicalURI / CanonicalQueryString / URIEncode are exported for
// callers (and tests) that want to compose these primitives directly,
// e.g. for presigned URLs or alternate signing flows.
func CanonicalURI(path string) string                            { return canonicalURI(path) }
func CanonicalQueryString(v map[string][]string) string          { return canonicalQueryString(url.Values(v)) }
func URIEncode(s string, encodeSlash bool) string                { return uriEncode(s, encodeSlash) }

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s, false)
	}
	return strings.Join(segments, "/")
}

func canonicalQueryString(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pairs []string
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			pairs = append(pairs, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(pairs, "&")
}

func canonicalHeaders(h http.Header, host string) (string, string) {
	flat := map[string]string{
		"host": host,
	}
	for k, v := range h {
		lk := strings.ToLower(k)
		if lk == "authorization" {
			continue
		}
		flat[lk] = strings.TrimSpace(strings.Join(v, ","))
	}
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(flat[k])
		b.WriteString("\n")
	}
	return b.String(), strings.Join(keys, ";")
}

// uriEncode RFC3986-encodes s. AWS docs: "/" is unreserved in path
// components but reserved in query.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}
