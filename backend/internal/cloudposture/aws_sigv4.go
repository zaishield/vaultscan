// aws_sigv4.go — AWS Signature Version 4 implementation.
//
// AWS API requests authenticated via access key + secret are signed
// using SigV4 (AWS Signature Version 4). The full algorithm:
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
//
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
package cloudposture

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSCredentials are the per-account secrets used to sign requests.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional; used for STS-assumed roles
}

// signRequestSigV4 mutates req to carry the Authorization +
// X-Amz-Date headers required by AWS API endpoints. Body is read once
// (and reset) so the payload hash is computed correctly.
func signRequestSigV4(req *http.Request, region, service string, creds AWSCredentials) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Read body for payload hash (and rewind).
	payloadHash := emptyPayloadSHA256
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("sigv4: read body: %w", err)
		}
		_ = req.Body.Close()
		payloadHash = sha256hex(body)
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
	}

	// Mandatory headers.
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// 1. Canonical request.
	canonURI := canonicalURI(req.URL.Path)
	canonQS := canonicalQueryString(req.URL.Query())
	canonHeaders, signedHeaders := canonicalHeaders(req.Header, req.URL.Host)
	canonReq := strings.Join([]string{
		req.Method, canonURI, canonQS, canonHeaders, signedHeaders, payloadHash,
	}, "\n")

	// 2. String to sign.
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credScope, sha256hex([]byte(canonReq)),
	}, "\n")

	// 3. Signing key.
	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// 4. Signature.
	sig := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	// 5. Authorization header.
	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credScope, signedHeaders, sig)
	req.Header.Set("Authorization", auth)
	return nil
}

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// canonicalURI URI-encodes path segments per AWS rules. Single-segment
// paths and empty paths return "/".
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

// canonicalQueryString sorts query params by key and URI-encodes both
// keys and values. Multiple values per key are sorted.
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

// canonicalHeaders builds the canonical headers block + the
// semicolon-joined signed headers list. Header names are lowercased,
// values trimmed, and host is always included.
func canonicalHeaders(h http.Header, host string) (string, string) {
	// Materialise into lowercase map.
	flat := map[string]string{
		"host": host,
	}
	for k, v := range h {
		lk := strings.ToLower(k)
		// Skip Authorization (we're computing it) + non-required hop headers.
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

// uriEncode RFC3986-encodes s. AWS docs are explicit: "/" is unreserved
// in path components but reserved in query.
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
