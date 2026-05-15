// aws_sigv4.go — thin compatibility layer over the shared awssig
// package. Kept in-package so existing test files (aws_sigv4_test.go)
// continue to drive the same symbols.
package cloudposture

import (
	"net/http"

	"github.com/zaishield/vaultscan/backend/internal/awssig"
)

// AWSCredentials are the per-account secrets used to sign requests.
type AWSCredentials = awssig.Credentials

const emptyPayloadSHA256 = awssig.EmptyPayloadSHA256

func signRequestSigV4(req *http.Request, region, service string, creds AWSCredentials) error {
	return awssig.Sign(req, region, service, creds)
}

func sha256hex(b []byte) string       { return awssig.SHA256Hex(b) }
func hmacSHA256(key, msg []byte) []byte { return awssig.HmacSHA256(key, msg) }

// canonicalURI / canonicalQueryString / uriEncode kept as thin wrappers
// because the existing tests in aws_sigv4_test.go call them directly.
// They're internal-only — no external caller hits these.
func canonicalURI(path string) string                    { return awssig.CanonicalURI(path) }
func canonicalQueryString(v map[string][]string) string  { return awssig.CanonicalQueryString(v) }
func uriEncode(s string, encodeSlash bool) string        { return awssig.URIEncode(s, encodeSlash) }
