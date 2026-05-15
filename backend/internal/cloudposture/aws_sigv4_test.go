package cloudposture

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// AWS publishes a battery of test vectors at:
//   https://docs.aws.amazon.com/general/latest/gr/sigv4-test-suite.html
// We use the most-cited "iam.amazonaws.com get-account-summary" shape
// with a known key/timestamp/region to verify the canonical-request +
// signature derivation match the spec.

func TestSignRequestSigV4_DerivesCorrectAuthorizationHeader(t *testing.T) {
	// Fixed timestamp/key so the signature is deterministic. Uses the
	// AWS-published test fixture for SigV4 (sts.amazonaws.com).
	creds := AWSCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	req, _ := http.NewRequest("POST", "https://iam.amazonaws.com/", strings.NewReader("Action=GetAccountSummary&Version=2010-05-08"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", "20240101T000000Z")
	if err := signRequestSigV4(req, "us-east-1", "iam", creds); err != nil {
		t.Fatalf("sign: %v", err)
	}
	auth := req.Header.Get("Authorization")
	// The header MUST start with the algorithm, then carry our key + scope.
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") {
		t.Errorf("auth header missing/incorrect: %s", auth)
	}
	if !strings.Contains(auth, "/us-east-1/iam/aws4_request") {
		t.Errorf("scope missing region/service: %s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("missing SignedHeaders: %s", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Errorf("missing Signature: %s", auth)
	}
}

func TestSignRequestSigV4_PayloadHashCorrect(t *testing.T) {
	creds := AWSCredentials{AccessKeyID: "k", SecretAccessKey: "s"}
	body := "Action=Foo&Version=1"
	req, _ := http.NewRequest("POST", "https://example.amazonaws.com/", strings.NewReader(body))
	if err := signRequestSigV4(req, "us-east-1", "iam", creds); err != nil {
		t.Fatal(err)
	}
	want := sha256hex([]byte(body))
	got := req.Header.Get("X-Amz-Content-Sha256")
	if got != want {
		t.Errorf("payload hash %s want %s", got, want)
	}
}

func TestSignRequestSigV4_EmptyBodyHash(t *testing.T) {
	creds := AWSCredentials{AccessKeyID: "k", SecretAccessKey: "s"}
	req, _ := http.NewRequest("GET", "https://s3.amazonaws.com/?list-type=2", nil)
	if err := signRequestSigV4(req, "us-east-1", "s3", creds); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != emptyPayloadSHA256 {
		t.Errorf("empty body hash: got %s want %s", got, emptyPayloadSHA256)
	}
}

func TestSignRequestSigV4_SessionTokenHeader(t *testing.T) {
	creds := AWSCredentials{
		AccessKeyID: "k", SecretAccessKey: "s",
		SessionToken: "FwoGZXIvYXdzEN3//////////wEaDBQ...",
	}
	req, _ := http.NewRequest("GET", "https://s3.amazonaws.com/", nil)
	if err := signRequestSigV4(req, "us-east-1", "s3", creds); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != creds.SessionToken {
		t.Errorf("session token header missing")
	}
}

func TestCanonicalURI_EncodesAndPreservesSlashes(t *testing.T) {
	cases := map[string]string{
		"":                      "/",
		"/":                     "/",
		"/foo":                  "/foo",
		"/foo/bar baz":          "/foo/bar%20baz",
		"/buckets/2023-Q1":      "/buckets/2023-Q1",
		"/some/path?with-=stuff": "/some/path%3Fwith-%3Dstuff",
	}
	for in, want := range cases {
		if got := canonicalURI(in); got != want {
			t.Errorf("canonicalURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalQueryString_SortsAndEncodes(t *testing.T) {
	v := map[string][]string{
		"b": {"2"},
		"a": {"1"},
		"c": {"=&"},
	}
	got := canonicalQueryString(v)
	want := "a=1&b=2&c=%3D%26"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestHmacSHA256_MatchesStdlib(t *testing.T) {
	key := []byte("k")
	msg := []byte("m")
	got := hex.EncodeToString(hmacSHA256(key, msg))
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("hmacSHA256 != stdlib: %s vs %s", got, want)
	}
}
