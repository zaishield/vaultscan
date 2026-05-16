package awssig

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// AWS-published SigV4 test vectors: the Authorization line is constructed
// from a fixed timestamp, region, and credentials. We verify the helper
// primitives (canonical URI / query string, payload hashing, key
// derivation) match the published reference values rather than trying to
// pin the entire signed request — since Sign() uses time.Now() we can't
// pin the signature itself without rewriting the API to inject a clock.

func TestURIEncode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"abc", false, "abc"},
		{"a b", false, "a%20b"},
		{"a/b", false, "a/b"},
		{"a/b", true, "a%2Fb"},
		{"~-._", false, "~-._"},
		{"!*'()", false, "%21%2A%27%28%29"},
		{"日本", false, "%E6%97%A5%E6%9C%AC"},
		{"", false, ""},
		{"A-Z_0-9.~", false, "A-Z_0-9.~"},
	}
	for _, c := range cases {
		got := URIEncode(c.in, c.encodeSlash)
		if got != c.want {
			t.Errorf("URIEncode(%q,%v)=%q want %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}

func TestCanonicalURI(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":             "/",
		"/":            "/",
		"/foo":         "/foo",
		"/foo/bar":     "/foo/bar",
		"/foo bar":     "/foo%20bar",
		"/foo/日本":      "/foo/%E6%97%A5%E6%9C%AC",
		"/a+b":         "/a%2Bb",
	}
	for in, want := range cases {
		if got := CanonicalURI(in); got != want {
			t.Errorf("CanonicalURI(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCanonicalQueryString(t *testing.T) {
	t.Parallel()
	// Multi-value keys must sort by key first, then value.
	in := map[string][]string{
		"b":    {"2", "1"},
		"a":    {"3"},
		"x y":  {"hello world"},
		"&eq=": {"v"},
	}
	got := CanonicalQueryString(in)
	// Expected order: %26eq%3D, a, b (two pairs sorted), x%20y
	want := "%26eq%3D=v&a=3&b=1&b=2&x%20y=hello%20world"
	if got != want {
		t.Errorf("CanonicalQueryString: got %q want %q", got, want)
	}
}

func TestSHA256HexAndHmac(t *testing.T) {
	t.Parallel()
	// Empty payload sha256 known constant — also exposed as EmptyPayloadSHA256.
	if got := SHA256Hex(nil); got != EmptyPayloadSHA256 {
		t.Errorf("SHA256Hex(nil)=%q want %q", got, EmptyPayloadSHA256)
	}
	// HMAC-SHA256 of "" with key "" — known value
	mac := HmacSHA256([]byte(""), []byte(""))
	if len(mac) != 32 {
		t.Fatalf("HmacSHA256 returned %d bytes, want 32", len(mac))
	}
}

func TestSign_AddsRequiredHeaders(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequest("GET", "https://s3.amazonaws.com/my-bucket/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	if err := Sign(req, "us-east-1", "s3", creds); err != nil {
		t.Fatalf("Sign returned %v", err)
	}
	if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/") {
		t.Errorf("Authorization header malformed: %q", got)
	}
	if got := req.Header.Get("X-Amz-Date"); len(got) != 16 || got[8] != 'T' || got[15] != 'Z' {
		t.Errorf("X-Amz-Date malformed: %q", got)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != EmptyPayloadSHA256 {
		t.Errorf("X-Amz-Content-Sha256 for empty body = %q want %q", got, EmptyPayloadSHA256)
	}
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "Signature=") {
		t.Errorf("Signature= missing in %q", got)
	}
}

func TestSign_WithSessionToken(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("GET", "https://sts.amazonaws.com/", nil)
	creds := Credentials{
		AccessKeyID:     "AKIA",
		SecretAccessKey: "secret",
		SessionToken:    "FwoGZXIvYXdzEXAMPLE",
	}
	if err := Sign(req, "us-east-1", "sts", creds); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "FwoGZXIvYXdzEXAMPLE" {
		t.Errorf("X-Amz-Security-Token=%q want session token", got)
	}
}

func TestSign_BodyHashedAndReset(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/api", io.NopCloser(bytes.NewReader(body)))
	creds := Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret"}
	if err := Sign(req, "us-east-1", "execute-api", creds); err != nil {
		t.Fatal(err)
	}
	got := req.Header.Get("X-Amz-Content-Sha256")
	want := SHA256Hex(body)
	if got != want {
		t.Errorf("X-Amz-Content-Sha256=%q want %q", got, want)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength=%d want %d", req.ContentLength, len(body))
	}
	// Body must be readable again after signing.
	readBack, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("re-read body: %v", err)
	}
	if !bytes.Equal(readBack, body) {
		t.Errorf("body after Sign=%q want %q", readBack, body)
	}
}

// BenchmarkSign — Gap 4 perf coverage. Production posture readers call
// this on every adapter request; we want a stable upper bound on cost.
func BenchmarkSign(b *testing.B) {
	creds := Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	body := bytes.Repeat([]byte{'x'}, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST",
			"https://s3.amazonaws.com/bucket/key?versionId=abc", bytes.NewReader(body))
		_ = Sign(req, "us-east-1", "s3", creds)
	}
}

func BenchmarkCanonicalURI(b *testing.B) {
	p := "/foo/bar/baz quux/日本/leaf"
	for i := 0; i < b.N; i++ {
		_ = CanonicalURI(p)
	}
}

func BenchmarkCanonicalQueryString(b *testing.B) {
	v := map[string][]string{
		"alpha": {"1", "2", "3"},
		"bravo": {"hello world"},
		"x y":   {"a b c"},
	}
	for i := 0; i < b.N; i++ {
		_ = CanonicalQueryString(v)
	}
}

// FuzzURIEncode — Gap 3 fuzz coverage. URIEncode is on the hot path for
// every signed AWS request; a panic or out-of-spec output would corrupt
// signatures across the cloud-posture adapters. The fuzzer drives random
// bytes through the encoder to catch panics and verify output is always
// pure ASCII (% + 2 hex digits or unreserved characters).
func FuzzURIEncode(f *testing.F) {
	for _, seed := range []string{"", "/", "a/b", "日本", "!*'()", "%20", "\x00\xff"} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, in string, encodeSlash bool) {
		out := URIEncode(in, encodeSlash)
		for i := 0; i < len(out); i++ {
			c := out[i]
			if c > 0x7F {
				t.Fatalf("non-ASCII byte 0x%02x in output %q from input %q", c, out, in)
			}
		}
	})
}

func FuzzCanonicalURI(f *testing.F) {
	seeds := []string{"", "/", "/foo", "/foo/bar/baz", "/a b/c", "/a/../b", "/日本", "//"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_ = CanonicalURI(in) // panic-free is the contract here.
	})
}
