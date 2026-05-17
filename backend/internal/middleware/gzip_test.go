package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Gzip middleware must:
//   1. Pass through when the client didn't ask for gzip
//   2. Pass through SSE / pre-encoded responses
//   3. Pass through small responses (< minBytes)
//   4. Compress large responses when the client asked
//   5. Set Content-Encoding: gzip + Vary: Accept-Encoding on compressed
//   6. NEVER set Content-Encoding: gzip on a passthrough

func TestGzip_PassthroughWhenClientDidNotAsk(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("hello-world-", 2000) // big enough to qualify
	h := Gzip(512)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	// No Accept-Encoding header.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding=%q want empty for non-gzip client", got)
	}
	if rec.Body.String() != body {
		t.Errorf("body mutated: len=%d want %d", rec.Body.Len(), len(body))
	}
}

func TestGzip_CompressesLargeJSON(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("hello-world-", 2000) // ~24KB, compresses well
	h := Gzip(512)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding=%q want gzip", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary=%q must include Accept-Encoding", got)
	}
	// Decompress and confirm we get the original body back.
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	out, _ := io.ReadAll(gz)
	if string(out) != body {
		t.Errorf("round-trip mismatch: len=%d want %d", len(out), len(body))
	}
	// Compressed size should be much smaller than original.
	if rec.Body.Len() >= len(body)/2 {
		t.Errorf("compression poor: gz=%d original=%d", rec.Body.Len(), len(body))
	}
}

func TestGzip_PassesThroughSSE(t *testing.T) {
	t.Parallel()
	h := Gzip(64)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(strings.Repeat("event: ping\ndata: {}\n\n", 100)))
	}))
	req := httptest.NewRequest("GET", "/sse", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got == "gzip" {
		t.Error("SSE must NOT be compressed (breaks chunked streaming)")
	}
}

func TestGzip_PassesThroughSmallBodies(t *testing.T) {
	t.Parallel()
	h := Gzip(1024)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got == "gzip" {
		t.Error("tiny body should not be gzipped (framing overhead)")
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("body mutated: %q", rec.Body.String())
	}
}

func TestGzip_PreservesAlreadyEncodedResponses(t *testing.T) {
	t.Parallel()
	h := Gzip(64)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br") // caller already brotli'd
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding=%q must stay 'br' — middleware should not re-encode", got)
	}
}
