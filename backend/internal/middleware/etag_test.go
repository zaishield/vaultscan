package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestETag_AddsHeaderOnGET(t *testing.T) {
	t.Parallel()
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if got := rec.Header().Get("ETag"); !strings.HasPrefix(got, `W/"`) {
		t.Errorf("ETag=%q expected weak tag", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
	if rec.Body.String() != `{"hello":"world"}` {
		t.Errorf("body mutated: %q", rec.Body.String())
	}
}

func TestETag_Returns304OnMatch(t *testing.T) {
	t.Parallel()
	// First call: capture the tag.
	body := `{"data":"v1"}`
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest("GET", "/x", nil))
	tag := rec1.Header().Get("ETag")
	if tag == "" {
		t.Fatal("first call missing ETag")
	}

	// Second call with If-None-Match → 304.
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("If-None-Match", tag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("status=%d want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 body must be empty; got %q", rec2.Body.String())
	}
}

func TestETag_WildcardMatch(t *testing.T) {
	t.Parallel()
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"any":"body"}`))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("If-None-Match", "*")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("status=%d want 304 (wildcard matches everything)", rec.Code)
	}
}

func TestETag_SkipsNonGET(t *testing.T) {
	t.Parallel()
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil))
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("POST should not get ETag; got %q", got)
	}
}

func TestETag_PreservesCustomStatusCode(t *testing.T) {
	t.Parallel()
	// Catches a regression: if the wrapper auto-calls WriteHeader(200)
	// before the handler-supplied status reaches the wire, the client
	// sees 200 OK on a 206 partial-content response.
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte(`{"partial":true}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusPartialContent {
		t.Errorf("status=%d want 206", rec.Code)
	}
}

func TestETag_SkipsSSE(t *testing.T) {
	t.Parallel()
	h := ETag()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/sse", nil))
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("SSE should not get ETag; got %q", got)
	}
}
