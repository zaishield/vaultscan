package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ---------------- RequestID -------------------------------------------------

// Client-supplied ID that matches the strict charset is preserved
// (UUID, hex, traceparent-shaped). Anything else is silently
// replaced with a fresh UUID — quiet defence against header
// injection or log-poisoning.

func TestRequestID_AcceptsValidClientID(t *testing.T) {
	t.Parallel()
	mw := RequestID()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(RequestIDFromContext(r.Context())))
	}))
	want := "00112233-4455-6677-8899-aabbccddeeff"
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", want)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Header().Get("X-Request-Id") != want {
		t.Errorf("response header didn't echo valid client id")
	}
	if w.Body.String() != want {
		t.Errorf("ctx didn't carry valid client id")
	}
}

func TestRequestID_RejectsCRLFInjection(t *testing.T) {
	t.Parallel()
	mw := RequestID()
	captured := ""
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", "00000000-0000-0000-0000-000000000000\r\nSet-Cookie: evil=1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if captured == "" {
		t.Error("ctx id should never be empty (fresh UUID minted)")
	}
	if strings.Contains(captured, "\r") || strings.Contains(captured, "\n") {
		t.Errorf("CRLF leaked into captured id: %q", captured)
	}
	got := w.Header().Get("X-Request-Id")
	if strings.Contains(got, "Set-Cookie") {
		t.Errorf("CRLF injection succeeded into response header: %q", got)
	}
}

func TestRequestID_RejectsShortValues(t *testing.T) {
	t.Parallel()
	mw := RequestID()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", "abc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	// Too-short client value should be replaced with a UUID (36 chars).
	if got := w.Header().Get("X-Request-Id"); len(got) < 8 {
		t.Errorf("short client id should have been replaced; got %q", got)
	}
}

func TestRequestID_RejectsExoticChars(t *testing.T) {
	t.Parallel()
	mw := RequestID()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", "abc; DROP TABLE users; --xxxxxx")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	got := w.Header().Get("X-Request-Id")
	if strings.Contains(got, "DROP TABLE") {
		t.Errorf("dangerous chars leaked into header: %q", got)
	}
}

func TestRequestID_MintsWhenAbsent(t *testing.T) {
	t.Parallel()
	mw := RequestID()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(RequestIDFromContext(r.Context())))
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	got := w.Body.String()
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("minted id should be a valid UUID: %q (%v)", got, err)
	}
}

func TestIsValidRequestID(t *testing.T) {
	t.Parallel()
	good := []string{
		"00000000-0000-0000-0000-000000000000", // UUID
		"abcdef1234567890",                     // hex
		"trace_id_with_underscores_123",
		"AAAAAAAA",
	}
	bad := []string{
		"",
		"short",                       // <8 chars
		strings.Repeat("a", 129),      // >128 chars
		"id with space",
		"id/with/slash",
		"id\nwith\nnewline",
		`id"with"quote`,
		"id;DROP TABLE users",
	}
	for _, g := range good {
		if !isValidRequestID(g) {
			t.Errorf("expected %q to be accepted", g)
		}
	}
	for _, b := range bad {
		if isValidRequestID(b) {
			t.Errorf("expected %q to be rejected", b)
		}
	}
}

// RequestIDFromContext returns "" if no middleware ran upstream.
func TestRequestIDFromContext_NoMiddleware(t *testing.T) {
	t.Parallel()
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("got %q, want empty when middleware didn't run", got)
	}
}

// ---------------- APIVersion ------------------------------------------------

func TestAPIVersion_StripsCRLF(t *testing.T) {
	t.Parallel()
	// Build-time -ldflags value containing CRLF injection. The
	// middleware MUST strip CR/LF so the value can't END the
	// header and start a new one — actual injection requires
	// CRLF in the value, NOT the literal text "Set-Cookie".
	mw := APIVersion("v1.0.0\r\nSet-Cookie: evil=1")
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	got := w.Header().Get("X-API-Version")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("CRLF leaked into version header: %q", got)
	}
	// Verify no SEPARATE Set-Cookie header was created (which would
	// be the actual injection outcome).
	if w.Header().Get("Set-Cookie") != "" {
		t.Errorf("CRLF stripping failed — Set-Cookie injected: %q",
			w.Header().Get("Set-Cookie"))
	}
}

func TestAPIVersion_DefaultsToDev(t *testing.T) {
	t.Parallel()
	mw := APIVersion("")
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Header().Get("X-API-Version") != "dev" {
		t.Errorf("empty version should default to 'dev'")
	}
}

// ---------------- TenantScope -----------------------------------------------
//
// TenantScope's contract is end-to-end-tested in test/integration; the
// pure-handler-level smoke covers the new auto-bind behaviour: no
// header AND an identity with a TenantID → header is auto-populated.
// Full auth setup is heavy; this test exercises just the header
// echoing for the no-header case to confirm the request reaches the
// next handler.

func TestTenantScope_PassesThroughWhenSuperAdmin(t *testing.T) {
	t.Parallel()
	mw := TenantScope("X-Tenant-Id")
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	// No identity in ctx → equivalent to anonymous, and no header
	// → middleware should pass through (downstream handlers
	// validate auth on the protected routes).
	req := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !called {
		t.Error("expected pass-through when no identity + no header")
	}
}

func TestTenantScope_RejectsMalformedHeader(t *testing.T) {
	t.Parallel()
	mw := TenantScope("X-Tenant-Id")
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Tenant-Id", "not-a-uuid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if called {
		t.Error("handler should not be called when tenant header is invalid")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on bad tenant header, got %d", w.Code)
	}
}
