package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeprecatedSetsHeaders(t *testing.T) {
	sunset := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	h := Deprecated(sunset, "/api/v2/things")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/things", nil))

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Fatalf("Deprecation header = %q want true", got)
	}
	if got := rec.Header().Get("Sunset"); got != sunset.Format(http.TimeFormat) {
		t.Fatalf("Sunset header = %q want %q", got, sunset.Format(http.TimeFormat))
	}
	if got := rec.Header().Get("Link"); got == "" {
		t.Fatalf("Link header empty")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d want 200", rec.Code)
	}
}

func TestDeprecatedNoSuccessorOmitsLink(t *testing.T) {
	h := Deprecated(time.Now().Add(24*time.Hour), "")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if got := rec.Header().Get("Link"); got != "" {
		t.Fatalf("Link should be empty when no successor, got %q", got)
	}
}

func TestGoneReturns410(t *testing.T) {
	h := Gone("/api/v2/things")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/things", nil))

	if rec.Code != http.StatusGone {
		t.Fatalf("code = %d want 410", rec.Code)
	}
	if got := rec.Header().Get("Link"); got == "" {
		t.Fatal("Link missing")
	}
}
