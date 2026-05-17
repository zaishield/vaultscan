package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MaxBodySize must:
//   1. Allow a body smaller than the cap to read in full.
//   2. Cause io.ReadAll to error when the body exceeds the cap.
// Without this middleware, a 1 GB POST would happily allocate 1 GB
// inside json.NewDecoder.
func TestMaxBodySize_AllowsUnderLimit(t *testing.T) {
	t.Parallel()
	mw := MaxBodySize(1 << 10) // 1 KiB
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll under limit errored: %v", err)
		}
		if len(body) != 512 {
			t.Errorf("read %d bytes, want 512", len(body))
		}
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(make([]byte, 512)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != 204 {
		t.Errorf("status=%d want 204", rec.Result().StatusCode)
	}
}

func TestMaxBodySize_RejectsOverLimit(t *testing.T) {
	t.Parallel()
	mw := MaxBodySize(1 << 10) // 1 KiB
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("ReadAll on oversized body should error")
		}
		// http.MaxBytesReader sets the status to 413 automatically when
		// the cap is hit inside a JSON decoder, but for raw ReadAll the
		// handler must check the error and respond. Stub a 413 here.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(make([]byte, 4096))) // 4 KiB > 1 KiB
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode == 200 {
		t.Errorf("oversize body got 200; expected 413 or similar error path")
	}
}

// Default cap (when limit ≤ 0) is 32 MiB.
func TestMaxBodySize_ZeroLimitDefaults(t *testing.T) {
	t.Parallel()
	mw := MaxBodySize(0)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Probe by writing 5 MiB — well under the 32 MiB default.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("5 MiB read errored: %v", err)
		}
		if len(body) != 5<<20 {
			t.Errorf("len=%d want %d", len(body), 5<<20)
		}
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(make([]byte, 5<<20)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != 204 {
		t.Errorf("status=%d want 204", rec.Result().StatusCode)
	}
}
