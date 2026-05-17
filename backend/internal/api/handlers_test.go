package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/middleware"
)

// The api package's pure helpers are tiny but they're on every
// response path. A typo in the error envelope shape breaks every
// frontend that consumes the contract. Locked down with explicit
// unit tests so a stray refactor can't silently rename `error.code`.

func decodeEnvelope(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return got
}

func TestWriteJSON_SetsContentTypeAndStatus(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]int{"n": 7})
	resp := rec.Result()
	if got := resp.StatusCode; got != http.StatusCreated {
		t.Errorf("status=%d want 201", got)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type=%q", ct)
	}
	body := decodeEnvelope(t, resp.Body)
	if body["n"].(float64) != 7 {
		t.Errorf("body=%v", body)
	}
}

func TestBadRequest_EnvelopeShape(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	badRequest(rec, "missing field 'name'")
	resp := rec.Result()
	if resp.StatusCode != 400 {
		t.Errorf("status=%d want 400", resp.StatusCode)
	}
	body := decodeEnvelope(t, resp.Body)
	errEnv := body["error"].(map[string]any)
	if errEnv["code"] != "bad_request" {
		t.Errorf("code=%v", errEnv["code"])
	}
	if !strings.Contains(errEnv["message"].(string), "missing field") {
		t.Errorf("message lost: %v", errEnv["message"])
	}
}

func TestNotFound_EnvelopeShape(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	notFound(rec)
	resp := rec.Result()
	if resp.StatusCode != 404 {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
	body := decodeEnvelope(t, resp.Body)
	if body["error"].(map[string]any)["code"] != "not_found" {
		t.Errorf("code wrong: %v", body)
	}
}

func TestForbidden_EnvelopeShape(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	forbidden(rec, "tenant scope mismatch")
	if rec.Result().StatusCode != 403 {
		t.Errorf("status=%d want 403", rec.Result().StatusCode)
	}
	body := decodeEnvelope(t, rec.Body)
	if body["error"].(map[string]any)["code"] != "forbidden" {
		t.Errorf("code wrong: %v", body)
	}
}

func TestInternalErr_EnvelopeShape(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	internalErr(rec, errors.New("boom: secret-table.column"))
	if rec.Result().StatusCode != 500 {
		t.Errorf("status=%d want 500", rec.Result().StatusCode)
	}
	body := decodeEnvelope(t, rec.Body)
	envelope := body["error"].(map[string]any)
	if envelope["code"] != "internal" {
		t.Errorf("code = %v want 'internal'", envelope["code"])
	}
	// Critical: raw err MUST NOT appear in the response. internalErr
	// previously echoed err.Error() and leaked SQL table/column names,
	// file paths, and stack-trace fragments. Operators see the full
	// err via the package logger; clients see a stable generic message.
	msg, _ := envelope["message"].(string)
	if strings.Contains(msg, "boom") || strings.Contains(msg, "secret-table") {
		t.Errorf("internal err leaked into response: %q", msg)
	}
	if msg == "" {
		t.Errorf("internal response must carry a generic message; got empty")
	}
}

func TestDecode_NilBodyErrors(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("POST", "/", nil)
	r.Body = nil
	var v map[string]any
	if err := decode(r, &v); err == nil {
		t.Error("nil body should error")
	}
}

func TestDecode_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hello":"world","n":7}`)
	r := httptest.NewRequest("POST", "/", io.NopCloser(bytes.NewReader(body)))
	var v map[string]any
	if err := decode(r, &v); err != nil {
		t.Fatal(err)
	}
	if v["hello"] != "world" || v["n"].(float64) != 7 {
		t.Errorf("decoded=%v", v)
	}
}

func TestDecode_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("POST", "/", io.NopCloser(bytes.NewReader([]byte(`{not json`))))
	var v map[string]any
	if err := decode(r, &v); err == nil {
		t.Error("malformed JSON must error")
	}
}

func TestClientIP_TrustsXFFOnlyFromTrustedProxy(t *testing.T) {
	// NOT parallel — we mutate the package-level trusted-proxy list.
	saved := middleware.TrustedProxyCIDRs
	defer func() { middleware.TrustedProxyCIDRs = saved }()

	_, trust10, _ := net.ParseCIDR("10.0.0.0/8")
	middleware.TrustedProxyCIDRs = []*net.IPNet{trust10}

	t.Run("xff_honoured_from_trusted_proxy", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.99:443"
		r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
		got := clientIP(r)
		if got == nil || got.String() != "203.0.113.5" {
			t.Errorf("X-Forwarded-For not parsed when peer is trusted proxy: %v", got)
		}
	})

	t.Run("xff_ignored_from_untrusted_peer", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.7:443" // public IP, NOT in 10/8
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		got := clientIP(r)
		if got == nil || got.String() != "198.51.100.7" {
			t.Errorf("X-Forwarded-For honoured from untrusted peer (IP-spoof vulnerability): %v", got)
		}
	})
}

func TestClientIP_DefaultIgnoresXFF(t *testing.T) {
	// NOT parallel — see above.
	saved := middleware.TrustedProxyCIDRs
	defer func() { middleware.TrustedProxyCIDRs = saved }()
	middleware.TrustedProxyCIDRs = nil // simulate default config

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.99:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	got := clientIP(r)
	if got == nil || got.String() != "10.0.0.99" {
		t.Errorf("default config must NOT trust X-Forwarded-For: %v", got)
	}
}

func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.42:1234"
	got := clientIP(r)
	if got == nil || got.String() != "10.0.0.42" {
		t.Errorf("RemoteAddr not parsed: %v", got)
	}
}

func TestClientIP_HandlesIPv6(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::1]:8080"
	got := clientIP(r)
	if got == nil || got.String() != "::1" {
		t.Errorf("IPv6 RemoteAddr not parsed: %v", got)
	}
}

func TestClientIP_HandlesNoPort(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.7"
	// SplitHostPort fails on bare IP; clientIP returns nil — that's
	// the documented contract (caller must handle nil).
	_ = clientIP(r)
}

// Fuzz clientIP — X-Forwarded-For is attacker-controlled (set by the
// LB or by anyone if the LB isn't stripping it). Must never panic.
func FuzzClientIP(f *testing.F) {
	f.Add("10.0.0.1", "")
	f.Add("", "203.0.113.5")
	f.Add("[::1]:8080", "")
	f.Add("garbage", "more garbage, even more")
	f.Add("", "x, y, z, a.b.c.d")
	f.Fuzz(func(t *testing.T, remoteAddr, xff string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		_ = clientIP(r) // panic-free is the contract
	})
}
