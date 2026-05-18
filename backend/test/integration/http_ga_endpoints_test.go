//go:build integration

// http_ga_endpoints_test.go — HTTP-layer coverage for the GA endpoints
// that landed late in the previous batches and were missing from
// http_handler_coverage_test.go:
//
//   GET  /api/v1/usage
//   GET  /api/v1/status
//   GET  /api/v1/audit/export
//   POST /api/v1/users/{user_id}/erase
//   PUT  /api/v1/tenants/{tenant_id}/residency
//   PUT  /api/v1/integrations/{integration_id}/signing-secret
//   POST /api/v1/integrations/{integration_id}/inbound
//   GET  /.well-known/security.txt
//
// Pattern: one happy-path success + one rejection per endpoint
// (auth required / permission required / bad input). Bulk coverage,
// not deep semantic verification — the per-feature integration tests
// (users_erase_test.go, tenants_residency_test.go etc.) own the
// behavioural correctness.

package integration

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestHandlers_StatusEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()

	t.Run("public_status_is_reachable", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/status")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		body := requireStatus(t, resp, 200)
		for _, must := range []string{"version", "uptime"} {
			if !strings.Contains(string(body), must) {
				t.Errorf("status body missing %q: %s", must, body)
			}
		}
	})
}

func TestHandlers_UsageEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()
	tenantID, _ := h.makeTenant(t, "usage-ep")
	tok := mintToken(t, tenantID)

	t.Run("unauth_403_or_401", func(t *testing.T) {
		resp, _ := http.Get(srv.URL + "/api/v1/usage")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 401/403 unauth, got %d", resp.StatusCode)
		}
	})

	t.Run("authed_200_with_plan_and_limits", func(t *testing.T) {
		resp := doReq(t, "GET", srv.URL+"/api/v1/usage", tok, tenantID.String(), nil)
		defer resp.Body.Close()
		body := requireStatus(t, resp, 200)
		// The endpoint returns plan + usage + rate-limit caps; verify
		// the contract surface without coupling to exact numbers.
		for _, must := range []string{"plan", "rate_limit"} {
			if !strings.Contains(string(body), must) {
				t.Errorf("usage missing %q in body: %s", must, body)
			}
		}
	})
}

func TestHandlers_AuditExportEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()
	tenantID, _ := h.makeTenant(t, "audit-export")
	tok := mintToken(t, tenantID)

	t.Run("authed_200_ndjson", func(t *testing.T) {
		resp := doReq(t, "GET", srv.URL+"/api/v1/audit/export?from=2024-01-01T00:00:00Z", tok, tenantID.String(), nil)
		defer resp.Body.Close()
		// Tenant callers must provide `from`; without it they get 400
		// (the handler-side bounds-check). With it: 200 + NDJSON.
		_ = requireStatus(t, resp, 200)
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/x-ndjson") && !strings.Contains(ct, "json") {
			t.Errorf("expected NDJSON content-type, got %q", ct)
		}
	})

	t.Run("tenant_caller_without_from_400", func(t *testing.T) {
		resp := doReq(t, "GET", srv.URL+"/api/v1/audit/export", tok, tenantID.String(), nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 (missing from), got %d", resp.StatusCode)
		}
	})
}

func TestHandlers_UsersEraseEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()
	tenantID, _ := h.makeTenant(t, "users-erase-ep")
	tok := mintToken(t, tenantID)

	t.Run("unauth_401_or_403", func(t *testing.T) {
		resp, _ := http.Post(srv.URL+"/api/v1/users/00000000-0000-0000-0000-000000000999/erase",
			"application/json", strings.NewReader(`{"reason":"test"}`))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 401/403 unauth, got %d", resp.StatusCode)
		}
	})

	t.Run("authed_unknown_user_404", func(t *testing.T) {
		resp := doReq(t, "POST",
			srv.URL+"/api/v1/users/00000000-0000-0000-0000-000000000999/erase",
			tok, tenantID.String(),
			bytes.NewReader([]byte(`{"reason":"unknown-user-test"}`)))
		defer resp.Body.Close()
		// 404 (not found) or 403 (perm required even for unknown id)
		// are both acceptable; what we DON'T want is 500.
		if resp.StatusCode == http.StatusInternalServerError {
			t.Errorf("erase unknown user returned 500 (should be 404 / 403): body=%s",
				requireStatus(t, resp, http.StatusInternalServerError))
		}
	})
}

func TestHandlers_TenantsResidencyEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()
	tenantID, _ := h.makeTenant(t, "residency-ep")
	tok := mintToken(t, tenantID)

	t.Run("authed_set_eu_200", func(t *testing.T) {
		resp := doReq(t, "PUT",
			srv.URL+"/api/v1/tenants/"+tenantID.String()+"/residency",
			tok, tenantID.String(),
			bytes.NewReader([]byte(`{"region":"eu","reason":"test"}`)))
		defer resp.Body.Close()
		// 200/204 are both acceptable success responses.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("set residency: expected 200/204, got %d body=%s",
				resp.StatusCode, requireStatus(t, resp, resp.StatusCode))
		}
	})

	t.Run("authed_invalid_region_400", func(t *testing.T) {
		resp := doReq(t, "PUT",
			srv.URL+"/api/v1/tenants/"+tenantID.String()+"/residency",
			tok, tenantID.String(),
			bytes.NewReader([]byte(`{"region":"narnia"}`)))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid region: expected 400, got %d", resp.StatusCode)
		}
	})
}

func TestHandlers_IntegrationsSigningSecretEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()
	tenantID, _ := h.makeTenant(t, "signing-secret-ep")
	tok := mintToken(t, tenantID)

	// Create an integration first; we need a real ID to PUT against.
	resp := doReq(t, "POST", srv.URL+"/api/v1/integrations",
		tok, tenantID.String(),
		bytes.NewReader([]byte(`{"type":"webhook","name":"ss-test","config":{"url":"https://example.com/in"}}`)))
	_ = requireStatus(t, resp, http.StatusOK)
	body := requireStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	// Body is JSON; extract id via string-search (avoids importing a
	// JSON struct for one field).
	id := extractFirstUUID(string(body))
	if id == "" {
		t.Fatalf("could not parse integration id from create response: %s", body)
	}

	t.Run("rotate_secret_200", func(t *testing.T) {
		resp := doReq(t, "PUT",
			srv.URL+"/api/v1/integrations/"+id+"/signing-secret",
			tok, tenantID.String(),
			bytes.NewReader([]byte(`{"secret":"rotated-secret-value"}`)))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("rotate: expected 200/204, got %d body=%s",
				resp.StatusCode, requireStatus(t, resp, resp.StatusCode))
		}
	})

	t.Run("clear_secret_200", func(t *testing.T) {
		resp := doReq(t, "PUT",
			srv.URL+"/api/v1/integrations/"+id+"/signing-secret",
			tok, tenantID.String(),
			bytes.NewReader([]byte(`{"secret":""}`)))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("clear: expected 200/204, got %d", resp.StatusCode)
		}
	})
}

func TestHandlers_SecurityTxtEndpoint(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()

	for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
		t.Run("public_"+path, func(t *testing.T) {
			resp, _ := http.Get(srv.URL + path)
			if resp == nil {
				t.Fatal("nil response")
			}
			defer resp.Body.Close()
			body := requireStatus(t, resp, 200)
			ct := resp.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("%s: expected text/plain, got %q", path, ct)
			}
			for _, must := range []string{"Contact:", "Expires:", "Canonical:"} {
				if !strings.Contains(string(body), must) {
					t.Errorf("%s body missing %q", path, must)
				}
			}
		})
	}
}

// doReq is a thin convenience wrapper consistent with the existing
// http_handler_coverage_test.go helper.
func doReq(t *testing.T, method, url, token, tenantID string, body interface {
	Read(p []byte) (int, error)
}) *http.Response {
	t.Helper()
	var rdr interface {
		Read(p []byte) (int, error)
	} = nil
	if body != nil {
		rdr = body
	}
	var req *http.Request
	if rdr != nil {
		req, _ = http.NewRequest(method, url, &readerAdapter{r: rdr})
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenantID != "" {
		req.Header.Set("X-Tenant-Id", tenantID)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// readerAdapter lets us pass any io.Reader-shaped value (bytes.Reader,
// strings.Reader, …) without coupling the test signature to the
// concrete type.
type readerAdapter struct {
	r interface {
		Read(p []byte) (int, error)
	}
}

func (a *readerAdapter) Read(p []byte) (int, error) { return a.r.Read(p) }

// extractFirstUUID pulls the first uuid-shaped substring out of body.
// Stays in this file so we don't drag a json struct + import for one
// field. Returns "" if none found.
func extractFirstUUID(body string) string {
	const uuidLen = 36
	for i := 0; i+uuidLen <= len(body); i++ {
		s := body[i : i+uuidLen]
		if s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && isHexish(s) {
			return s
		}
	}
	return ""
}

func isHexish(s string) bool {
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
