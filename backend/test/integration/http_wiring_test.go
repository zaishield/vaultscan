//go:build integration

// HTTP-level smoke test that exercises the newly-wired VS-05..VS-12 +
// HS routes through chi.Mount. Without this, we'd only know the
// services compile — not that the router actually serves them.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/api"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/guardrails"
)

const testJWTSecret = "test-shared-secret-vaultscan-acceptance"

// mountAPI spins a fully-wired chi router on top of the harness. The
// returned cleanup closes the test server.
func mountAPI(t *testing.T, h *harness) (*httptest.Server, func()) {
	t.Helper()
	verifier := auth.NewVerifier(testJWTSecret, h.pool)
	cfg := &config.Config{
		CORSAllowedOrigins: []string{"*"},
		RateLimitRPS:       10000,
	}
	bruteforce := auth.NewBruteforceShield(h.pool)
	guardrailSvc := guardrails.New(h.pool, h.audit)
	ls := dashboards.NewLiveStream(h.bus)
	router := api.Mount(&api.Services{
		Pool: h.pool, Cfg: cfg, Verifier: verifier,
		Audit: h.audit, Bus: h.bus, Branding: h.branding,
		Tenants: h.tenants, Engagements: h.engagements,
		AuthDocs: h.authdocs, Assets: h.assets, Scope: h.scope,
		ScanOrch: h.scanorch, Signer: h.signer, Agents: h.agents,
		Findings: h.findings, Vault: h.vault, Reports: h.reports,
		Dashboards: dashboards.New(h.pool),
		Nodes: h.nodes, LiveStream: ls, Guardrails: guardrailSvc,
		Bruteforce: bruteforce,
	})
	srv := httptest.NewServer(router)
	return srv, srv.Close
}

// mintToken signs an HS256 JWT with the zaishield_super_admin role,
// which Identity.Has treats as carrying every permission code.
func mintToken(t *testing.T, tenantID uuid.UUID) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":         adminID.String(),
		"tenant_id":   tenantID.String(),
		"partner_id":  directID.String(),
		"platform_id": platformID.String(),
		"roles":       []string{"zaishield_super_admin"},
		"mfa":         true,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type apiClient struct {
	t      *testing.T
	base   string
	token  string
	tenant uuid.UUID
}

func (c *apiClient) do(method, path string, body any, want int) ([]byte, *http.Response) {
	c.t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Tenant-Id", c.tenant.String())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if want > 0 && resp.StatusCode != want {
		c.t.Fatalf("%s %s: want %d got %d body=%s", method, path, want, resp.StatusCode, out)
	}
	return out, resp
}

// TestHTTP_OpsWiring exercises a representative slice of the new routes
// through the real router. Catches missing route mounts, wrong middleware,
// or handler signature drift.
func TestHTTP_OpsWiring(t *testing.T) {
	h := newHarness(t)
	srv, cleanup := mountAPI(t, h)
	defer cleanup()

	tenantID, eng := h.makeTenant(t, "wire-http")
	c := &apiClient{
		t: t, base: srv.URL, tenant: tenantID,
		token: mintToken(t, tenantID),
	}

	// HS-02: deep verify endpoint returns intact chain
	body, _ := c.do("GET", "/api/v1/audit/verify-deep", nil, 200)
	var deep struct{ FirstBadID int64 `json:"first_bad_id"` }
	_ = json.Unmarshal(body, &deep)
	if deep.FirstBadID != 0 {
		t.Fatalf("audit chain broken at %d", deep.FirstBadID)
	}

	// VS-05: read region quota for seeded 'ae'
	c.do("GET", "/api/v1/scanner/regions/ae/quota", nil, 200)

	// VS-05: set region quota — round-trip mutation.
	c.do("PUT", "/api/v1/scanner/regions/ae/quota",
		map[string]any{"max_concurrent_jobs": 20, "reserved_for_platform": 2}, 200)

	// VS-05: network policy YAML renders.
	body, _ = c.do("GET", "/api/v1/scanner/regions/ae/network-policy.yaml", nil, 200)
	if !strings.Contains(string(body), "kind: NetworkPolicy") {
		t.Fatalf("network policy missing kind: %s", body[:80])
	}

	// VS-07: clusters list (might be empty for a fresh tenant — just 200).
	c.do("GET", "/api/v1/findings/clusters?tenant_id="+tenantID.String(), nil, 200)

	// VS-07: add a severity override.
	c.do("POST", "/api/v1/findings/severity-overrides?tenant_id="+tenantID.String(),
		map[string]any{
			"name": "tls-critical-http",
			"title_regex": "weak tls",
			"new_severity": "critical",
			"reason": "regulator",
		}, 201)

	// VS-08: rotate tenant data key — MFA-gated; our token claims mfa:true.
	body, _ = c.do("POST", "/api/v1/tenants/"+tenantID.String()+"/data-key/rotate", nil, 200)
	if !strings.Contains(string(body), "new_key_version") {
		t.Fatalf("rotate response missing field: %s", body)
	}

	// VS-09: bulk batch (empty list rejected, then non-empty succeeds).
	c.do("POST", "/api/v1/retest-batches",
		map[string]any{"tenant_id": tenantID, "reason": "Q2-2026", "finding_ids": []string{}}, 400)
	// (We don't seed findings here; non-empty batches are covered by VS-09 svc test.)
	_ = eng

	// VS-10: scheduled report
	body, _ = c.do("POST", "/api/v1/report-schedules",
		map[string]any{
			"tenant_id": tenantID, "engagement_id": eng,
			"name": "quarterly-tech", "report_type": "technical",
			"cadence": "weekly",
		}, 201)
	if !strings.Contains(string(body), `"id":`) {
		t.Fatalf("schedule create missing id: %s", body)
	}

	// VS-10: PCI compliance matrix.
	c.do("GET", "/api/v1/compliance/pci_dss/engagements/"+eng.String(), nil, 200)

	// VS-12: geo nodes (seeded coords).
	body, _ = c.do("GET", "/api/v1/dashboards/geo", nil, 200)
	if !strings.Contains(string(body), "Dubai") {
		t.Fatalf("geo missing seeded region: %s", body[:80])
	}

	// VS-12: compliance snapshot.
	c.do("GET", "/api/v1/dashboards/compliance?tenant_id="+tenantID.String(), nil, 200)

	// HS-01: ip-lockouts list (likely empty).
	c.do("GET", "/api/v1/auth/ip-lockouts", nil, 200)

	// HS-05: maintenance status.
	c.do("GET", "/api/v1/platform/maintenance", nil, 200)

	// HS-05: enable maintenance + immediately disable (audit trail intact).
	c.do("PUT", "/api/v1/platform/maintenance",
		map[string]any{"enabled": true, "reason": "wiring test"}, 200)
	c.do("PUT", "/api/v1/platform/maintenance",
		map[string]any{"enabled": false}, 200)

	// HS-05: list seeded policy rules.
	body, _ = c.do("GET", "/api/v1/platform/policy-rules?subject=scan", nil, 200)
	if !strings.Contains(string(body), "never_allow_out_of_scope") {
		t.Fatalf("policy rules missing seeded rule: %s", body[:200])
	}

	// HS-02: timeline last hour.
	c.do("GET", "/api/v1/audit/timeline?tenant_id="+tenantID.String()+
		"&since="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), nil, 200)

	_ = context.Background
}
