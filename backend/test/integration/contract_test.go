//go:build integration

// Contract tests — validate that the live HTTP API conforms to
// docs/api/openapi.yaml. Fires real requests against an httptest
// server wrapping api.Mount and runs each response through
// kin-openapi's request + response validators.
//
// What this catches that service-level tests don't:
//   * handler exists but isn't mounted under the documented path
//   * response shape silently drifts (renamed field, missing required)
//   * status code drifted (200 → 204, 201 → 200) without spec update
//   * required fields missing from a response body
//
// The spec is intentionally a subset (~15 endpoints) of the ~135-route
// surface — the §37 acceptance flow + the security-critical routes.
// Adding a new route to the spec costs ~10 lines of YAML; not adding
// it means the contract test stays silent.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/zaishield/vaultscan/backend/internal/api"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/billing"
	"github.com/zaishield/vaultscan/backend/internal/compliance"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/guardrails"
	"github.com/zaishield/vaultscan/backend/internal/impersonation"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/planrequests"
	"github.com/zaishield/vaultscan/backend/internal/scimtokens"
	"github.com/zaishield/vaultscan/backend/internal/ssoconfig"
)

// Register decoders for content types kin-openapi doesn't know about
// natively. JWKS endpoints serve `application/jwk-set+json` per RFC
// 7517 — body is JSON, just with a different content-type label, so
// reuse the JSON decoder. PEM and OpenMetrics responses get a
// passthrough decoder that emits the raw string so a {type: string}
// schema validates.
func init() {
	jsonDecoder := func(body io.Reader, _ http.Header, _ *openapi3.SchemaRef,
		_ openapi3filter.EncodingFn) (any, error) {
		raw, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		var out any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	stringDecoder := func(body io.Reader, _ http.Header, _ *openapi3.SchemaRef,
		_ openapi3filter.EncodingFn) (any, error) {
		raw, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	}
	openapi3filter.RegisterBodyDecoder("application/jwk-set+json", jsonDecoder)
	openapi3filter.RegisterBodyDecoder("application/x-pem-file", stringDecoder)
	openapi3filter.RegisterBodyDecoder("application/openmetrics-text", stringDecoder)
}

// loadSpec reads docs/api/openapi.yaml and builds a kin-openapi
// router. The router is what matches an incoming request path to the
// PathItem and Operation defined in the spec.
func loadSpec(t *testing.T) (*openapi3.T, routers.Router) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	specPath := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "api", "openapi.yaml")
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: false}
	spec, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("load spec %s: %v", specPath, err)
	}
	if err := spec.Validate(context.Background()); err != nil {
		t.Fatalf("spec invalid: %v", err)
	}
	// gorillamux refuses to route a request whose host doesn't match a
	// declared server. httptest assigns a random :PORT, so clear the
	// server list — host-matching isn't the contract we're verifying.
	spec.Servers = nil
	r, err := gorillamux.NewRouter(spec)
	if err != nil {
		t.Fatalf("build router: %v", err)
	}
	return spec, r
}

// validateRoundtrip fires one request, then validates BOTH the
// request and the response against the spec. Returns the raw body
// so per-test assertions can keep going.
func validateRoundtrip(t *testing.T, router routers.Router, req *http.Request, resp *http.Response, body []byte) {
	t.Helper()
	route, params, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("route %s %s not in spec: %v", req.Method, req.URL.Path, err)
	}

	// Replace body so the validator can read it again.
	if err := openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: params,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: func(_ context.Context, _ *openapi3filter.AuthenticationInput) error {
				// Auth is enforced by middleware; spec security is informational.
				return nil
			},
		},
	}); err != nil {
		t.Errorf("request validation %s %s: %v", req.Method, req.URL.Path, err)
	}
	if err := openapi3filter.ValidateResponse(context.Background(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req, PathParams: params, Route: route,
		},
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   io.NopCloser(bytes.NewReader(body)),
	}); err != nil {
		t.Errorf("response validation %s %s [%d]: %v", req.Method, req.URL.Path, resp.StatusCode, err)
	}
}

// mountFullAPI builds the full router the same way main.go does, so
// the contract tests hit the actual middleware chain.
func mountFullAPI(t *testing.T, h *harness) *httptest.Server {
	t.Helper()
	verifier := auth.NewVerifier(testJWTSecret, h.pool)
	bruteforce := auth.NewBruteforceShield(h.pool)
	guardrailSvc := guardrails.New(h.pool, h.audit)
	ls := dashboards.NewLiveStream(h.bus)
	mfaSvc, _ := auth.NewMFAService(h.pool, testKEK)
	keyMgr, _ := auth.NewKeyManager(h.pool, testKEK)
	_, _ = keyMgr.Bootstrap(context.Background())
	verifier = verifier.WithKeyManager(keyMgr)
	cfg := &config.Config{CORSAllowedOrigins: []string{"*"}, RateLimitRPS: 10000}
	intSvc := integrations.New(h.pool, h.bus, h.audit)
	// GA-era services. Without these the contract test panics with
	// nil derefs in /usage, /audit/export, /users/{id}/erase, etc.
	billSvc := billing.New(h.pool, h.bus)
	ssoSvc := ssoconfig.New(h.pool, h.audit)
	scimSvc := scimtokens.New(h.pool, h.audit)
	planSvc := planrequests.New(h.pool, h.audit)
	impSvc := impersonation.New(h.pool, h.audit)
	complEval := compliance.NewEvaluator(h.pool)
	router := api.Mount(&api.Services{
		Pool: h.pool, Cfg: cfg, Verifier: verifier,
		Audit: h.audit, Bus: h.bus, Branding: h.branding,
		Tenants: h.tenants, Engagements: h.engagements,
		AuthDocs: h.authdocs, Assets: h.assets, Scope: h.scope,
		ScanOrch: h.scanorch, Signer: h.signer, Agents: h.agents,
		Findings: h.findings, Vault: h.vault, Reports: h.reports,
		Dashboards: dashboards.New(h.pool),
		Nodes: h.nodes, LiveStream: ls, Guardrails: guardrailSvc,
		Bruteforce: bruteforce, MFA: mfaSvc, Keys: keyMgr,
		Integrations: intSvc, Users: h.users, Billing: billSvc,
		SSOConfig: ssoSvc, SCIMTokens: scimSvc, PlanRequests: planSvc,
		Impersonation: impSvc, ComplianceEval: complEval,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

// TestContract_SmokeAllSpecPaths walks the OpenAPI spec and fires a
// real request at every documented endpoint. Each round-trip is
// validated against the spec; the test fails on any drift between
// code and contract.
func TestContract_SmokeAllSpecPaths(t *testing.T) {
	h := newHarness(t)
	_, router := loadSpec(t)
	srv := mountFullAPI(t, h)
	tenantID, _ := h.makeTenant(t, "contract-tenant")
	tok := mintToken(t, tenantID)

	type call struct {
		method, path string
		body         string
		wantStatus   int
	}
	calls := []call{
		{"GET", "/healthz", "", 200},
		{"GET", "/.well-known/jwks.json", "", 200},
		{"GET", "/api/v1/.well-known/jwks.json", "", 200},
		{"GET", "/api/v1/branding", "", 200},
		{"GET", "/api/v1/orchestrator/public-key", "", 200},
		{"GET", "/api/v1/audit/verify", "", 200},
		{"GET", "/api/v1/audit/verify-deep", "", 200},
		{"GET", "/api/v1/platform/maintenance", "", 200},
		{"GET", "/api/v1/platform/policy-rules?subject=scan", "", 200},
		{"GET", "/api/v1/dashboards/geo", "", 200},
		{"GET", "/api/v1/scanner/regions/ae/quota", "", 200},
		{"GET", "/metrics", "", 200},
		// Mutations
		// platform_id is taken from the auth context, not the body.
		{"POST", "/api/v1/tenants",
			`{"name":"contract-create","slug":"contract-create",
              "partner_id":"00000000-0000-0000-0000-0000000000b1"}`, 201},
		{"POST", "/api/v1/auth/jwt-keys/rotate", ``, 200},
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	for _, c := range calls {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req, err := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(c.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("X-Tenant-Id", tenantID.String())
			if c.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status: want %d got %d body=%s",
					c.wantStatus, resp.StatusCode, body)
			}
			// Replace the request body so the validator can read it
			// again (it already drained when we built req).
			req.Body = io.NopCloser(strings.NewReader(c.body))
			validateRoundtrip(t, router, req, resp, body)
		})
	}
}

// TestContract_SpecValid loads the spec on its own and asserts it
// parses + validates. Catches "I edited the YAML and broke it".
func TestContract_SpecValid(t *testing.T) {
	_, _ = loadSpec(t)
}
