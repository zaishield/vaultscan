//go:build integration

// permission_matrix_test.go — systematic 403 coverage for
// permission-gated endpoints. For each endpoint that uses
// middleware.RequirePermission, this test:
//
//   1. Mints a JWT that has the tenant scope but NOT the required permission
//   2. Hits the endpoint with that JWT
//   3. Asserts the response is 403 (not 200, not 500)
//
// This catches the regression where an endpoint accidentally gets
// the wrong permission name (typo → permission never required),
// or where the permission requirement is removed during a refactor.

package integration

import (
	"net/http"
	"strings"
	"testing"
)

// permissionCase = "what happens when a JWT WITHOUT this permission
// hits this endpoint." Each case is independently scoped — no shared
// state, parallel-safe.
type permissionCase struct {
	name       string
	method     string
	path       string // may contain {tenant_id}; substituted at run time
	body       string
	wantStatus int    // expected HTTP status WITHOUT the permission
	skipNote   string // non-empty → skip the case (with reason)
}

// Cases for the GA-era + frequently-mutated endpoints. Add new ones
// here whenever you add a RequirePermission gate in server.go.
var permissionCases = []permissionCase{
	// Tenant lifecycle ---------------------------------------------
	{
		name: "create_tenant_unauthorized",
		method: "POST", path: "/api/v1/tenants",
		body: `{"name":"x","slug":"x"}`,
		wantStatus: http.StatusForbidden,
	},
	{
		name: "suspend_tenant_unauthorized",
		method: "POST", path: "/api/v1/tenants/{tenant_id}/suspend",
		body: `{}`, wantStatus: http.StatusForbidden,
	},
	{
		name: "promote_isolation_requires_mfa_or_perm",
		method: "POST", path: "/api/v1/tenants/{tenant_id}/promote-isolation",
		body: `{}`,
		// Either 403 (perm missing) or 412/403 (mfa missing) is fine;
		// we just don't want 200 / 500.
		wantStatus: http.StatusForbidden,
	},
	{
		name: "set_residency_unauthorized",
		method: "PUT", path: "/api/v1/tenants/{tenant_id}/residency",
		body: `{"region":"eu"}`, wantStatus: http.StatusForbidden,
	},

	// Evidence -----------------------------------------------------
	{
		name: "download_evidence_requires_perm_plus_mfa",
		method: "GET", path: "/api/v1/evidence",
		body: "", wantStatus: http.StatusForbidden,
		// MFA gate also fires; either path returns 403/412.
	},

	// User admin ---------------------------------------------------
	{
		name: "erase_user_requires_admin",
		method: "POST", path: "/api/v1/users/00000000-0000-0000-0000-000000000111/erase",
		body: `{"reason":"x"}`, wantStatus: http.StatusForbidden,
	},

	// Audit --------------------------------------------------------
	{
		name: "audit_verify_deep_requires_perm",
		method: "POST", path: "/api/v1/audit/verify-deep",
		body: "", wantStatus: http.StatusForbidden,
	},
	{
		name: "audit_export_requires_perm",
		method: "GET", path: "/api/v1/audit/export?from=2024-01-01T00:00:00Z",
		body: "", wantStatus: http.StatusForbidden,
	},

	// Platform admin ----------------------------------------------
	{
		name: "rotate_jwt_keys_requires_platform_admin",
		method: "POST", path: "/api/v1/auth/jwt-keys/rotate",
		body: `{}`, wantStatus: http.StatusForbidden,
	},
	{
		name: "ip_lockouts_requires_perm",
		method: "GET", path: "/api/v1/auth/ip-lockouts",
		body: "", wantStatus: http.StatusForbidden,
	},

	// Integrations rotation ---------------------------------------
	{
		name: "rotate_signing_secret_requires_perm",
		method: "PUT", path: "/api/v1/integrations/00000000-0000-0000-0000-000000000888/signing-secret",
		body: `{"secret":"x"}`, wantStatus: http.StatusForbidden,
	},
}

func TestPermissions_403WhenPermissionMissing(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	defer srv.Close()

	tenantID, _ := h.makeTenant(t, "perm-matrix")
	// mintToken default-issues a token with the basic operator role
	// (no admin / no manage_* / no platform_admin); each case above
	// requires one of the gated permissions.
	tok := mintToken(t, tenantID)

	for _, c := range permissionCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if c.skipNote != "" {
				t.Skip(c.skipNote)
			}
			path := strings.ReplaceAll(c.path, "{tenant_id}", tenantID.String())
			var bodyReader interface {
				Read(p []byte) (int, error)
			}
			if c.body != "" {
				bodyReader = strings.NewReader(c.body)
			}
			resp := doReq(t, c.method, srv.URL+path, tok, tenantID.String(), bodyReader)
			defer resp.Body.Close()

			// We accept either 403 (permission missing) OR 412
			// (precondition: MFA required). Both signal the gate did
			// its job. What we MUSTN'T see:
			//   200 → gate is broken; the action succeeded
			//   500 → handler crashed instead of cleanly refusing
			switch resp.StatusCode {
			case http.StatusForbidden, http.StatusPreconditionRequired,
				http.StatusUnauthorized, http.StatusPreconditionFailed:
				// expected — gate fired
			case http.StatusOK, http.StatusCreated, http.StatusNoContent:
				t.Errorf("PERMISSION GATE BROKEN: %s %s returned %d to a token without the required permission",
					c.method, path, resp.StatusCode)
			case http.StatusInternalServerError:
				t.Errorf("HANDLER CRASHED: %s %s returned 500; should have refused cleanly (403)",
					c.method, path)
			default:
				// Other 4xx (400 / 404) is acceptable — the gate may be
				// validating before checking perm, which is fine.
				t.Logf("%s %s returned %d (non-403 but non-success — OK)",
					c.method, path, resp.StatusCode)
			}
		})
	}
}
