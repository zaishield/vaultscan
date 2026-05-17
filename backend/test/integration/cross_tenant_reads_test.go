//go:build integration

// Cross-tenant READ rejection: a tenant_admin from tenant B must NOT
// be able to read tenant A's findings / engagements / assets / scan
// jobs by passing tenant A's UUID as the ?tenant_id= query parameter.
//
// Before AuthorizeTargetTenant was wired into these read handlers,
// the query parameter was honoured verbatim — the TenantScope
// middleware only validated the X-Tenant-Id HEADER, not the URL.
// These tests pin the fix.

package integration

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestCrossTenant_ReadHandlers_Rejected(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)

	tenantA, engA := h.makeTenant(t, "ct-read-a-"+uuid.NewString()[:6])
	tenantB, _ := h.makeTenant(t, "ct-read-b-"+uuid.NewString()[:6])
	_ = engA

	// tenant_admin role on tenantB — not super_admin, so authz engages.
	tokB := mintTenantScopedToken(t, tenantB, "tenant_admin")

	cases := []struct {
		name string
		path string
	}{
		{"listFindings",         "/api/v1/findings?tenant_id="                 + tenantA.String()},
		{"listEngagements",      "/api/v1/engagements?tenant_id="              + tenantA.String()},
		{"listAssets",           "/api/v1/assets?tenant_id="                   + tenantA.String()},
		{"listScans",            "/api/v1/scans?tenant_id="                    + tenantA.String()},
		{"listAgents",        "/api/v1/agents?tenant_id="                      + tenantA.String()},
		{"execDashboard",     "/api/v1/dashboards/executive?tenant_id="        + tenantA.String()},
		{"techDashboard",     "/api/v1/dashboards/technical?tenant_id="        + tenantA.String()},
		{"drillCritical",     "/api/v1/dashboards/findings/critical?tenant_id="     + tenantA.String()},
		{"drillSLABreaches",  "/api/v1/dashboards/findings/sla-breaches?tenant_id=" + tenantA.String()},
		{"drillRecentScans",  "/api/v1/dashboards/scans/recent?tenant_id="          + tenantA.String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", srv.URL+tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tokB)
			req.Header.Set("X-Tenant-Id", tenantB.String())
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: status=%d want 403 (cross-tenant query bypass)", tc.name, resp.StatusCode)
			}
		})
	}
}

// Negative case: a super_admin SHOULD be able to read any tenant's
// data — that role is exactly the platform-admin escape hatch.
// Guards against an over-aggressive lockdown.
func TestCrossTenant_ReadHandlers_SuperAdminAllowed(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	tenantA, _ := h.makeTenant(t, "ct-super-a-"+uuid.NewString()[:6])

	// mintToken (the standard helper) bakes in zaishield_super_admin.
	tok := mintToken(t, tenantA)
	req, _ := http.NewRequest("GET",
		srv.URL+"/api/v1/findings?tenant_id="+tenantA.String(), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Tenant-Id", tenantA.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("super_admin self-tenant read: status=%d want 200", resp.StatusCode)
	}
}
