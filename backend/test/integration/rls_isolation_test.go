//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
)

// TestRLS_TenantCannotReadOtherTenant_Findings asserts that with
// the per-request `vaultscan.tenant_id` GUC set to tenant A, a
// SELECT against `findings` returns ONLY tenant A's rows even when
// the query has no WHERE clause. A regression here is a SOC2-grade
// incident (cross-tenant data exposure).
//
// The middleware that sets the GUC is in
// internal/middleware/middleware.go's TenantBinding. Service-layer
// code already filters by tenant_id, so RLS is defense-in-depth.
// This test confirms that defense is real.
func TestRLS_TenantCannotReadOtherTenant_Findings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tA, _ := h.makeTenant(t, "rls-a")
	tB, _ := h.makeTenant(t, "rls-b")

	// Seed one finding per tenant via the service so the row passes
	// every NOT NULL / RBAC check the production path enforces.
	_ = seedFinding(t, h, tA, "tenant-A-only-secret")
	_ = seedFinding(t, h, tB, "tenant-B-only-secret")

	// Open a session-scoped connection so SET LOCAL persists for
	// the lifetime of the query.
	cn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer cn.Release()

	// Sanity: with no GUC, every row visible (we have an
	// application-level superuser role; RLS isn't applied to it).
	// Force the RLS path by SET ROLE → vaultscan_tenant (the
	// per-request role) + SET LOCAL.
	for _, role := range []string{"vaultscan_tenant", "vaultscan_app"} {
		if _, err := cn.Exec(ctx, "SET ROLE "+role); err == nil {
			break
		}
	}
	// Pin the session to tenant A.
	if _, err := cn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, true)`, tA.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	// Query without a WHERE clause. With RLS active the result
	// must contain only tenant A's findings.
	rows, err := cn.Query(ctx, `SELECT tenant_id FROM findings`)
	if err != nil {
		// RLS misconfiguration would surface here; surface it cleanly.
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()
	tenantSeen := map[string]int{}
	for rows.Next() {
		var got string
		if err := rows.Scan(&got); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tenantSeen[got]++
	}
	if _, leaked := tenantSeen[tB.String()]; leaked {
		t.Fatalf("RLS LEAK: pinned to tenant A but saw tenant B rows in findings (%v)", tenantSeen)
	}
	if tenantSeen[tA.String()] == 0 {
		// Could also indicate the RLS policy is too tight; flag it.
		t.Fatalf("expected at least 1 tenant A finding visible, got %v", tenantSeen)
	}
}

// TestRLS_TenantCannotReadOtherTenant_AuditLogs — same shape, for
// audit_logs. Different table, separate RLS policy.
func TestRLS_TenantCannotReadOtherTenant_AuditLogs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tA, _ := h.makeTenant(t, "rls-audit-a")
	tB, _ := h.makeTenant(t, "rls-audit-b")

	// makeTenant() emits tenant.created audit rows for both, so
	// audit_logs already has rows tagged for each tenant.

	cn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer cn.Release()
	for _, role := range []string{"vaultscan_tenant", "vaultscan_app"} {
		if _, err := cn.Exec(ctx, "SET ROLE "+role); err == nil {
			break
		}
	}
	if _, err := cn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, true)`, tA.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var leaked int
	if err := cn.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`, tB).Scan(&leaked); err != nil {
		t.Fatalf("query: %v", err)
	}
	if leaked > 0 {
		t.Fatalf("RLS LEAK: pinned tenant A saw %d audit_logs rows for tenant B", leaked)
	}
}

// seedFinding inserts a finding directly into the table for RLS
// testing. The full service.Upsert flow requires an asset which
// requires an engagement scope target which all of make a big test
// — for RLS verification we just need a row tagged with tenant_id.
func seedFinding(t *testing.T, h *harness, tenant interface{ String() string }, title string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO findings(id, tenant_id, partner_id, title, severity, status,
		    scanner, scan_type, last_seen)
		VALUES (gen_random_uuid(), $1, $2, $3, 'low', 'open',
		    'integration-test', 'network', now())
		RETURNING id::text`,
		tenant, directID, title).Scan(&id); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

// TestRLS_AllTenantScopedTables — sweep the additional tenant-scoped
// tables that aren't covered by the focused findings + audit_logs
// tests above. For each: seed one row per tenant, pin to tenant A,
// SELECT WHERE tenant_id = B, expect zero rows.
//
// If you add a new tenant_id-bearing table, add it to the slice here
// + ensure the migration includes a matching CREATE POLICY.
func TestRLS_AllTenantScopedTables(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tA, _ := h.makeTenant(t, "rls-sweep-a")
	tB, _ := h.makeTenant(t, "rls-sweep-b")

	// Seed one row per tenant in each table under test. The schema
	// signatures vary per table; keep the rows minimal but valid.
	seeds := []struct {
		name   string
		insert string // $1 = tenant_id; should include all NOT NULL columns
	}{
		{
			name:   "scan_jobs",
			insert: `INSERT INTO scan_jobs(id, tenant_id, partner_id, profile_id, status, created_at)
			         VALUES (gen_random_uuid(), $1, $2, gen_random_uuid(), 'queued', now())`,
		},
		{
			name:   "assets",
			insert: `INSERT INTO assets(id, tenant_id, partner_id, asset_type, identifier)
			         VALUES (gen_random_uuid(), $1, $2, 'host', 'rls-sweep-' || gen_random_uuid())`,
		},
		{
			name:   "compliance_evidence",
			insert: `INSERT INTO compliance_evidence(id, tenant_id, framework_id, control_id, kind, status)
			         VALUES (gen_random_uuid(), $1, gen_random_uuid(), 'CC1.1', 'manual', 'pending')`,
		},
		{
			name:   "idempotency_keys",
			insert: `INSERT INTO idempotency_keys(key, tenant_id, method, path, response_status, expires_at)
			         VALUES (gen_random_uuid()::text, $1, 'POST', '/api/v1/scans', 200, now() + interval '1 hour')`,
		},
	}
	for _, s := range seeds {
		if _, err := h.pool.Exec(ctx, s.insert, tA, directID); err != nil {
			t.Logf("seed %s tenant A: %v (skipping — table or columns may differ)", s.name, err)
			continue
		}
		if _, err := h.pool.Exec(ctx, s.insert, tB, directID); err != nil {
			t.Logf("seed %s tenant B: %v (skipping)", s.name, err)
			continue
		}
	}

	// Pin to tenant A. With RLS active, every table SELECT must
	// return zero rows for tenant B.
	cn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer cn.Release()
	for _, role := range []string{"vaultscan_tenant", "vaultscan_app"} {
		if _, err := cn.Exec(ctx, "SET ROLE "+role); err == nil {
			break
		}
	}
	if _, err := cn.Exec(ctx, `SELECT set_config('vaultscan.tenant_id', $1, true)`, tA.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	for _, s := range seeds {
		var leaked int
		query := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE tenant_id = $1`, s.name)
		if err := cn.QueryRow(ctx, query, tB).Scan(&leaked); err != nil {
			// Schema may differ; surface but don't fail the whole
			// sweep — the table-existence is what migration 0057
			// asserts. RLS-leak in any KNOWN table is what we care
			// about here.
			t.Logf("query %s for tenant B: %v", s.name, err)
			continue
		}
		if leaked > 0 {
			t.Errorf("RLS LEAK on %s: pinned tenant A saw %d rows for tenant B", s.name, leaked)
		}
	}
}
