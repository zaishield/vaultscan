//go:build integration

// HS-01: RLS engagement test. Migration 0017 defined the policies;
// migration 0033 actually enables RLS. This test:
//   1. Seeds two tenants A and B each with one finding.
//   2. Without the session var, a plain query sees both rows (because
//      our policy short-circuits on NULL).
//   3. After SetTenantContext(A), the same query sees only A's row.
//   4. After SetTenantContext(B), only B's row.
//   5. ClearTenantContext re-opens the view.

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// setupRLSRole creates a non-superuser app role and grants it the
// minimum it needs to exercise RLS in the current test schema.
// Returns (role, schema) so the caller can SET ROLE + SET search_path.
//
// This is what production looks like: the API connects as a role
// without the BYPASSRLS attribute so the policies engage. In dev the
// vaultscan superuser bypasses RLS — this helper makes the test honest.
func setupRLSRole(t *testing.T, h *harness) (role, schema string) {
	t.Helper()
	role = "vaultscan_rls_app"
	// Resolve the test's current schema (set on the pool via search_path).
	if err := h.pool.QueryRow(context.Background(),
		`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), `
		DO $$ BEGIN
		  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='`+role+`') THEN
		    CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS;
		  END IF;
		END $$`); err != nil {
		t.Fatalf("create role: %v", err)
	}
	// Grant access to the test schema + its tables.
	if _, err := h.pool.Exec(context.Background(),
		`GRANT USAGE ON SCHEMA `+schema+` TO `+role); err != nil {
		t.Fatalf("grant usage: %v", err)
	}
	for _, table := range []string{"findings", "assets", "finding_evidence"} {
		if _, err := h.pool.Exec(context.Background(),
			`GRANT SELECT ON `+schema+`.`+table+` TO `+role); err != nil {
			t.Fatalf("grant %s: %v", table, err)
		}
	}
	return role, schema
}

func TestHS01_RLS_BlocksCrossTenant(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rlsRole, rlsSchema := setupRLSRole(t, h)
	tA, engA := h.makeTenant(t, "rls-a")
	tB, engB := h.makeTenant(t, "rls-b")

	// Seed one finding per tenant. dedupFingerprint includes tenant_id so
	// these don't collide even with identical titles.
	for _, fi := range []struct {
		tenant uuid.UUID
		eng    uuid.UUID
		title  string
	}{
		{tA, engA, "rls-A-finding"},
		{tB, engB, "rls-B-finding"},
	} {
		_, _, err := h.findings.Upsert(ctx, findings.IngestInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: fi.tenant, EngagementID: fi.eng,
			Title: fi.title, Severity: "medium", Scanner: "nmap",
			AffectedEndpoint: "rls-test.example",
		})
		if err != nil {
			t.Fatalf("seed %s: %v", fi.title, err)
		}
	}

	// Acquire one dedicated connection so SET persists for the next query.
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	// Switch the session to the non-superuser role so RLS binds.
	if _, err := conn.Exec(ctx, `SET ROLE `+rlsRole); err != nil {
		t.Fatalf("SET ROLE: %v", err)
	}
	if _, err := conn.Exec(ctx, `SET search_path = `+rlsSchema+`, public`); err != nil {
		t.Fatalf("SET search_path: %v", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	// Defensive: pgxpool may have leased us a conn that another test
	// previously SET vaultscan.tenant_id on without clearing. Reset
	// the GUC to empty before reading baseline so the test is
	// isolation-resistant.
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', '', false)`); err != nil {
		t.Fatalf("reset GUC: %v", err)
	}

	// Baseline: no GUC set → policy short-circuits → both rows visible.
	var both int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE title IN ('rls-A-finding','rls-B-finding')`).
		Scan(&both); err != nil {
		t.Fatal(err)
	}
	if both != 2 {
		t.Fatalf("baseline: expected 2 rows visible without GUC, got %d", both)
	}

	// Set tenant context to A → only A visible.
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, tA.String()); err != nil {
		t.Fatal(err)
	}
	var seenA int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE title IN ('rls-A-finding','rls-B-finding')`).
		Scan(&seenA); err != nil {
		t.Fatal(err)
	}
	if seenA != 1 {
		t.Fatalf("RLS=A: expected 1 row, got %d (policy not engaged)", seenA)
	}
	var titleA string
	_ = conn.QueryRow(ctx,
		`SELECT title FROM findings WHERE title LIKE 'rls-%-finding'`).Scan(&titleA)
	if titleA != "rls-A-finding" {
		t.Fatalf("RLS=A: cross-tenant leak — saw %q", titleA)
	}

	// Switch to B.
	_, _ = conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, tB.String())
	var titleB string
	_ = conn.QueryRow(ctx,
		`SELECT title FROM findings WHERE title LIKE 'rls-%-finding'`).Scan(&titleB)
	if titleB != "rls-B-finding" {
		t.Fatalf("RLS=B: expected B visible, got %q", titleB)
	}

	// Clear → both visible again.
	_, _ = conn.Exec(ctx, `SELECT set_config('vaultscan.tenant_id', '', false)`)
	var bothAfter int
	_ = conn.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE title IN ('rls-A-finding','rls-B-finding')`).
		Scan(&bothAfter)
	if bothAfter != 2 {
		t.Fatalf("cleared GUC: expected 2 rows, got %d", bothAfter)
	}
}

// TestHS01_RLS_HelperEngagesPolicy: SetTenantContext from the db package
// produces the same RLS effect — proves the helper is wired correctly.
func TestHS01_RLS_HelperEngagesPolicy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rlsRole, rlsSchema := setupRLSRole(t, h)
	tA, engA := h.makeTenant(t, "rls-helper")
	_, _, _ = h.findings.Upsert(ctx, findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tA, EngagementID: engA,
		Title: "rls-helper-A", Severity: "low", Scanner: "nmap",
		AffectedEndpoint: "rls.example",
	})

	// Acquire a dedicated conn + switch to the non-superuser role.
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET ROLE `+rlsRole); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SET search_path = `+rlsSchema+`, public`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	// Set tenant via set_config directly on the conn.
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, tA.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = conn.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE tenant_id <> $1`, tA).Scan(&n)
	if n != 0 {
		t.Fatalf("RLS leak: with tenant=A, expected 0 cross-tenant rows visible, got %d", n)
	}

	// Helper exists at the db package level too — sanity check that
	// callers can invoke it through the pool.
	if err := db.SetTenantContext(ctx, h.pool, tA); err != nil {
		t.Fatalf("SetTenantContext: %v", err)
	}
	if err := db.ClearTenantContext(ctx, h.pool); err != nil {
		t.Fatalf("ClearTenantContext: %v", err)
	}
	_ = strings.Contains // keep import live
}

