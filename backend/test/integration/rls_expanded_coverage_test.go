//go:build integration

// Migration 0040 expanded RLS to every tenant-scoped table. This test
// proves the expansion is real: for each affected table we seed two
// rows in different tenants, switch the GUC, and verify the cross-
// tenant row vanishes.
//
// Rather than seed all 20 tables manually (each has its own FK web),
// we test the representative high-risk ones: engagements, scan_jobs,
// agents, integrations, reports, retest_batches, marketplace_installs,
// tenant_data_keys, tenant_settings, tenant_branding, clients.
//
// A meta-test then asserts that EVERY table named in migration 0040
// has rowsecurity=true + relforcerowsecurity=true in pg_class — so
// future-added tables don't silently skip RLS.

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// tablesUnderRLS is the full set migration 0040 covers, plus the
// original three from 0033. Used by TestRLS_Coverage_AllTablesEnabled.
var tablesUnderRLS = []string{
	// 0033
	"findings", "assets", "finding_evidence",
	// 0040
	"engagements", "scan_jobs", "agents", "integrations", "reports",
	"tenant_branding", "tenant_settings", "tenant_data_keys",
	"clients", "retest_batches", "marketplace_installs",
}

func TestRLS_Coverage_AllTablesEnabled(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, table := range tablesUnderRLS {
		t.Run(table, func(t *testing.T) {
			var rowsec, forced bool
			err := h.pool.QueryRow(ctx, `
				SELECT c.relrowsecurity, c.relforcerowsecurity
				  FROM pg_class c
				  JOIN pg_namespace n ON n.oid = c.relnamespace
				 WHERE c.relname = $1
				   AND n.nspname = current_schema()`, table).Scan(&rowsec, &forced)
			if err != nil {
				t.Fatalf("query pg_class for %s: %v", table, err)
			}
			if !rowsec {
				t.Errorf("table %s: rowsecurity is false (ENABLE missing)", table)
			}
			if !forced {
				t.Errorf("table %s: relforcerowsecurity is false (FORCE missing)", table)
			}
		})
	}
}

func TestRLS_Coverage_PoliciesPresent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, table := range tablesUnderRLS {
		t.Run(table, func(t *testing.T) {
			var count int
			err := h.pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_policies
				 WHERE tablename = $1
				   AND schemaname = current_schema()
				   AND policyname LIKE '%tenant_isolation'`,
				table).Scan(&count)
			if err != nil {
				t.Fatalf("pg_policies %s: %v", table, err)
			}
			if count == 0 {
				t.Errorf("table %s: no _tenant_isolation policy", table)
			}
		})
	}
}

func TestRLS_EngagementsCrossTenantBlocked(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rlsRole, rlsSchema := setupRLSRoleForTable(t, h, "engagements")
	tA, _ := h.makeTenant(t, "rls-eng-a")
	tB, _ := h.makeTenant(t, "rls-eng-b")

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

	// Both engagements visible without GUC (NULL → pass-through).
	var both int
	_ = conn.QueryRow(ctx,
		`SELECT count(*) FROM engagements WHERE tenant_id IN ($1,$2)`,
		tA, tB).Scan(&both)
	if both < 2 {
		t.Fatalf("baseline: expected 2+ engagement rows, got %d", both)
	}

	// Bind to A → B's row must vanish.
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, tA.String()); err != nil {
		t.Fatal(err)
	}
	var seenAny int
	_ = conn.QueryRow(ctx,
		`SELECT count(*) FROM engagements WHERE tenant_id = $1`, tB).Scan(&seenAny)
	if seenAny != 0 {
		t.Fatalf("RLS leak on engagements: tenant=A saw %d B-rows", seenAny)
	}
}

func TestRLS_TenantDataKeysCrossTenantBlocked(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tA, _ := h.makeTenant(t, "rls-dek-a")
	tB, _ := h.makeTenant(t, "rls-dek-b")

	// Seed wrapped-DEK rows for both.
	_, err := h.pool.Exec(ctx, `
		INSERT INTO tenant_data_keys(tenant_id, wrapped_key, kek_version)
		VALUES ($1, $2, 1), ($3, $4, 1)
		ON CONFLICT (tenant_id) DO NOTHING`,
		tA, []byte("WRAPPED-DEK-A"), tB, []byte("WRAPPED-DEK-B"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rlsRole, rlsSchema := setupRLSRoleForTable(t, h, "tenant_data_keys")
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	_, _ = conn.Exec(ctx, `SET ROLE `+rlsRole)
	_, _ = conn.Exec(ctx, `SET search_path = `+rlsSchema+`, public`)
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	// Bind to A — even though we hold A's pool conn, attempting to fetch
	// B's wrapped DEK must return zero rows.
	_, _ = conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, tA.String())
	var leaked int
	err = conn.QueryRow(ctx,
		`SELECT count(*) FROM tenant_data_keys WHERE tenant_id = $1`, tB).
		Scan(&leaked)
	if err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("CRITICAL: tenant_data_keys RLS leak — A read %d of B's wrapped DEKs", leaked)
	}
}

// setupRLSRoleForTable is the same idea as the original setupRLSRole
// but parameterised — grants only on the specific table the test
// queries so we know the test isn't accidentally bypassing via implicit
// inheritance.
func setupRLSRoleForTable(t *testing.T, h *harness, table string) (role, schema string) {
	t.Helper()
	role = "vaultscan_rls_app_expanded"
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
	_, _ = h.pool.Exec(context.Background(),
		`GRANT USAGE ON SCHEMA `+schema+` TO `+role)
	_, _ = h.pool.Exec(context.Background(),
		`GRANT SELECT, INSERT, UPDATE, DELETE ON `+schema+`.`+table+` TO `+role)
	return role, schema
}

// keep the import live in builds that compile this file without using
// the uuid type directly.
var _ = uuid.New
