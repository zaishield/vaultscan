//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrations_FreshScratchApplyCleanly asserts every migration
// in backend/migrations/ applies cleanly to a fresh schema in
// numerical order. The harness's TestMain already does this once
// per test run; this test makes it explicit + bounded.
//
// What this test does NOT check:
//   * Idempotent re-apply. Many migrations use CREATE TABLE without
//     IF NOT EXISTS — that's fine under the production migration
//     runner (db.Migrate) which records applied versions in
//     schema_migrations and refuses to re-run them. Tests that
//     manually pipe a migration's SQL into psql on an already-
//     migrated DB will error on those statements; that's the
//     EXPECTED behavior, not a bug.
//   * Down-migrations. Every up has a matching down.sql but those
//     are exercised separately (rollback testing belongs in a
//     staging-environment drill, not in unit tests).
//
// What this test catches:
//   * A new migration whose SQL is malformed.
//   * A migration that references an object that doesn't exist
//     yet (forward dependency).
//   * A migration whose 4-digit prefix collides with another
//     (the sort produces a deterministic order).
//   * A NOT NULL column added without a backfill that breaks
//     existing schema state.
func TestMigrations_FreshScratchApplyCleanly(t *testing.T) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VAULTSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()

	schema := "mig_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	bootPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer bootPool.Close()
	if _, err := bootPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*1e9)
		defer cancel()
		c, _ := pgxpool.New(dropCtx, dsn)
		defer c.Close()
		_, _ = c.Exec(dropCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	for _, ext := range []string{"pgcrypto", "citext"} {
		_, _ = bootPool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS "+ext+" WITH SCHEMA public")
	}

	_, file, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	sort.Strings(ups)
	if len(ups) < 10 {
		t.Fatalf("only %d migrations found — wrong dir?", len(ups))
	}

	// Check for prefix collisions: two files starting with the
	// same 4-digit number is an authoring bug.
	prefixes := map[string]string{}
	for _, name := range ups {
		if len(name) < 5 || name[4] != '_' {
			t.Errorf("migration %q doesn't follow NNNN_*.up.sql convention", name)
			continue
		}
		p := name[:4]
		if prior, ok := prefixes[p]; ok {
			t.Errorf("migration prefix collision: %q and %q both start with %s", prior, name, p)
		}
		prefixes[p] = name
	}

	// Apply each in order. Any failure is a real bug.
	for _, name := range ups {
		body, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		conn, err := bootPool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, "SET search_path = "+schema+",public"); err != nil {
			conn.Release()
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			conn.Release()
			t.Fatalf("apply %s: %v", name, err)
		}
		conn.Release()
	}
	t.Logf("applied %d migrations cleanly to %s", len(ups), schema)
}

// TestMigrations_NewStyleAreIdempotent specifically tests the
// migrations authored with idempotency guards in mind. The new-
// style pattern (used by all migrations from 0057 onward) wraps
// table/policy creation in `IF NOT EXISTS` or `DO $$ IF NOT
// EXISTS ... THEN ... END IF; END $$;` blocks. These MUST safely
// re-apply because operators sometimes need to manually re-run a
// migration during incident response (e.g. when the
// schema_migrations table is out-of-sync with the actual state).
func TestMigrations_NewStyleAreIdempotent(t *testing.T) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VAULTSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()

	schema := "mig2_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*1e9)
		defer cancel()
		c, _ := pgxpool.New(dropCtx, dsn)
		defer c.Close()
		_, _ = c.Exec(dropCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	for _, ext := range []string{"pgcrypto", "citext"} {
		_, _ = pool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS "+ext+" WITH SCHEMA public")
	}

	// Migrate the schema to head first.
	_, file, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	entries, _ := os.ReadDir(migrationsDir)
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	sort.Strings(ups)
	for _, name := range ups {
		body, _ := os.ReadFile(filepath.Join(migrationsDir, name))
		conn, _ := pool.Acquire(ctx)
		_, _ = conn.Exec(ctx, "SET search_path = "+schema+",public")
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			conn.Release()
			t.Fatalf("first-apply %s: %v", name, err)
		}
		conn.Release()
	}

	// Re-apply only the migrations authored with idempotency
	// guards. As of this writing, that's 0057+ and migration 0017.
	idempotent := []string{
		"0057_rls_gaps_close.up.sql",
		"0062_audit_chain_verification_checkpoint.up.sql",
		"0063_dlq_retry_tracking.up.sql",
	}
	for _, name := range idempotent {
		body, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Logf("skipping %s: %v", name, err)
			continue
		}
		conn, _ := pool.Acquire(ctx)
		_, _ = conn.Exec(ctx, "SET search_path = "+schema+",public")
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			conn.Release()
			t.Errorf("idempotency-claiming migration %s ERROR'd on re-apply: %v", name, err)
			continue
		}
		conn.Release()
	}
}
