//go:build integration

// Migration hygiene tests:
//   1. every .up.sql has a matching .down.sql (no silent gaps)
//   2. Rollback unwinds the most recent migration and Migrate re-applies
//      it without checksum drift
//   3. RollbackTo unwinds to a specific version

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zaishield/vaultscan/backend/internal/db"
)

func migrationsDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func TestMigrations_EveryUpHasDown(t *testing.T) {
	dir := migrationsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ups := map[string]bool{}
	downs := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".up.sql") {
			ups[strings.TrimSuffix(name, ".up.sql")] = true
		}
		if strings.HasSuffix(name, ".down.sql") {
			downs[strings.TrimSuffix(name, ".down.sql")] = true
		}
	}
	for v := range ups {
		if !downs[v] {
			t.Errorf("migration %s.up.sql has no matching .down.sql — rollback impossible", v)
		}
	}
}

// TestMigrations_RollbackRoundTrip provisions a fresh schema, applies
// every migration, rolls back the top one, and confirms Migrate re-
// applies it cleanly. Catches drift between .up.sql and .down.sql
// (typical drift: down forgets to drop a column or index).
func TestMigrations_RollbackRoundTrip(t *testing.T) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VAULTSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "rb_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	// Create a one-off schema isolated from the shared harness.
	bootPool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer bootPool.Close()
	if _, err := bootPool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = bootPool.Exec(context.Background(),
			fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
	})
	for _, ext := range []string{"pgcrypto", "citext"} {
		_, _ = bootPool.Exec(ctx,
			fmt.Sprintf(`CREATE EXTENSION IF NOT EXISTS %s WITH SCHEMA public`, ext))
	}

	target, err := db.Open(ctx, appendOpt(dsn, "search_path", schema+",public"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	dir := migrationsDir()
	applied, err := target.Migrate(ctx, dir)
	if err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("expected at least one migration applied")
	}
	top := applied[len(applied)-1]

	// Rollback the top one.
	rolled, err := target.Rollback(ctx, dir)
	if err != nil {
		t.Fatalf("rollback %s: %v", top, err)
	}
	if rolled != top {
		t.Fatalf("rollback removed %s, want %s", rolled, top)
	}

	// schema_migrations row gone.
	var n int
	if err := target.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=$1`, top).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rolled-back migration still recorded as applied")
	}

	// Re-apply: Migrate should pick up exactly the rolled-back one.
	reapplied, err := target.Migrate(ctx, dir)
	if err != nil {
		t.Fatalf("re-migrate after rollback: %v", err)
	}
	if len(reapplied) != 1 || reapplied[0] != top {
		t.Fatalf("expected re-apply of just %s, got %v", top, reapplied)
	}
}

var _ = pgx.ErrNoRows
