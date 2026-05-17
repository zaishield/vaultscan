//go:build integration

// Concurrent-pod migration safety. Without the advisory lock, two
// pods starting at the same instant could both: SELECT and miss,
// both INSERT, and apply DDL twice. The advisory-lock makes the
// loop strict-serial across the cluster.

package integration

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/db"
)

func TestMigrate_ConcurrentInvocationsSerialise(t *testing.T) {
	if os.Getenv("VAULTSCAN_TEST_DATABASE_URL") == "" {
		t.Skip("no DB configured")
	}

	dir := t.TempDir()
	// Write a single migration that would crash on second-time apply
	// (creates a unique table). If the advisory lock fails, both
	// goroutines try to CREATE TABLE and one errors with "already
	// exists" — that's the bug we want to catch.
	tableName := "vstest_concurrent_" + uuid.NewString()[:8]
	upPath := filepath.Join(dir, "0001_create_"+tableName+".up.sql")
	if err := os.WriteFile(upPath, []byte(
		"CREATE TABLE "+tableName+" (id BIGSERIAL PRIMARY KEY);"), 0o644); err != nil {
		t.Fatal(err)
	}
	downPath := filepath.Join(dir, "0001_create_"+tableName+".down.sql")
	if err := os.WriteFile(downPath, []byte(
		"DROP TABLE IF EXISTS "+tableName+";"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t)
	ctx := context.Background()
	// Cleanup so reruns work.
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+tableName)
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM schema_migrations WHERE version=$1`, "0001_create_"+tableName)
	})

	wrappedDB := &db.DB{Pool: h.pool}
	// Fire 8 concurrent Migrate calls against the same pool.
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = wrappedDB.Migrate(ctx, dir)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d Migrate failed: %v", i, err)
		}
	}
	// Exactly one row should be in schema_migrations for this version.
	var count int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=$1`,
		"0001_create_"+tableName).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 schema_migrations row; got %d", count)
	}
}
