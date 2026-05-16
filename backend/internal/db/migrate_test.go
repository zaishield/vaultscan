package db

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// loadMigrations is pure (filesystem only) so we test it standalone.
// The bigger Migrate()/Rollback()/RollbackTo() round-trip lives in
// the integration suite (test/integration/migrations_test.go) where
// it can hit a real Postgres.

func TestLoadMigrations_OnlyUpSQLFilesIncluded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustWrite(t, dir, "0001_init.up.sql", "CREATE TABLE x();")
	mustWrite(t, dir, "0001_init.down.sql", "DROP TABLE x;")
	mustWrite(t, dir, "0002_alter.up.sql", "ALTER TABLE x ADD c INT;")
	mustWrite(t, dir, "README.md", "ignored")
	// Subdirectory should be skipped
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	ms, err := loadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("loaded=%d want 2 (.up.sql only)", len(ms))
	}
	// Sorted ascending by version
	versions := []string{ms[0].Version, ms[1].Version}
	if !sort.StringsAreSorted(versions) {
		t.Errorf("not sorted: %v", versions)
	}
	if ms[0].Version != "0001_init" {
		t.Errorf("ms[0].Version=%q want 0001_init", ms[0].Version)
	}
	// Hash is reproducible
	if ms[0].Hash == "" {
		t.Error("Hash empty")
	}
}

func TestLoadMigrations_HashIsContentAddressed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustWrite(t, dir, "0001_x.up.sql", "SELECT 1")
	ms1, err := loadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Re-load same file → same hash
	ms2, _ := loadMigrations(dir)
	if ms1[0].Hash != ms2[0].Hash {
		t.Errorf("hash not stable: %s vs %s", ms1[0].Hash, ms2[0].Hash)
	}
	// Modify content → hash changes
	mustWrite(t, dir, "0001_x.up.sql", "SELECT 2")
	ms3, _ := loadMigrations(dir)
	if ms3[0].Hash == ms1[0].Hash {
		t.Errorf("hash didn't change after edit")
	}
}

func TestLoadMigrations_MissingDirErrors(t *testing.T) {
	t.Parallel()
	if _, err := loadMigrations("/nonexistent-path-vaultscan-test"); err == nil {
		t.Error("missing dir should error")
	}
}

func TestLoadDownMigration_MissingErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := loadDownMigration(dir, "0001_missing"); err == nil {
		t.Error("missing down file should error")
	}
}

func TestLoadDownMigration_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustWrite(t, dir, "0042_x.down.sql", "DROP TABLE x;")
	body, err := loadDownMigration(dir, "0042_x")
	if err != nil {
		t.Fatal(err)
	}
	if body != "DROP TABLE x;" {
		t.Errorf("body=%q", body)
	}
}

func mustWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
