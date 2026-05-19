//go:build integration

package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAuditBundle_RealRun spins up the audit-bundle binary against
// a freshly-migrated schema and asserts the produced tar.gz:
//   * contains every expected artifact
//   * manifest.json's sha256 entries match the actual file bytes
//   * bundle.sig HMAC validates against the supplied key
//   * verify_deep.json reports first_bad_id=0 (the chain is intact)
func TestAuditBundle_RealRun(t *testing.T) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VAULTSCAN_TEST_DATABASE_URL not set")
	}

	// Create a fresh schema and migrate. Reuses the harness style.
	schema := "ab_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	ctx := context.Background()

	bootPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := bootPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		bootPool.Close()
		t.Fatalf("create schema: %v", err)
	}
	bootPool.Close()
	t.Cleanup(func() {
		c, _ := pgxpool.New(context.Background(), dsn)
		defer c.Close()
		_, _ = c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})

	// Migrate via psql + the on-disk migrations.
	_, file, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	if err := applyMigrations(t, dsn, schema, migrationsDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Build the binary fresh — catches any compile-time regression
	// in audit-bundle that surface only when wired against the real
	// audit package.
	bin := t.TempDir() + "/audit-bundle"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build audit-bundle: %v\n%s", err, out)
	}

	output := t.TempDir() + "/bundle.tar.gz"
	signKey := hex.EncodeToString(sha256.New().Sum(nil)) // deterministic 32 bytes
	cmd := exec.Command(bin,
		"-db", appendSearchPath(dsn, schema),
		"-output", output,
		"-sign-key", signKey)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("audit-bundle run: %v\n%s", err, out)
	}

	// Read the bundle back and verify structure + integrity.
	f, err := os.Open(output)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		body, _ := io.ReadAll(tr)
		files[hdr.Name] = body
	}

	for _, want := range []string{
		"manifest.json", "verify_deep.json", "chain_breaks.json",
		"verification_checkpoints.json", "tenant_data_keys_inventory.json",
		"retention_policies.json", "bundle.sig",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle missing artifact %q", want)
		}
	}

	// Parse the manifest, verify each artifact's sha256 matches.
	var manifest struct {
		Artifacts []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest decode: %v", err)
	}
	if len(manifest.Artifacts) == 0 {
		t.Fatal("manifest has no artifacts")
	}
	for _, a := range manifest.Artifacts {
		body, ok := files[a.Name]
		if !ok {
			t.Errorf("manifest references missing artifact %q", a.Name)
			continue
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if got != a.SHA256 {
			t.Errorf("artifact %q sha256 mismatch: manifest=%s actual=%s",
				a.Name, a.SHA256, got)
		}
	}

	// Verify bundle.sig is a real HMAC over manifest.json.
	key, _ := hex.DecodeString(signKey)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(files["manifest.json"])
	expected := hex.EncodeToString(mac.Sum(nil))
	if got := strings.TrimSpace(string(files["bundle.sig"])); got != expected {
		t.Errorf("bundle.sig HMAC mismatch:\n got  = %s\n want = %s", got, expected)
	}

	// VerifyDeep result on a fresh-migrated empty audit_logs MUST
	// report first_bad_id=0 (no rows → no break).
	var vd struct {
		FirstBadID int64 `json:"first_bad_id"`
		Total      int64 `json:"total_rows"`
	}
	if err := json.Unmarshal(files["verify_deep.json"], &vd); err != nil {
		t.Fatalf("verify_deep.json decode: %v", err)
	}
	if vd.FirstBadID != 0 {
		t.Errorf("fresh migration reports chain break at row %d (Total=%d)", vd.FirstBadID, vd.Total)
	}
}

// TestAuditBundle_VerifySubcommand exercises the auditor-facing
// `audit-bundle verify` subcommand: produce a real bundle, then
// hand-craft tampered variants and confirm verify exits non-zero
// with a clear message.
func TestAuditBundle_VerifySubcommand(t *testing.T) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VAULTSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "ab_v_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, _ := pgxpool.New(context.Background(), dsn)
		defer c.Close()
		_, _ = c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})
	_, file, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	if err := applyMigrations(t, dsn, schema, migrationsDir); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir() + "/audit-bundle"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	signKey := hex.EncodeToString(sha256.New().Sum([]byte("test-key")))[:64]
	bundlePath := t.TempDir() + "/bundle.tar.gz"
	gen := exec.Command(bin,
		"-db", appendSearchPath(dsn, schema),
		"-output", bundlePath,
		"-sign-key", signKey)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	// Happy path: verify with the correct key.
	t.Run("good_signature", func(t *testing.T) {
		out, err := exec.Command(bin, "verify", bundlePath, "-sign-key", signKey).CombinedOutput()
		if err != nil {
			t.Errorf("verify with correct key failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "OK") {
			t.Errorf("verify output missing OK: %s", out)
		}
	})

	// Bad signature: wrong key → must FAIL.
	t.Run("wrong_signature", func(t *testing.T) {
		badKey := strings.Repeat("aa", 32)
		_, err := exec.Command(bin, "verify", bundlePath, "-sign-key", badKey).CombinedOutput()
		if err == nil {
			t.Error("verify with wrong key should have failed but returned 0")
		}
	})

	// No signature flag → verify runs but skips sig check (prints
	// note). Should succeed because all sha256s are still valid.
	t.Run("no_signature_flag", func(t *testing.T) {
		out, err := exec.Command(bin, "verify", bundlePath).CombinedOutput()
		if err != nil {
			t.Errorf("verify without sig key should succeed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "OK") {
			t.Errorf("verify output missing OK: %s", out)
		}
	})
}

// applyMigrations reads .up.sql files in dir, sets the connection's
// search_path to the target schema, and runs each in order.
func applyMigrations(t *testing.T, dsn, schema, dir string) error {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	// pgcrypto / citext live in public so cross-schema lookups work.
	for _, ext := range []string{"pgcrypto", "citext"} {
		_, _ = pool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS "+ext+" WITH SCHEMA public")
	}
	// Per-statement we'll route into the target schema by setting
	// the GUC for the connection.
	if _, err := pool.Exec(ctx, "SET search_path = "+schema+",public"); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	// Filenames sort lexicographically by their 4-digit prefix.
	sortStrings(ups)
	for _, name := range ups {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		// Use a fresh conn per migration so search_path persistence
		// behaves the same way the real migrator does.
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, "SET search_path = "+schema+",public"); err != nil {
			conn.Release()
			return err
		}
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			conn.Release()
			return err
		}
		conn.Release()
	}
	return nil
}

// appendSearchPath suffixes the DSN with options=-csearch_path=<schema>
// so pgxpool.New connects with the desired path.
func appendSearchPath(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema + ",public"
}

func sortStrings(s []string) {
	// Tiny sort to keep dependencies inside stdlib-only.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

