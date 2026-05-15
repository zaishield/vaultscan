// Package db (migrate.go) drives versioned SQL migrations.
package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type migration struct {
	Version  string
	Filename string
	SQL      string
	Hash     string
}

func loadMigrations(dir string) ([]migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		sum := sha256.Sum256(body)
		ms = append(ms, migration{
			Version:  strings.TrimSuffix(name, ".up.sql"),
			Filename: name,
			SQL:      string(body),
			Hash:     hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
	return ms, nil
}

// loadDownMigration looks up <version>.down.sql in dir. Returns the
// SQL or an error if the file is missing (rollback refuses to proceed
// when a down script isn't available so the operator can't silently
// half-revert).
func loadDownMigration(dir, version string) (string, error) {
	path := filepath.Join(dir, version+".down.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("rollback: missing down migration %s: %w", version, err)
	}
	return string(body), nil
}

// Rollback reverts the most recently applied migration:
//   1. pick the highest version in schema_migrations
//   2. apply <version>.down.sql in a transaction
//   3. delete the schema_migrations row on success
func (d *DB) Rollback(ctx context.Context, dir string) (string, error) {
	var version, filename string
	err := d.QueryRow(ctx, `
		SELECT version, filename FROM schema_migrations
		 ORDER BY version DESC LIMIT 1`).Scan(&version, &filename)
	if err != nil {
		return "", fmt.Errorf("rollback: no applied migrations: %w", err)
	}
	body, err := loadDownMigration(dir, version)
	if err != nil {
		return "", err
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, body); err != nil {
		_ = tx.Rollback(ctx)
		return "", fmt.Errorf("rollback apply %s: %w", version, err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version=$1`, version); err != nil {
		_ = tx.Rollback(ctx)
		return "", fmt.Errorf("rollback dequeue %s: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return version, nil
}

// RollbackTo rolls back migrations one by one until schema_migrations
// no longer contains anything strictly greater than `targetVersion`.
// Empty target = unwind everything.
func (d *DB) RollbackTo(ctx context.Context, dir, targetVersion string) ([]string, error) {
	var unrolled []string
	for {
		var top string
		err := d.QueryRow(ctx,
			`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&top)
		if err != nil {
			return unrolled, nil
		}
		if top <= targetVersion {
			return unrolled, nil
		}
		v, err := d.Rollback(ctx, dir)
		if err != nil {
			return unrolled, err
		}
		unrolled = append(unrolled, v)
	}
}

// Migrate applies any new versioned migrations from dir.
func (d *DB) Migrate(ctx context.Context, dir string) (applied []string, err error) {
	if _, err := d.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			filename   TEXT NOT NULL,
			hash       TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	ms, err := loadMigrations(dir)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		var existing string
		err := d.QueryRow(ctx,
			`SELECT hash FROM schema_migrations WHERE version=$1`, m.Version).Scan(&existing)
		switch {
		case err == nil:
			if existing != m.Hash {
				return applied, fmt.Errorf("migration %s checksum drift: db=%s file=%s",
					m.Version, existing, m.Hash)
			}
			continue
		}
		tx, err := d.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply %s: %w", m.Version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version, filename, hash) VALUES($1,$2,$3)`,
			m.Version, m.Filename, m.Hash); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record %s: %w", m.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit %s: %w", m.Version, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}
