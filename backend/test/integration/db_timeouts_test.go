//go:build integration

// Statement and idle-in-tx timeouts are applied via AfterConnect on
// every physical conn the pool hands out. This test verifies the
// settings reach Postgres — without them a runaway query can pin a
// pool connection indefinitely and abandoned transactions hold row
// locks forever.

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/db"
)

func TestPool_AppliesStatementAndTxTimeouts(t *testing.T) {
	dsn := mustDSN(t)
	d, err := db.OpenWithConfig(context.Background(), dsn, db.PoolConfig{
		MaxConns:         4,
		MinConns:         1,
		MaxConnLifetime:  10 * time.Minute,
		MaxConnIdle:      5 * time.Minute,
		HealthCheck:      time.Minute,
		StatementTimeout: 5 * time.Second,
		IdleInTxTimeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer d.Close()

	var st, idle string
	if err := d.QueryRow(context.Background(),
		`SHOW statement_timeout`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "5s" {
		t.Errorf("statement_timeout = %q want 5s", st)
	}
	if err := d.QueryRow(context.Background(),
		`SHOW idle_in_transaction_session_timeout`).Scan(&idle); err != nil {
		t.Fatal(err)
	}
	if idle != "3s" {
		t.Errorf("idle_in_transaction_session_timeout = %q want 3s", idle)
	}
}

func TestPool_StatementTimeoutKillsRunawayQuery(t *testing.T) {
	dsn := mustDSN(t)
	d, err := db.OpenWithConfig(context.Background(), dsn, db.PoolConfig{
		MaxConns:         2,
		MinConns:         1,
		MaxConnLifetime:  10 * time.Minute,
		MaxConnIdle:      5 * time.Minute,
		HealthCheck:      time.Minute,
		StatementTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer d.Close()

	// pg_sleep(2) deliberately exceeds the 500ms cap. PG should
	// cancel with code 57014 (query_canceled). Without the timeout
	// this would block the test for the full 2 seconds AND a
	// hostile caller could block a pool conn indefinitely.
	start := time.Now()
	_, err = d.Exec(context.Background(), `SELECT pg_sleep(2)`)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected statement-timeout error, got nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("statement ran %s; expected ~500ms cancel", elapsed)
	}
}

func mustDSN(t *testing.T) string {
	t.Helper()
	dsn := newHarness(t).pool.Config().ConnString()
	if dsn == "" {
		t.Fatal("could not derive DSN from harness")
	}
	return dsn
}
