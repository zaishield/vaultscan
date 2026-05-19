//go:build integration

// replica_real_streaming_test.go — end-to-end proof that the
// read-after-write fence works against a REAL Postgres streaming-
// replication setup. Boots two postgres containers (primary and
// replica), configures streaming replication, exercises the fence:
//
//   1. Write on primary, capture CurrentLSN token
//   2. Block replica from replaying briefly (pg_wal_replay_pause)
//   3. ReaderFresh with the token MUST return primary (fence kicks in)
//   4. Resume replay, wait for catch-up
//   5. ReaderFresh with the token MUST return replica (caught up)
//   6. With NO token, ReaderFresh always returns replica
//
// This closes the multi-region Partial — the application layer is
// proven to do the right thing against a real replication setup,
// not just a stub.
//
// Skip path: needs docker. ~20 seconds setup overhead.

package integration

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/db"
)

func TestReplicaStreaming_FenceWorksAgainstRealReplica(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}

	pName := "vs-test-primary-" + uuid.NewString()[:8]
	rName := "vs-test-replica-" + uuid.NewString()[:8]
	netName := "vs-test-repl-" + uuid.NewString()[:8]
	pPort := freeTCPPort(t)
	rPort := freeTCPPort(t)
	if pPort == rPort {
		rPort++
	}

	// Create a dedicated docker network so primary + replica can
	// reach each other by name. Host networking would also work
	// but conflicts on the test host with the existing vs-test-pg.
	if out, err := exec.Command("docker", "network", "create", netName).CombinedOutput(); err != nil {
		t.Skipf("could not create docker network: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", pName).Run()
		_ = exec.Command("docker", "rm", "-f", rName).Run()
		_ = exec.Command("docker", "network", "rm", netName).Run()
	})

	startReplicationPrimary(t, pName, netName, pPort)
	if err := waitForPg(fmt.Sprintf("postgres://vaultscan:vaultscan@127.0.0.1:%d/vaultscan?sslmode=disable", pPort), 30*time.Second); err != nil {
		t.Fatalf("primary not ready: %v", err)
	}

	// Configure the primary for replication: ensure replication
	// slot + replication-capable user. The image's default
	// postgresql.conf already has wal_level=replica but we make
	// sure with an ALTER SYSTEM (no restart needed).
	primaryDSN := fmt.Sprintf("postgres://vaultscan:vaultscan@127.0.0.1:%d/vaultscan?sslmode=disable", pPort)
	ctx := context.Background()
	pConn, err := pgxpool.New(ctx, primaryDSN)
	if err != nil {
		t.Fatalf("connect primary: %v", err)
	}
	defer pConn.Close()

	// Switch the replication user's password to a known value;
	// the official postgres image creates vaultscan as a regular
	// user, we need REPLICATION privilege. We also have to add a
	// pg_hba entry for replication — POSTGRES_HOST_AUTH_METHOD=trust
	// applies to ordinary connections only, not to physical
	// replication.
	for _, stmt := range []string{
		`ALTER ROLE vaultscan WITH REPLICATION`,
		`SELECT pg_create_physical_replication_slot('vs_repl_slot', true)`,
	} {
		if _, err := pConn.Exec(ctx, stmt); err != nil {
			// Slot might already exist if a prior run died mid-setup.
			if !strings.Contains(err.Error(), "already exists") {
				t.Logf("primary setup %q: %v (continuing)", stmt, err)
			}
		}
	}
	// Append the replication line to pg_hba.conf via docker exec
	// (no SQL surface for this in pg). Then reload.
	if out, err := exec.Command("docker", "exec", pName, "sh", "-c",
		`echo 'host replication vaultscan all trust' >> /var/lib/postgresql/data/pg_hba.conf`).CombinedOutput(); err != nil {
		t.Fatalf("append pg_hba: %v\n%s", err, out)
	}
	if _, err := pConn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
		t.Fatalf("pg_reload_conf: %v", err)
	}

	// Use pg_basebackup to seed the replica's data directory,
	// then start the replica with the seeded data + primary_conninfo.
	startReplicationReplica(t, rName, pName, netName, rPort)
	replicaDSN := fmt.Sprintf("postgres://vaultscan:vaultscan@127.0.0.1:%d/vaultscan?sslmode=disable", rPort)
	if err := waitForPg(replicaDSN, 45*time.Second); err != nil {
		t.Fatalf("replica not ready: %v", err)
	}

	rConn, err := pgxpool.New(ctx, replicaDSN)
	if err != nil {
		t.Fatalf("connect replica: %v", err)
	}
	defer rConn.Close()

	// Confirm the replica IS in fact a replica (pg_is_in_recovery=true).
	var inRecovery bool
	if err := rConn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		t.Fatalf("pg_is_in_recovery: %v", err)
	}
	if !inRecovery {
		t.Fatal("replica is NOT in recovery — streaming setup failed")
	}

	replica := &db.ReplicaPool{Pool: rConn}

	// ---- Test 1: with NO token, fence routes everything to replica.
	pool1, route1, err := db.ReaderFresh(ctx, pConn, replica, "")
	if err != nil {
		t.Fatalf("ReaderFresh no-token: %v", err)
	}
	if pool1 != rConn {
		t.Errorf("no-token fence: expected replica, got primary; route=%s", route1)
	}
	if route1 != db.ReadRouteReplicaUnfenced {
		t.Errorf("route=%s, want replica_unfenced", route1)
	}

	// ---- Test 2: write on primary, capture LSN, pause replica's
	//      replay, fence MUST return primary.
	//
	// Make a sentinel table + insert one row.
	if _, err := pConn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS repl_test_sentinel (
		    id  SERIAL PRIMARY KEY,
		    val TEXT NOT NULL
		)`); err != nil {
		t.Fatalf("create sentinel: %v", err)
	}
	if _, err := pConn.Exec(ctx,
		`INSERT INTO repl_test_sentinel(val) VALUES ($1)`, "fence-probe"); err != nil {
		t.Fatalf("insert sentinel: %v", err)
	}
	tok, err := db.CurrentLSN(ctx, pConn)
	if err != nil {
		t.Fatalf("CurrentLSN: %v", err)
	}
	if tok.IsZero() {
		t.Fatal("empty LSN token")
	}

	// Pause replay so the replica DEFINITELY hasn't applied tok yet.
	if _, err := rConn.Exec(ctx, `SELECT pg_wal_replay_pause()`); err != nil {
		t.Fatalf("pg_wal_replay_pause: %v", err)
	}

	// Force a new write so there's pending WAL to apply, then check
	// fence. With the replica paused, ReaderFresh MUST return primary.
	if _, err := pConn.Exec(ctx,
		`INSERT INTO repl_test_sentinel(val) VALUES ($1)`, "fence-probe-2"); err != nil {
		t.Fatalf("insert after pause: %v", err)
	}
	freshTok, err := db.CurrentLSN(ctx, pConn)
	if err != nil {
		t.Fatal(err)
	}
	pool2, route2, err := db.ReaderFresh(ctx, pConn, replica, freshTok)
	if err != nil {
		t.Fatalf("ReaderFresh paused: %v", err)
	}
	if pool2 != pConn {
		t.Errorf("with paused replica + freshTok: expected primary, got replica; route=%s", route2)
	}
	if route2 != db.ReadRoutePrimaryDueToLag {
		t.Errorf("paused route=%s, want primary_due_to_lag", route2)
	}

	// ---- Test 3: resume replay, wait for catch-up, fence MUST
	//      now return replica.
	if _, err := rConn.Exec(ctx, `SELECT pg_wal_replay_resume()`); err != nil {
		t.Fatalf("pg_wal_replay_resume: %v", err)
	}

	// Poll until replica catches up. Bounded retry so a busted
	// streaming setup doesn't hang the test forever.
	deadline := time.Now().Add(15 * time.Second)
	var pool3 *pgxpool.Pool
	var route3 db.ReadRoute
	for time.Now().Before(deadline) {
		pool3, route3, err = db.ReaderFresh(ctx, pConn, replica, freshTok)
		if err == nil && pool3 == rConn {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ReaderFresh post-resume: %v", err)
	}
	if pool3 != rConn {
		t.Errorf("post-resume: expected replica, got primary; route=%s", route3)
	}
	if route3 != db.ReadRouteReplicaCaughtUp {
		t.Errorf("post-resume route=%s, want replica_caught_up", route3)
	}

	// ---- Test 4: replica lag measurement returns a sensible value.
	lag, err := db.MeasureReplicaLagBytes(ctx, pConn, rConn)
	if err != nil {
		t.Errorf("MeasureReplicaLagBytes: %v", err)
	} else if lag < 0 || lag > 10*1024*1024 {
		// Lag should be ≥0 and small (<10MB) for a quiet replica.
		t.Errorf("implausible lag: %d bytes", lag)
	}
}

// ----- helpers ---------------------------------------------------

func startReplicationPrimary(t *testing.T, name, network string, port int) {
	t.Helper()
	if out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"--network", network,
		"--network-alias", "primary",
		"-p", fmt.Sprintf("%d:5432", port),
		"-e", "POSTGRES_USER=vaultscan",
		"-e", "POSTGRES_PASSWORD=vaultscan",
		"-e", "POSTGRES_DB=vaultscan",
		// Use trust auth for the replication user from inside the
		// network so the replica can stream. Out of scope for prod;
		// fine for the test setup.
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust",
		"postgres:16-alpine",
		// Run with wal_level=replica (alpine's default already is, but
		// be explicit) and a slightly larger wal_keep_size for the
		// brief replay-pause window we use below.
		"-c", "wal_level=replica",
		"-c", "max_wal_senders=10",
		"-c", "wal_keep_size=64",
		"-c", "max_replication_slots=10",
	).CombinedOutput(); err != nil {
		t.Skipf("could not start primary postgres: %v\n%s", err, out)
	}
}

func startReplicationReplica(t *testing.T, name, primaryAlias, network string, port int) {
	t.Helper()
	// Use pg_basebackup to seed the replica's data dir from the
	// primary, then start a fresh postgres process from that seed.
	// The Alpine image's entrypoint creates a default cluster on
	// start; we have to override with a custom shell that runs
	// basebackup first then exec's postgres directly.
	// We use --network-alias and the primary's alias for the conn.
	script := `set -e
mkdir -p /var/lib/postgresql/data && chown postgres:postgres /var/lib/postgresql/data
chmod 0700 /var/lib/postgresql/data
su postgres -c "pg_basebackup -h primary -U vaultscan -D /var/lib/postgresql/data -X stream -R -S vs_repl_slot"
exec su postgres -c "postgres -D /var/lib/postgresql/data"
`
	if out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"--network", network,
		"-p", fmt.Sprintf("%d:5432", port),
		"--entrypoint", "/bin/sh",
		"postgres:16-alpine",
		"-c", script).CombinedOutput(); err != nil {
		t.Skipf("could not start replica postgres: %v\n%s", err, out)
	}
}

func waitForPg(dsn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			if perr := pool.Ping(ctx); perr == nil {
				pool.Close()
				cancel()
				return nil
			}
			pool.Close()
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("not ready within %s", timeout)
}
