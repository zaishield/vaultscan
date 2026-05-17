// Package db wraps the pgx connection pool used by every service.
package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	pgxConnAlias "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxConn is the per-physical-conn handle passed to AfterConnect.
// Aliased so the imports stay tidy.
type pgxConn = pgxConnAlias.Conn

type DB struct {
	*pgxpool.Pool
}

// ReplicaPool holds the read-only replica pool alongside the primary.
// Heavy read-only handlers (analytics dashboards, long-tail audit
// queries, asset/finding list endpoints) can route to the replica
// to take load off the primary writer.
//
// Wiring: cmd/api opens this with OpenReplica(); if
// VAULTSCAN_DATABASE_REPLICA_URL is empty, the field is nil and
// callers fall back to the primary pool transparently via Reader().
type ReplicaPool struct {
	*pgxpool.Pool
}

// OpenReplica opens a read-only replica pool sized for read-heavy
// queries. Returns nil + nil error when no replica DSN is configured —
// callers must handle nil and fall back to the primary.
//
// Replica pool config is intentionally bigger than the primary's
// because reads dominate; the analytics + dashboards endpoints alone
// easily saturate a 10-conn pool.
func OpenReplica(ctx context.Context, dsn string) (*ReplicaPool, error) {
	if dsn == "" {
		return nil, nil
	}
	pc := PoolConfig{
		MaxConns:        envInt32("VAULTSCAN_PG_REPLICA_MAX_CONNS", 75),
		MinConns:        envInt32("VAULTSCAN_PG_REPLICA_MIN_CONNS", 5),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdle:     5 * time.Minute,
		HealthCheck:     30 * time.Second,
		// Longer statement timeout — read-only analytics queries can
		// legitimately scan large tables.
		StatementTimeout: envDur("VAULTSCAN_PG_REPLICA_STATEMENT_TIMEOUT", 30*time.Second),
	}
	db, err := OpenWithConfig(ctx, dsn, pc)
	if err != nil {
		return nil, fmt.Errorf("open replica: %w", err)
	}
	// Mark every connection as read-only at the session level so a
	// rogue handler that accidentally routes a write to the replica
	// fails loudly instead of returning silently-stale primary data
	// (or worse, getting promoted to a primary by a fail-over and
	// accepting the write).
	prev := db.Pool.Config().AfterConnect
	db.Pool.Config().AfterConnect = func(ctx context.Context, conn *pgxConn) error {
		if prev != nil {
			if err := prev(ctx, conn); err != nil {
				return err
			}
		}
		if _, err := conn.Exec(ctx, "SET default_transaction_read_only = on"); err != nil {
			return fmt.Errorf("replica: set default_transaction_read_only: %w", err)
		}
		return nil
	}
	return &ReplicaPool{Pool: db.Pool}, nil
}

// Reader returns the replica pool if configured, otherwise the
// primary. Use this from read-only handlers that can tolerate
// the small replication lag (typically <1s on a healthy cluster).
//
// Write paths MUST use the primary directly — never call Reader()
// for INSERT/UPDATE/DELETE.
func Reader(primary *pgxpool.Pool, replica *ReplicaPool) *pgxpool.Pool {
	if replica != nil && replica.Pool != nil {
		return replica.Pool
	}
	return primary
}

// PoolConfig is the tunable surface, populated from env vars by Open.
// All knobs have production-grade defaults; bump them for high-load
// environments via VAULTSCAN_PG_{MAX_CONNS, MIN_CONNS, ...}.
//
// Per-component overrides: each binary calls
// PoolConfigForComponent("api" / "scanner-worker" / "agent-gateway"
// / "analytics-worker" / "cron-runner") which layers component-
// specific env vars on top of the defaults. Components hit different
// query patterns:
//
//   - api              — many short read-heavy queries; high concurrency
//   - scanner-worker   — long-held rows under FOR UPDATE; few conns,
//                        long statement timeouts
//   - agent-gateway    — high RPS but each request is small; medium conns
//   - analytics-worker — long-running aggregations; few conns, very
//                        long statement timeouts
//   - cron-runner      — sporadic jobs; minimal conns, leader-elect
//                        already serialises
//
// A single shared default would have to pick one of these as the
// loser. Per-component lets each binary tune appropriately.
type PoolConfig struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdle     time.Duration
	HealthCheck     time.Duration
	// StatementTimeout is the per-statement cap set via SET on each
	// new connection. A runaway query (bad plan, missing index)
	// otherwise pins a connection until the request ctx cancels —
	// and many service-layer code paths don't pass a deadline.
	StatementTimeout time.Duration
	// IdleInTxTimeout kills sessions that left a tx open and stopped
	// sending statements. Otherwise an abandoned tx holds row locks
	// indefinitely and blocks every concurrent writer.
	IdleInTxTimeout time.Duration
}

func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:         envInt32("VAULTSCAN_PG_MAX_CONNS", 32),
		MinConns:         envInt32("VAULTSCAN_PG_MIN_CONNS", 4),
		MaxConnLifetime:  envDur("VAULTSCAN_PG_MAX_CONN_LIFETIME", time.Hour),
		MaxConnIdle:      envDur("VAULTSCAN_PG_MAX_CONN_IDLE", 30*time.Minute),
		HealthCheck:      envDur("VAULTSCAN_PG_HEALTHCHECK", 1*time.Minute),
		StatementTimeout: envDur("VAULTSCAN_PG_STATEMENT_TIMEOUT", 30*time.Second),
		IdleInTxTimeout:  envDur("VAULTSCAN_PG_IDLE_IN_TX_TIMEOUT", 60*time.Second),
	}
}

func Open(ctx context.Context, dsn string) (*DB, error) {
	return OpenWithConfig(ctx, dsn, DefaultPoolConfig())
}

// componentDefaults pins reasonable defaults per binary. Operators
// override individual knobs by setting VAULTSCAN_PG_<COMPONENT>_*
// env vars (or the legacy VAULTSCAN_PG_* for global override).
//
// The shapes here are derived from a production target of
// 50 vCPU / 200GB Postgres with ~150 max connections. The sum of
// MaxConns across all binaries in one region MUST stay under that
// ceiling — these defaults total ~80, leaving headroom for
// migrations + ad-hoc operator psql sessions.
var componentDefaults = map[string]PoolConfig{
	"api": {
		MaxConns:         50, // request-driven, many short queries
		MinConns:         8,
		MaxConnLifetime:  time.Hour,
		MaxConnIdle:      30 * time.Minute,
		HealthCheck:      time.Minute,
		StatementTimeout: 15 * time.Second, // short — API has its own request timeouts
		IdleInTxTimeout:  30 * time.Second,
	},
	"scanner-worker": {
		MaxConns:         12, // FOR UPDATE rows held — too many conns wastes them
		MinConns:         2,
		MaxConnLifetime:  2 * time.Hour,
		MaxConnIdle:      time.Hour,
		HealthCheck:      time.Minute,
		StatementTimeout: 5 * time.Minute, // scanner output ingest can be slow
		IdleInTxTimeout:  10 * time.Minute,
	},
	"agent-gateway": {
		MaxConns:         20, // high RPS but tiny queries
		MinConns:         4,
		MaxConnLifetime:  time.Hour,
		MaxConnIdle:      15 * time.Minute,
		HealthCheck:      time.Minute,
		StatementTimeout: 10 * time.Second,
		IdleInTxTimeout:  30 * time.Second,
	},
	"analytics-worker": {
		MaxConns:         8, // long-running aggregations; few conns
		MinConns:         2,
		MaxConnLifetime:  4 * time.Hour, // long-lived; warm caches matter
		MaxConnIdle:      time.Hour,
		HealthCheck:      2 * time.Minute,
		StatementTimeout: 15 * time.Minute, // OLAP queries can take this
		IdleInTxTimeout:  20 * time.Minute,
	},
	"cron-runner": {
		MaxConns:         4, // jobs serialise via leader election anyway
		MinConns:         1,
		MaxConnLifetime:  time.Hour,
		MaxConnIdle:      30 * time.Minute,
		HealthCheck:      2 * time.Minute,
		StatementTimeout: 5 * time.Minute, // partition mgmt, retention cron
		IdleInTxTimeout:  5 * time.Minute,
	},
}

// PoolConfigForComponent returns the right defaults for `component`,
// with VAULTSCAN_PG_* env vars taking precedence (operator override
// works at any layer). Unknown component falls back to the generic
// DefaultPoolConfig so a typo doesn't crash boot.
func PoolConfigForComponent(component string) PoolConfig {
	base, ok := componentDefaults[component]
	if !ok {
		return DefaultPoolConfig()
	}
	// Layer the global VAULTSCAN_PG_* env vars on top — they
	// override the component default if set.
	if v := envInt32("VAULTSCAN_PG_MAX_CONNS", -1); v >= 0 {
		base.MaxConns = v
	}
	if v := envInt32("VAULTSCAN_PG_MIN_CONNS", -1); v >= 0 {
		base.MinConns = v
	}
	if v := envDur("VAULTSCAN_PG_MAX_CONN_LIFETIME", 0); v > 0 {
		base.MaxConnLifetime = v
	}
	if v := envDur("VAULTSCAN_PG_MAX_CONN_IDLE", 0); v > 0 {
		base.MaxConnIdle = v
	}
	if v := envDur("VAULTSCAN_PG_HEALTHCHECK", 0); v > 0 {
		base.HealthCheck = v
	}
	if v := envDur("VAULTSCAN_PG_STATEMENT_TIMEOUT", 0); v > 0 {
		base.StatementTimeout = v
	}
	if v := envDur("VAULTSCAN_PG_IDLE_IN_TX_TIMEOUT", 0); v > 0 {
		base.IdleInTxTimeout = v
	}
	return base
}

// OpenForComponent is the convenience wrapper most binaries use
// instead of Open. Picks the component-specific defaults and opens
// the pool.
func OpenForComponent(ctx context.Context, dsn, component string) (*DB, error) {
	return OpenWithConfig(ctx, dsn, PoolConfigForComponent(component))
}

func OpenWithConfig(ctx context.Context, dsn string, pc PoolConfig) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pg dsn: %w", err)
	}
	cfg.MaxConns = pc.MaxConns
	cfg.MinConns = pc.MinConns
	cfg.MaxConnLifetime = pc.MaxConnLifetime
	cfg.MaxConnIdleTime = pc.MaxConnIdle
	cfg.HealthCheckPeriod = pc.HealthCheck
	// Slow-query tracer logs any statement above the threshold to
	// stderr with sql + duration + (optional) request_id.
	cfg.ConnConfig.Tracer = NewSlowQueryTracer(SlowQueryThresholdFromEnv())
	// AfterConnect runs once per new physical connection. Set the
	// statement + idle-in-transaction timeouts here so they're
	// applied to every conn the pool ever hands out, including
	// reconnects after a Postgres failover.
	if pc.StatementTimeout > 0 || pc.IdleInTxTimeout > 0 {
		stTimeout := pc.StatementTimeout
		idleTx := pc.IdleInTxTimeout
		cfg.AfterConnect = func(ctx context.Context, conn *pgxConn) error {
			if stTimeout > 0 {
				ms := stTimeout.Milliseconds()
				if _, err := conn.Exec(ctx,
					fmt.Sprintf("SET statement_timeout = %d", ms)); err != nil {
					return fmt.Errorf("set statement_timeout: %w", err)
				}
			}
			if idleTx > 0 {
				ms := idleTx.Milliseconds()
				if _, err := conn.Exec(ctx,
					fmt.Sprintf("SET idle_in_transaction_session_timeout = %d", ms)); err != nil {
					return fmt.Errorf("set idle_in_transaction_session_timeout: %w", err)
				}
			}
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect pg: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping pg: %w", err)
	}
	return &DB{Pool: pool}, nil
}

func envInt32(key string, def int32) int32 {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr,
				"vaultscan: %s=%q not a positive int (%v); using default %d\n",
				key, v, err, def)
			return def
		}
		return int32(n)
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			fmt.Fprintf(os.Stderr,
				"vaultscan: %s=%q not a positive duration (%v); using default %s\n",
				key, v, err, def)
			return def
		}
		return d
	}
	return def
}
