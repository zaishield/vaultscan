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

// PoolConfig is the tunable surface, populated from env vars by Open.
// All knobs have production-grade defaults; bump them for high-load
// environments via VAULTSCAN_PG_{MAX_CONNS, MIN_CONNS, ...}.
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
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return int32(n)
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
