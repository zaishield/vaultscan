// Package db wraps the pgx connection pool used by every service.
package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
}

func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:        envInt32("VAULTSCAN_PG_MAX_CONNS", 32),
		MinConns:        envInt32("VAULTSCAN_PG_MIN_CONNS", 4),
		MaxConnLifetime: envDur("VAULTSCAN_PG_MAX_CONN_LIFETIME", time.Hour),
		MaxConnIdle:     envDur("VAULTSCAN_PG_MAX_CONN_IDLE", 30*time.Minute),
		HealthCheck:     envDur("VAULTSCAN_PG_HEALTHCHECK", 1*time.Minute),
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
