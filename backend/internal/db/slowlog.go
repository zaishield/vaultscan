// slowlog.go — pgx QueryTracer that logs slow queries.
//
// The threshold defaults to 500ms (env: VAULTSCAN_PG_SLOW_QUERY_MS).
// Faster queries are silent; slow ones get a single structured log
// line with the SQL + duration + (optional) request ID pulled from
// the ctx. That makes correlating "user X waited 8s" to a specific
// query trivial in log search.
//
// SQL is truncated to 512 chars to prevent log explosion from giant
// COPY / ANALYZE / DDL statements; the truncation is signalled with
// a trailing "...".
package db

import (
	"context"
	"os"
	"strconv"
	"time"

	pgx "github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// slowQueryTracer implements pgx.QueryTracer. We track per-query
// start times via a context key and emit a single log line on
// completion when duration exceeds the threshold.
type slowQueryTracer struct {
	log       zerolog.Logger
	threshold time.Duration
}

type slowQueryStart struct {
	start time.Time
	sql   string
}

type slowQueryCtxKey struct{}

// NewSlowQueryTracer returns a tracer ready to attach to a pgxpool
// Config. threshold=0 disables logging entirely (use that in unit
// tests).
func NewSlowQueryTracer(threshold time.Duration) pgx.QueryTracer {
	if threshold <= 0 {
		// 0 = disabled — caller may want this in tests where every
		// query has unpredictable scheduling.
		return noopTracer{}
	}
	return &slowQueryTracer{
		log: zerolog.New(os.Stderr).With().
			Timestamp().Str("component", "pg-slow-query").Logger(),
		threshold: threshold,
	}
}

func (t *slowQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, slowQueryCtxKey{}, &slowQueryStart{
		start: time.Now(),
		sql:   data.SQL,
	})
}

func (t *slowQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	st, ok := ctx.Value(slowQueryCtxKey{}).(*slowQueryStart)
	if !ok || st == nil {
		return
	}
	d := time.Since(st.start)
	if d < t.threshold {
		return
	}
	sql := st.sql
	if len(sql) > 512 {
		sql = sql[:512] + "..."
	}
	ev := t.log.Warn().
		Dur("duration", d).
		Str("sql", sql)
	if data.Err != nil {
		ev = ev.Err(data.Err)
	}
	// Optional request-ID correlation via the package-level hook.
	// cmd/api wires this once at startup; tests leave it nil.
	if requestIDExtractor != nil {
		if rid := requestIDExtractor(ctx); rid != "" {
			ev = ev.Str("request_id", rid)
		}
	}
	ev.Msg("slow query")
}

// requestIDExtractor is set by cmd/api/main.go at startup to plug
// in middleware.RequestIDFromContext without creating a db →
// middleware import cycle. Nil = no request_id field on slow
// query logs (still log SQL + duration).
var requestIDExtractor func(ctx context.Context) string

// SetRequestIDExtractor wires the request-ID lookup. Call once at
// process startup. Safe to leave unset in tests.
func SetRequestIDExtractor(f func(ctx context.Context) string) {
	requestIDExtractor = f
}

// noopTracer no-ops both methods so we don't pay the per-query
// overhead in production when the threshold is set to 0.
type noopTracer struct{}

func (noopTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (noopTracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {}

// SlowQueryThresholdFromEnv returns the configured threshold or
// the 500ms default when unset.
func SlowQueryThresholdFromEnv() time.Duration {
	if v := os.Getenv("VAULTSCAN_PG_SLOW_QUERY_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 500 * time.Millisecond
}
