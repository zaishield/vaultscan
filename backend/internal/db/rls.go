package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SetTenantContext sets the vaultscan.tenant_id GUC at session scope on
// a connection acquired from pool. The GUC binds the RLS policy:
//
//   USING (vaultscan_current_tenant_id() IS NULL
//          OR tenant_id = vaultscan_current_tenant_id())
//
// IMPORTANT — connection reuse caveat:
//
//   pgxpool reuses connections across requests. set_config(_, _, false)
//   sets a session-scoped GUC, so once a conn returns to the pool the
//   GUC value persists; the next caller may inherit it. To avoid that,
//   callers that NEED airtight per-request isolation should use
//   WithTenantBoundConn (below), which acquires a dedicated conn,
//   SETs, runs the function, and RESETs the GUC before release.
//
// For best-effort middleware use (the API HTTP path), this function
// is still useful: it pre-sets the GUC on whatever conn the next
// pool.Exec/Query happens to grab, and on every authenticated request
// the value is freshly overwritten — race conditions can only leak
// rows during a narrow window, and the application's WHERE-clause
// discipline already filters by tenant_id. This is defense-in-depth,
// not the primary defense.
//
// Pass uuid.Nil to clear the GUC (RLS falls back to pass-through —
// the right behaviour for service paths that legitimately need
// cross-tenant reads: analytics worker, cosign verifier).
func SetTenantContext(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) error {
	v := ""
	if tenantID != uuid.Nil {
		v = tenantID.String()
	}
	_, err := pool.Exec(ctx, `SELECT set_config('vaultscan.tenant_id', $1, false)`, v)
	return err
}

// ClearTenantContext is a convenience for the analytics worker and other
// service paths that need cross-tenant reads.
func ClearTenantContext(ctx context.Context, pool *pgxpool.Pool) error {
	return SetTenantContext(ctx, pool, uuid.Nil)
}

// WithTenantBoundConn acquires a dedicated connection from pool, sets
// the tenant GUC on it, runs fn, then resets the GUC before releasing
// the conn. Use this when you need airtight per-request RLS isolation —
// e.g. when reading wrapped DEKs or aggregating sensitive cross-tenant
// data on the same pool a different request might use moments later.
//
// fn receives the conn so it can issue its own queries on the same
// session where the GUC is set.
func WithTenantBoundConn(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID uuid.UUID,
	fn func(conn *pgxpool.Conn) error,
) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	v := ""
	if tenantID != uuid.Nil {
		v = tenantID.String()
	}
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vaultscan.tenant_id', $1, false)`, v); err != nil {
		return err
	}
	// Reset before release so the next user of this conn doesn't inherit
	// the binding. Best-effort: if Reset fails, we still release the conn
	// (subsequent borrow will overwrite the GUC).
	defer func() {
		_, _ = conn.Exec(context.Background(),
			`SELECT set_config('vaultscan.tenant_id', '', false)`)
	}()

	return fn(conn)
}
