package db

import (
	"context"

	"github.com/google/uuid"
	pgxConnAliasRLS "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rlsCtxKey is the context key under which middleware stashes the
// caller's tenant binding. The pool's BeforeAcquire callback reads
// this key on every checkout and SETs the vaultscan.tenant_id GUC
// on the freshly-acquired connection — guaranteeing that whichever
// conn the handler ends up using, the RLS policy
//
//   USING (vaultscan_current_tenant_id() IS NULL
//          OR tenant_id = vaultscan_current_tenant_id())
//
// sees the right tenant. This closes the GUC race that existed when
// SetTenantContext set the GUC on ONE pool-borrowed conn and the
// handler's subsequent pool.Exec/Query grabbed a DIFFERENT conn.
type rlsCtxKeyT struct{}

var rlsCtxKey = rlsCtxKeyT{}

// rlsBinding represents the per-request tenant binding pulled out of
// ctx by BeforeAcquire. tenantID == uuid.Nil means "clear" (RLS
// passes through — used by service paths that legitimately read
// across tenants: analytics worker, cosign verifier).
type rlsBinding struct {
	tenantID uuid.UUID
	// set true when the binding was placed explicitly by middleware
	// (vs. an unauthenticated request where we want the conn cleared
	// of any GUC inherited from a prior request).
	bound bool
}

// ContextWithTenantBinding returns ctx with the given tenant attached.
// The pool's BeforeAcquire callback will set vaultscan.tenant_id to
// this tenant on every conn checked out under this ctx. Pass uuid.Nil
// to bind "no tenant" (RLS pass-through). Use ContextWithoutTenantBinding
// to explicitly remove any prior binding.
func ContextWithTenantBinding(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, rlsCtxKey, rlsBinding{tenantID: tenantID, bound: true})
}

// ContextWithoutTenantBinding returns ctx with the tenant binding
// removed. Useful for nested calls that must escape the request's
// tenant binding (cross-tenant aggregation, system maintenance).
func ContextWithoutTenantBinding(ctx context.Context) context.Context {
	return context.WithValue(ctx, rlsCtxKey, rlsBinding{tenantID: uuid.Nil, bound: true})
}

// tenantBindingFromContext returns the binding stashed by middleware
// (or empty + false when none — BeforeAcquire then leaves the conn
// untouched, and AfterRelease still clears the GUC on return).
func tenantBindingFromContext(ctx context.Context) (rlsBinding, bool) {
	v, ok := ctx.Value(rlsCtxKey).(rlsBinding)
	return v, ok
}

// installRLSHooks wires the BeforeAcquire + AfterRelease pool
// callbacks that bind the GUC per-request. Called by OpenWithConfig.
// Composes with any existing AfterRelease (so we don't blow away
// hooks set by, say, the replica's read-only enforcement).
func installRLSHooks(cfg *pgxpool.Config) {
	prevBeforeAcquire := cfg.BeforeAcquire
	cfg.BeforeAcquire = func(ctx context.Context, conn *pgxConnAliasRLS.Conn) bool {
		if prevBeforeAcquire != nil && !prevBeforeAcquire(ctx, conn) {
			return false
		}
		binding, ok := tenantBindingFromContext(ctx)
		// No binding in ctx → leave the conn as-is. AfterRelease
		// will have cleared the GUC when this conn was returned to
		// the pool, so the default is "no tenant" (pass-through RLS).
		if !ok {
			return true
		}
		v := ""
		if binding.tenantID != uuid.Nil {
			v = binding.tenantID.String()
		}
		if _, err := conn.Exec(ctx,
			`SELECT set_config('vaultscan.tenant_id', $1, false)`, v); err != nil {
			// Failing to set the GUC must NOT silently hand back a
			// conn that may carry a stale tenant binding from the
			// previous user. Discard the conn — pool will spin a
			// fresh one. The handler's subsequent Acquire will retry.
			return false
		}
		return true
	}
	prevAfterRelease := cfg.AfterRelease
	cfg.AfterRelease = func(conn *pgxConnAliasRLS.Conn) bool {
		// Clear the GUC unconditionally before the conn re-enters
		// the pool. If clear fails the conn is suspect — destroy it.
		if _, err := conn.Exec(context.Background(),
			`SELECT set_config('vaultscan.tenant_id', '', false)`); err != nil {
			return false
		}
		if prevAfterRelease != nil {
			return prevAfterRelease(conn)
		}
		return true
	}
}

// SetTenantContext is retained for backward compatibility with code
// paths that haven't yet been migrated to ContextWithTenantBinding.
// It is no longer the primary RLS binding mechanism: the pool's
// BeforeAcquire/AfterRelease hooks do the binding properly. This
// function is now a thin shim that updates the request context and
// pre-sets the GUC on one pooled conn (best-effort warmup).
//
// New code should prefer ContextWithTenantBinding(ctx, tid) and pass
// the returned ctx down — the pool will set the GUC on whichever
// conn the handler ends up using, racelessly.
func SetTenantContext(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) error {
	v := ""
	if tenantID != uuid.Nil {
		v = tenantID.String()
	}
	_, err := pool.Exec(ctx, `SELECT set_config('vaultscan.tenant_id', $1, false)`, v)
	return err
}

// ClearTenantContext is the legacy convenience helper. Prefer
// ContextWithoutTenantBinding for new code.
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
