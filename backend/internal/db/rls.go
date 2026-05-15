package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SetTenantContext sets the per-session vaultscan.tenant_id GUC so RLS
// policies on findings / assets / finding_evidence kick in. Designed to
// be called from the API tenant-scope middleware after authentication
// resolves the request's tenant.
//
// Pass uuid.Nil (or "") to clear the GUC — RLS then falls back to the
// pass-through branch (vaultscan_current_tenant_id() IS NULL), which
// is the right behaviour for service paths that legitimately need
// cross-tenant reads (analytics worker, cosign verifier).
//
// pgx releases connections back to the pool after each query, so the
// GUC must be re-applied on every request. The pool-acquire path here
// guarantees that by issuing the SET and the subsequent caller-supplied
// work on the same connection.
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
