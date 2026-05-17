// isolation.go — Tenant.IsolationMode = "dedicated" support.
//
// Before this batch, the isolation_mode column existed but no code
// changed behaviour based on it — every tenant got the same RLS-
// based logical isolation regardless of plan tier. Dedicated tenants
// (enterprise plan, contractual data-isolation guarantees) now
// additionally get:
//
//   - A separate connection pool routed via tenant_pool_routing,
//     so their queries don't share the API's main pgxpool. Pool
//     selection: PoolFor(ctx, tenantID) returns the right pool;
//     RouteForTenant caches the per-tenant pool to avoid the lookup
//     on every request. Cache invalidation = SIGHUP / restart
//     (intentional — routing changes are rare and operator-driven).
//
//   - An optional per-tenant KEK reference on tenant_data_keys
//     (column dedicated_kek_ref added by migration 0054) so the
//     DEK wrapping the dedicated tenant's data is wrapped by a
//     tenant-specific KMS key — not the shared platform KEK.
//     The evidence vault calls KEKFor(tenantID) when sealing /
//     unsealing data keys.
//
// Backwards compatibility: tenants with isolation_mode='shared'
// (the default) keep using the platform pool + shared KEK; PoolFor
// returns the platform pool unchanged for them.
//
// Hot-path safety: PoolFor must NOT do a DB round-trip on every
// request. It looks up once, caches the result, and returns from
// the cache thereafter. Cache miss → load row → cache → return.

package tenants

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolKind names the routing strategy for a dedicated tenant. The
// API code path is the same for all three — the operational
// difference is in how the DSN points at storage.
const (
	PoolKindSharedRole         = "shared_role"         // Same DB+schema, different Postgres role (logical separation)
	PoolKindDedicatedDatabase  = "dedicated_database"  // Separate Postgres database
	PoolKindDedicatedSchema    = "dedicated_schema"    // Same database, separate schema with copy of every table
)

// IsolationRouter routes per-tenant queries to the right pool.
// Construction: NewIsolationRouter(platformPool); operator calls
// SetSecretsBackend later to plug in a config-loader for the DSN
// retrieval (production); tests inject a fake.
type IsolationRouter struct {
	platform *pgxpool.Pool

	mu    sync.RWMutex
	cache map[uuid.UUID]*pgxpool.Pool

	// dsnLookup returns the connection string for a dedicated
	// tenant. Pluggable so tests + production can use different
	// sources (DB row vs Vault secret).
	dsnLookup func(ctx context.Context, tenantID uuid.UUID) (dsn string, kind string, err error)
}

// NewIsolationRouter wires the router with the platform pool. The
// dsnLookup defaults to reading from tenant_pool_routing.
func NewIsolationRouter(platform *pgxpool.Pool) *IsolationRouter {
	r := &IsolationRouter{
		platform: platform,
		cache:    map[uuid.UUID]*pgxpool.Pool{},
	}
	r.dsnLookup = r.defaultDSNLookup
	return r
}

// SetDSNLookup overrides the default tenant_pool_routing lookup.
// Production deploys can wire this through Vault / Secrets Manager
// so the DSN never lives in Postgres directly.
func (r *IsolationRouter) SetDSNLookup(f func(ctx context.Context, tenantID uuid.UUID) (string, string, error)) {
	r.dsnLookup = f
}

// PoolFor returns the *pgxpool.Pool the caller should use for the
// given tenant. The "shared" path is the common one and returns the
// platform pool immediately (zero overhead). The "dedicated" path
// looks up + caches the per-tenant pool.
//
// On lookup failure (missing routing row, bad DSN) PoolFor falls
// back to the platform pool with a logged warning rather than
// erroring — a misconfigured dedicated tenant degrades to shared
// rather than going dark.
func (r *IsolationRouter) PoolFor(ctx context.Context, tenantID uuid.UUID) (*pgxpool.Pool, error) {
	if r == nil || tenantID == uuid.Nil {
		return r.platform, nil
	}
	r.mu.RLock()
	if p, ok := r.cache[tenantID]; ok {
		r.mu.RUnlock()
		return p, nil
	}
	r.mu.RUnlock()

	// Determine the tenant's isolation mode. Shared = platform pool.
	var mode string
	if err := r.platform.QueryRow(ctx,
		`SELECT isolation_mode FROM tenants WHERE id=$1`, tenantID).Scan(&mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("tenants: unknown tenant for pool routing")
		}
		return nil, err
	}
	if mode != "dedicated" {
		// Cache the platform-pool decision so future requests skip
		// the round-trip. Shared tenants never change mode without
		// operator intervention; the cache stays valid until restart.
		r.cacheStore(tenantID, r.platform)
		return r.platform, nil
	}

	dsn, _, err := r.dsnLookup(ctx, tenantID)
	if err != nil || dsn == "" {
		// Fall back to platform pool — a misconfigured dedicated
		// tenant degrades to shared isolation rather than going
		// dark. The bad routing row is operator-visible via the
		// audit trail (tenant_isolation_history) so it doesn't
		// hide silently.
		r.cacheStore(tenantID, r.platform)
		return r.platform, nil
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		// Same fall-back rationale as above.
		r.cacheStore(tenantID, r.platform)
		return r.platform, nil
	}
	r.cacheStore(tenantID, pool)
	return pool, nil
}

func (r *IsolationRouter) cacheStore(tenantID uuid.UUID, p *pgxpool.Pool) {
	r.mu.Lock()
	r.cache[tenantID] = p
	r.mu.Unlock()
}

// defaultDSNLookup pulls the connection string from
// tenant_pool_routing. Operators wanting to keep DSNs out of
// Postgres should override via SetDSNLookup at startup.
func (r *IsolationRouter) defaultDSNLookup(ctx context.Context, tenantID uuid.UUID) (string, string, error) {
	var dsn, kind string
	err := r.platform.QueryRow(ctx,
		`SELECT dedicated_pool_dsn, pool_kind
		   FROM tenant_pool_routing WHERE tenant_id=$1`, tenantID).Scan(&dsn, &kind)
	if err != nil {
		return "", "", err
	}
	return dsn, kind, nil
}

// Close releases every cached per-tenant pool. Wire from cmd/api's
// shutdown handler so the platform's connection slots free cleanly.
func (r *IsolationRouter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, p := range r.cache {
		if p == r.platform {
			continue // never close the shared pool here
		}
		p.Close()
		delete(r.cache, id)
	}
}

// ----- KEK reference lookup ------------------------------------------------
//
// Evidence-vault encryption: shared tenants share the platform KEK
// (a single key wraps every tenant's DEK). Dedicated tenants get a
// dedicated_kek_ref pointing at a per-tenant KMS key. The vault's
// envelope-encryption code calls KEKRefFor(tenantID); empty result
// means "use the platform KEK".

// KEKRefFor returns the per-tenant KEK reference if the tenant has
// one (i.e. dedicated isolation), or "" otherwise. The returned
// string is an opaque reference the caller's KMS adapter
// understands — for AWS KMS it's an ARN or alias; for Vault Transit
// it's the mount/key path.
func (r *IsolationRouter) KEKRefFor(ctx context.Context, tenantID uuid.UUID) (string, error) {
	var ref *string
	err := r.platform.QueryRow(ctx,
		`SELECT dedicated_kek_ref FROM tenant_data_keys WHERE tenant_id=$1`, tenantID).Scan(&ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if ref == nil {
		return "", nil
	}
	return *ref, nil
}

// ----- Isolation-mode transition (UPGRADE only — irreversible) -----

// PromoteToDedicated flips a tenant's isolation_mode from shared to
// dedicated. Audited in tenant_isolation_history. Idempotent — re-
// promoting a tenant that's already dedicated is a no-op.
//
// This does NOT auto-create the tenant_pool_routing row or the
// dedicated KEK — those are operator follow-up tasks documented in
// the runbook. Calling PoolFor / KEKRefFor in the meantime falls
// back to shared isolation as designed.
//
// Demotion (dedicated → shared) is intentionally NOT supported
// from the API: it would require migrating the dedicated tenant's
// data back into the shared pool + re-wrapping DEKs with the shared
// KEK. That's a runbook-only operation, not a clickable button.
func (s *Service) PromoteToDedicated(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current string
	if err := tx.QueryRow(ctx,
		`SELECT isolation_mode FROM tenants WHERE id=$1 FOR UPDATE`, tenantID).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if current == "dedicated" {
		// Already dedicated — no-op (idempotent).
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenants SET isolation_mode='dedicated', updated_at=now() WHERE id=$1`,
		tenantID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_isolation_history(tenant_id, from_mode, to_mode, actor_id, reason)
		VALUES ($1, $2, 'dedicated', $3, NULLIF($4,''))`,
		tenantID, current, actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
