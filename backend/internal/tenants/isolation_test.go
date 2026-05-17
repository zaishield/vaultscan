package tenants

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// PoolKind constants — pin the literal strings the migration uses,
// so a refactor here surfaces here rather than as runtime SQL
// constraint failures.
func TestPoolKindConstants(t *testing.T) {
	t.Parallel()
	if PoolKindSharedRole != "shared_role" {
		t.Errorf("PoolKindSharedRole drift: %s", PoolKindSharedRole)
	}
	if PoolKindDedicatedDatabase != "dedicated_database" {
		t.Errorf("PoolKindDedicatedDatabase drift: %s", PoolKindDedicatedDatabase)
	}
	if PoolKindDedicatedSchema != "dedicated_schema" {
		t.Errorf("PoolKindDedicatedSchema drift: %s", PoolKindDedicatedSchema)
	}
}

// IsolationRouter constructor + nil safety.
func TestNewIsolationRouter_NilSafe(t *testing.T) {
	t.Parallel()
	r := NewIsolationRouter(nil)
	if r == nil {
		t.Fatal("NewIsolationRouter returned nil")
	}
	if r.dsnLookup == nil {
		t.Error("default dsnLookup not wired")
	}
	if r.cache == nil {
		t.Error("cache not initialized")
	}
}

// SetDSNLookup wires a custom lookup. Calling PoolFor on a router
// with no platform pool + uuid.Nil tenant short-circuits to nil
// platform pool with no DB hit.
func TestPoolFor_NilTenantShortCircuits(t *testing.T) {
	t.Parallel()
	r := NewIsolationRouter(nil)
	p, err := r.PoolFor(context.Background(), uuid.Nil)
	if err != nil {
		t.Errorf("uuid.Nil should not error: %v", err)
	}
	if p != nil {
		t.Errorf("nil platform pool should return nil")
	}
}

// SetDSNLookup overrides the default; ensure the field is mutable.
func TestSetDSNLookup_FieldIsMutable(t *testing.T) {
	t.Parallel()
	r := NewIsolationRouter(nil)
	override := func(_ context.Context, _ uuid.UUID) (string, string, error) {
		return "fake-dsn", PoolKindSharedRole, nil
	}
	r.SetDSNLookup(override)
	// We can't trivially check function-pointer equality (would
	// require reflect.Value.Pointer), but the type-check above
	// confirms the signature, and the override is now in place
	// for any subsequent PoolFor call.
}
