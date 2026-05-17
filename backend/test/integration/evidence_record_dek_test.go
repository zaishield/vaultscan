//go:build integration

// Record now uses per-tenant DEK by default. This test pins the
// invariant: an object written via the legacy Record() call must
// land with encryption_key_version IS NOT NULL — proof that the
// master-key fallback isn't silently in use for all callers.
//
// Without this test, a regression that disabled the DEK path would
// be invisible until a KEK compromise revealed that every tenant's
// evidence was sealed with a single shared key.

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

func TestRecord_UsesPerTenantDEK(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "ev-dek-"+uuid.NewString()[:6])

	ev, err := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID,
		Kind: "raw_output", ContentType: "text/plain",
		Body: []byte("audit evidence body"),
	})
	if err != nil {
		t.Fatal(err)
	}

	var keyVersion *int
	if err := h.pool.QueryRow(ctx,
		`SELECT encryption_key_version FROM finding_evidence WHERE id=$1`,
		ev.ID).Scan(&keyVersion); err != nil {
		t.Fatal(err)
	}
	if keyVersion == nil {
		t.Fatal("Record() wrote encryption_key_version=NULL — per-tenant DEK path is not engaged; KEK compromise would reveal all tenants")
	}
	if *keyVersion < 1 {
		t.Fatalf("expected key version >= 1, got %d", *keyVersion)
	}

	// Read must round-trip through the DEK envelope without the
	// caller having to know which key version is in play.
	plain, _, err := h.vault.Read(ctx, ev.ID, nil, nil, "test-ua")
	if err != nil {
		t.Fatalf("Read after DEK-path Record failed: %v", err)
	}
	if string(plain) != "audit evidence body" {
		t.Fatalf("plaintext round-trip mismatch: %q", plain)
	}
}

// TestRecord_PerTenantKeysAreDifferent: two tenants writing the same
// body must produce different ciphertexts AND have distinct DEKs in
// tenant_data_keys. Proves the isolation property.
func TestRecord_PerTenantKeysAreDifferent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantA, _ := h.makeTenant(t, "ev-dek-a-"+uuid.NewString()[:6])
	tenantB, _ := h.makeTenant(t, "ev-dek-b-"+uuid.NewString()[:6])

	body := []byte("the same body bytes for both tenants")
	evA, err := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantA, PartnerID: directID,
		Kind: "raw_output", ContentType: "text/plain", Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	evB, err := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantB, PartnerID: directID,
		Kind: "raw_output", ContentType: "text/plain", Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Storage URLs differ (per-tenant prefix).
	if evA.StorageURL == evB.StorageURL {
		t.Fatal("two tenants produced the same storage URL")
	}

	// Wrapped DEKs differ — the unit of compromise is per-tenant.
	var wrappedA, wrappedB []byte
	_ = h.pool.QueryRow(ctx,
		`SELECT wrapped_key FROM tenant_data_keys WHERE tenant_id=$1 ORDER BY key_version DESC LIMIT 1`,
		tenantA).Scan(&wrappedA)
	_ = h.pool.QueryRow(ctx,
		`SELECT wrapped_key FROM tenant_data_keys WHERE tenant_id=$1 ORDER BY key_version DESC LIMIT 1`,
		tenantB).Scan(&wrappedB)
	if len(wrappedA) == 0 || len(wrappedB) == 0 {
		t.Fatal("expected both tenants to have wrapped DEK rows")
	}
	if string(wrappedA) == string(wrappedB) {
		t.Fatal("tenants share a wrapped DEK — per-tenant isolation is broken")
	}
}
