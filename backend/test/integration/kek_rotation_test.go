//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// TestKEKRotation_EndToEnd is the operator-grade proof that the
// platform survives a master-KEK rotation:
//
//   1. Vault #1 is configured with the test harness's dev KEK
//      (acting as "the original master"). Seal an evidence blob.
//   2. Mint a fresh random KEK to simulate a freshly-provisioned
//      rotation target.
//   3. Re-construct the Vault with the NEW key as active and the
//      OLD key in WithPreviousMasterKeys. Existing evidence MUST
//      still decrypt (the unwrap fallback to the retired KEK
//      kicks in).
//   4. Run RewrapTenantDEKsToActiveKEK. All tenant_data_keys rows
//      that were wrapped under the old KEK get re-wrapped under
//      the new active KEK.
//   5. After the rewrap, re-construct the Vault with ONLY the new
//      KEK (no previous). Existing evidence MUST still decrypt —
//      proving the rewrap actually moved every row off the
//      retired KEK and the old key material can now be destroyed.
func TestKEKRotation_EndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "kek-rot-"+uuid.NewString()[:6])

	// The harness's vault was constructed with the dev-test master
	// KEK already. Seal a blob under it.
	plainOld := []byte("evidence sealed under KEK v1")
	idOld, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: &engagementID,
		Body:         plainOld,
		Kind:         "scan_output",
		ContentType:  "text/plain",
		UploadedBy:   &adminID,
	})
	if err != nil {
		t.Fatalf("seal under KEK v1: %v", err)
	}

	// Mint a fresh KEK to act as v2.
	newKeyBytes := make([]byte, 32)
	if _, err := rand.Read(newKeyBytes); err != nil {
		t.Fatal(err)
	}
	newKeyB64 := base64.StdEncoding.EncodeToString(newKeyBytes)
	oldKeyB64 := "ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA="

	// ---- Phase 1: rotation window ----
	// New active KEK + old KEK in previous list. Existing rows are
	// still wrapped under old; new writes are wrapped under new.
	rotatingVault, err := evidence.NewVault(h.pool,
		audit.New(h.pool), eventbus.New(h.pool),
		newKeyB64,
		evidence.WithStorage(h.vault.Storage()),
		evidence.WithActiveKEKID("platform-master-v2"),
		evidence.WithPreviousMasterKeys([]string{oldKeyB64}),
	)
	if err != nil {
		t.Fatalf("rotating vault: %v", err)
	}

	// Existing evidence still decrypts (via retired-KEK fallback).
	gotOld, err := rotatingVault.ReadWithDEK(ctx, idOld, &adminID, nil, "kek-rot-test")
	if err != nil {
		t.Fatalf("read old evidence during rotation: %v", err)
	}
	if string(gotOld) != string(plainOld) {
		t.Fatalf("rotation-window read returned wrong plaintext: got %q want %q",
			gotOld, plainOld)
	}

	// Run the rewrap sweep. Every row whose kek_id != active must
	// be re-wrapped.
	rewrapped, _, err := rotatingVault.RewrapTenantDEKsToActiveKEK(ctx, 1000)
	if err != nil {
		t.Fatalf("RewrapTenantDEKsToActiveKEK: %v", err)
	}
	if rewrapped == 0 {
		t.Fatal("expected ≥1 row to be re-wrapped under the new KEK")
	}

	// ---- Phase 2: retired KEK removed from config ----
	postRotateVault, err := evidence.NewVault(h.pool,
		audit.New(h.pool), eventbus.New(h.pool),
		newKeyB64,
		evidence.WithStorage(h.vault.Storage()),
		evidence.WithActiveKEKID("platform-master-v2"),
		// NO previous KEK. If the rewrap missed a row, this Read
		// would fail with "unwrap failed against active + all
		// retired KEKs".
	)
	if err != nil {
		t.Fatalf("post-rotate vault: %v", err)
	}

	got, err := postRotateVault.ReadWithDEK(ctx, idOld, &adminID, nil, "kek-rot-test")
	if err != nil {
		t.Fatalf("read after retired KEK dropped: %v", err)
	}
	if string(got) != string(plainOld) {
		t.Errorf("post-rotation read mismatch: got %q want %q", got, plainOld)
	}

	// Verify the DB row actually reflects the new kek_id.
	var kekID string
	if err := h.pool.QueryRow(ctx,
		`SELECT kek_id FROM tenant_data_keys WHERE tenant_id = $1
		   AND retired_at IS NULL
		 ORDER BY key_version DESC LIMIT 1`, tenantID).Scan(&kekID); err != nil {
		t.Fatalf("read kek_id: %v", err)
	}
	if kekID != "platform-master-v2" {
		t.Errorf("DB kek_id = %q, want platform-master-v2 (rewrap didn't update)", kekID)
	}
}

// TestKEKRotation_RewrapIsIdempotent verifies that re-running the
// sweep after convergence is a no-op. Operators schedule
// rotations as recurring runs; "I already did the work" must not
// duplicate effort or corrupt state.
func TestKEKRotation_RewrapIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "kek-idem-"+uuid.NewString()[:6])

	// Seal one blob under the harness's default KEK ("v1").
	if _, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: &engagementID,
		Body:         []byte("idempotency probe"),
		Kind:         "scan_output",
		ContentType:  "text/plain",
		UploadedBy:   &adminID,
	}); err != nil {
		t.Fatal(err)
	}

	// Build a vault whose active KEK matches the existing rows'
	// kek_id (i.e. "no rotation needed"). The sweep must report 0.
	v, err := evidence.NewVault(h.pool,
		audit.New(h.pool), eventbus.New(h.pool),
		"ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA=",
		evidence.WithStorage(h.vault.Storage()),
		evidence.WithActiveKEKID("platform-master-v1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, more, err := v.RewrapTenantDEKsToActiveKEK(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped != 0 || more {
		t.Errorf("expected (0, false) when all rows already under active KEK; got (%d, %v)",
			rewrapped, more)
	}
}
