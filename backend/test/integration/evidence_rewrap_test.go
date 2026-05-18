//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// TestEvidence_ReWrapTenantObjects asserts the SOC2-grade KEK/DEK
// rotation re-encrypts existing blobs end-to-end:
//   1. Seal blob A under DEK version 1
//   2. RotateTenantKey → DEK version 2 (blob A stays sealed under v1)
//   3. Seal blob B under DEK version 2
//   4. ReWrapTenantObjects → blob A migrates to v2; blob B is already v2
//   5. Both blobs decrypt under the latest DEK
//   6. encryption_key_version on the DB row reflects the rotation
//   7. evidence_chain_of_custody records a 'rewrapped' event
func TestEvidence_ReWrapTenantObjects(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "rewrap-test")

	plainA := []byte("evidence-blob-A: pre-rotation contents")
	plainB := []byte("evidence-blob-B: post-rotation contents")

	// Seal blob A under DEK v1.
	idA, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: &engagementID,
		Body:         plainA,
		Kind:         "scan_output",
		ContentType:  "text/plain",
		UploadedBy:   &adminID,
	})
	if err != nil {
		t.Fatalf("seal A: %v", err)
	}

	// Force a DEK rotation.
	newVer, err := h.vault.RotateTenantKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("RotateTenantKey: %v", err)
	}
	if newVer < 2 {
		t.Fatalf("expected DEK version >= 2 after rotation, got %d", newVer)
	}

	// Seal blob B under the new DEK.
	idB, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID:     tenantID,
		PartnerID:    directID,
		EngagementID: &engagementID,
		Body:         plainB,
		Kind:         "scan_output",
		ContentType:  "text/plain",
		UploadedBy:   &adminID,
	})
	if err != nil {
		t.Fatalf("seal B: %v", err)
	}

	// Pre-rewrap: blob A is at v1, blob B is at v2.
	verA := readEvidenceVersion(t, h, idA)
	verB := readEvidenceVersion(t, h, idB)
	if verA == verB {
		t.Fatalf("expected A < B pre-rewrap, both at v%d", verA)
	}

	// Run a bounded rewrap pass.
	rewrapped, _, err := h.vault.ReWrapTenantObjects(ctx, tenantID, 100)
	if err != nil {
		t.Fatalf("ReWrapTenantObjects: %v", err)
	}
	if rewrapped != 1 {
		t.Errorf("expected exactly 1 object re-wrapped (blob A), got %d", rewrapped)
	}

	// Both blobs now at v2 (newVer).
	verAAfter := readEvidenceVersion(t, h, idA)
	verBAfter := readEvidenceVersion(t, h, idB)
	if verAAfter != newVer || verBAfter != newVer {
		t.Errorf("post-rewrap version mismatch: A=%d B=%d want both=%d", verAAfter, verBAfter, newVer)
	}

	// Decrypt both via ReadWithDEK — verifies the re-encryption was
	// real (not just a DB metadata flip).
	gotA, err := h.vault.ReadWithDEK(ctx, idA, &adminID, nil, "integration")
	if err != nil {
		t.Fatalf("read A: %v", err)
	}
	if !bytes.Equal(gotA, plainA) {
		t.Errorf("A round-trip plaintext mismatch")
	}
	gotB, err := h.vault.ReadWithDEK(ctx, idB, &adminID, nil, "integration")
	if err != nil {
		t.Fatalf("read B: %v", err)
	}
	if !bytes.Equal(gotB, plainB) {
		t.Errorf("B round-trip plaintext mismatch")
	}

	// Custody event 'rewrapped' was logged for blob A.
	var custody int
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM evidence_chain_of_custody
		 WHERE evidence_id = $1 AND event = 'rewrapped'`, idA).
		Scan(&custody); err != nil {
		t.Fatalf("read custody: %v", err)
	}
	if custody < 1 {
		t.Errorf("expected 'rewrapped' custody event for A, got %d", custody)
	}
}

// TestEvidence_ReWrapTenantObjectsIdempotent — running rewrap twice
// when nothing is stale must report 0 + more=false.
func TestEvidence_ReWrapTenantObjectsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, _ := h.makeTenant(t, "rewrap-idem")
	if _, err := h.vault.RotateTenantKey(ctx, tenantID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	n, more, err := h.vault.ReWrapTenantObjects(ctx, tenantID, 100)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if n != 0 || more {
		t.Errorf("expected (0, false), got (%d, %v)", n, more)
	}
}

func readEvidenceVersion(t *testing.T, h *harness, id uuid.UUID) int {
	t.Helper()
	var v *int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT encryption_key_version FROM finding_evidence WHERE id = $1`, id).
		Scan(&v); err != nil {
		t.Fatalf("read encryption_key_version: %v", err)
	}
	if v == nil {
		t.Fatalf("encryption_key_version is NULL for %s", id)
	}
	return *v
}
