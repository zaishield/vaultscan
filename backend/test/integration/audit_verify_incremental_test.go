//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// TestAuditVerifyIncremental_AdvancesCheckpoint verifies the GA
// scale-resumability story: VerifyIncremental does NOT re-scan rows
// that have already been validated. The checkpoint advances on
// success, so an hourly cron tick stays bounded even on a multi-
// million-row chain.
func TestAuditVerifyIncremental_AdvancesCheckpoint(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.makeTenant(t, "verify-incr-"+uuid.NewString()[:6])

	// Run #1: scans whatever audit rows the harness has so far.
	res1, err := h.audit.VerifyIncremental(ctx)
	if err != nil {
		t.Fatalf("verify incremental run 1: %v", err)
	}
	if res1.FirstBadID != 0 {
		t.Fatalf("run 1 reports break at %d: %s", res1.FirstBadID, res1.Detail)
	}
	if res1.Total == 0 {
		t.Fatal("run 1 verified zero rows — checkpoint cannot advance")
	}

	// Capture the checkpoint advance — total should be the count of
	// rows scanned. Run #2 with no new audit activity scans zero rows.
	res2, err := h.audit.VerifyIncremental(ctx)
	if err != nil {
		t.Fatalf("verify incremental run 2: %v", err)
	}
	if res2.FirstBadID != 0 {
		t.Fatalf("run 2 reports break at %d: %s", res2.FirstBadID, res2.Detail)
	}
	if res2.Total != 0 {
		t.Errorf("run 2 should re-scan zero rows (checkpoint advanced); got total=%d", res2.Total)
	}

	// Generate one new audit row — run #3 picks up only that row.
	platID := platformID
	if err := h.audit.Record(ctx, audit.Entry{
		PlatformID: platID, Event: "test.checkpoint_probe",
		ActorType: "system", TargetType: "test",
		Payload: map[string]any{"probe": "checkpoint"},
	}); err != nil {
		t.Fatalf("record probe row: %v", err)
	}
	res3, err := h.audit.VerifyIncremental(ctx)
	if err != nil {
		t.Fatalf("verify incremental run 3: %v", err)
	}
	if res3.FirstBadID != 0 {
		t.Fatalf("run 3 reports break at %d: %s", res3.FirstBadID, res3.Detail)
	}
	if res3.Total != 1 {
		t.Errorf("run 3 should scan exactly 1 new row; got total=%d", res3.Total)
	}
}

// TestAuditVerifyIncremental_CheckpointPersists confirms the
// checkpoint row exists and tracks total verification volume.
func TestAuditVerifyIncremental_CheckpointPersists(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.makeTenant(t, "verify-ckpt-"+uuid.NewString()[:6])

	// Force at least one verification pass.
	if _, err := h.audit.VerifyIncremental(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var lastID int64
	var rowsTotal int64
	if err := h.pool.QueryRow(ctx,
		`SELECT last_verified_id, rows_verified_total
		   FROM audit_chain_verification_checkpoints
		  WHERE id = 1`).Scan(&lastID, &rowsTotal); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if lastID == 0 {
		t.Error("checkpoint last_verified_id should advance past 0")
	}
	if rowsTotal == 0 {
		t.Error("rows_verified_total should be > 0 after a successful run")
	}
}
