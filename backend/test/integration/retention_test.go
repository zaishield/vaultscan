//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// TestEvidence_RetentionEnforcer: SweepExpired purges evidence past its
// expires_at, but honours the immutable_until guard.
func TestEvidence_RetentionEnforcer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "evidence-retention")

	// Put three evidence blobs: one expired-and-purgeable, one expired-but-
	// immutability-locked, one still in retention.
	mkEvidence := func(label string) *time.Time {
		return ptrTime(time.Now())
	}
	_ = mkEvidence

	exp1, _ := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, EngagementID: &engagementID,
		Kind: "raw_output", ContentType: "text/plain", Body: []byte("expired-purgeable"),
		UploadedBy: &adminID,
	})
	exp2, _ := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, EngagementID: &engagementID,
		Kind: "raw_output", ContentType: "text/plain", Body: []byte("expired-locked"),
		UploadedBy: &adminID,
	})
	live, _ := h.vault.Record(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, EngagementID: &engagementID,
		Kind: "raw_output", ContentType: "text/plain", Body: []byte("still-live"),
		UploadedBy: &adminID,
	})

	// 1: expired, no immutability lock — should be purged.
	if _, err := h.pool.Exec(ctx,
		`UPDATE finding_evidence SET expires_at = now() - INTERVAL '1 hour' WHERE id=$1`,
		exp1.ID); err != nil {
		t.Fatalf("set expired: %v", err)
	}
	// 2: expired BUT immutability lock still in force — must NOT be purged.
	if _, err := h.pool.Exec(ctx,
		`UPDATE finding_evidence
		    SET expires_at = now() - INTERVAL '1 hour',
		        immutable_until = now() + INTERVAL '1 hour'
		  WHERE id=$1`, exp2.ID); err != nil {
		t.Fatalf("set locked: %v", err)
	}
	// 3: not yet expired — must NOT be purged.

	n, err := h.vault.SweepExpired(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purge, got %d", n)
	}

	check := func(id any, wantPurged bool) {
		var purged *time.Time
		_ = h.pool.QueryRow(ctx, `SELECT purged_at FROM finding_evidence WHERE id=$1`, id).
			Scan(&purged)
		if wantPurged && purged == nil {
			t.Fatalf("expected purged_at set for %v", id)
		}
		if !wantPurged && purged != nil {
			t.Fatalf("expected purged_at NULL for %v", id)
		}
	}
	check(exp1.ID, true)
	check(exp2.ID, false)
	check(live.ID, false)
}

func ptrTime(t time.Time) *time.Time { return &t }
