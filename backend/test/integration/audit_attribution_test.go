//go:build integration

// Audit chain attribution coverage. Before adding actor_id +
// user_agent to the canonical hash input, an attacker with write
// access to audit_logs could rewrite WHO performed an action (or
// HOW their browser fingerprint looked) without the chain verifier
// flagging the row. These tests prove that gap is now closed.

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

func TestAuditChain_DetectsActorIDTamper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "audit-actor-"+uuid.NewString()[:6])
	// Write a chained row.
	originalActor := adminID
	if err := h.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
		ActorID: &originalActor, ActorType: "user",
		Event: "test.actor-tamper", TargetType: "test", TargetID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	var rowID int64
	_ = h.pool.QueryRow(ctx,
		`SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&rowID)

	// Bypass the no-update trigger + rewrite actor_id.
	if _, err := h.pool.Exec(ctx,
		`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE audit_logs SET actor_id=$2 WHERE id=$1`, rowID, originalActor)
		_, _ = h.pool.Exec(context.Background(),
			`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update`)
	}()
	// Reattribute to a different actor.
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET actor_id=$1 WHERE id=$2`, uuid.New(), rowID); err != nil {
		t.Fatal(err)
	}
	r, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.FirstBadID == 0 {
		t.Error("actor_id tamper went undetected — verifier didn't catch the rewrite")
	}
	if r.FirstBadID != rowID {
		t.Errorf("chain break reported at id=%d, want %d", r.FirstBadID, rowID)
	}
}

func TestAuditChain_DetectsUserAgentTamper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "audit-ua-"+uuid.NewString()[:6])
	if err := h.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
		ActorID: &adminID, ActorType: "user",
		Event: "test.ua-tamper", TargetType: "test", TargetID: uuid.NewString(),
		UserAgent: "Mozilla/5.0 originalbrowser",
	}); err != nil {
		t.Fatal(err)
	}
	var rowID int64
	var origUA *string
	_ = h.pool.QueryRow(ctx,
		`SELECT id, user_agent FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&rowID, &origUA)

	if _, err := h.pool.Exec(ctx,
		`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE audit_logs SET user_agent=$2 WHERE id=$1`, rowID, origUA)
		_, _ = h.pool.Exec(context.Background(),
			`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update`)
	}()
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET user_agent='TAMPERED-AGENT' WHERE id=$1`, rowID); err != nil {
		t.Fatal(err)
	}
	r, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.FirstBadID == 0 {
		t.Error("user_agent tamper went undetected — verifier didn't catch the rewrite")
	}
}
