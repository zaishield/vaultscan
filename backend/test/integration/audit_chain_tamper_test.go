//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// disableAuditImmutableTrigger turns off the BEFORE UPDATE/DELETE
// trigger on audit_logs for the duration of a test. Production
// keeps the trigger enabled; we're proving that EVEN IF an attacker
// has rights to drop/disable the trigger (or is operating at a
// lower layer like physical disk access), the hash chain still
// catches the tamper.
func disableAuditImmutableTrigger(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx,
		`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update`); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(ctx,
			`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update`)
	})
}

// TestAuditChain_VerifyDeepCatchesPayloadTamper inserts known
// audit rows, then directly UPDATEs one row's payload column in
// place (simulating an attacker with DB write access who's also
// bypassed the append-only trigger). VerifyDeep MUST report the
// tampered row's id as first_bad_id.
//
// Without this test, the audit-chain story is just "we hash
// stuff." With it, we prove the verifier actually detects the
// most realistic forensic-tamper scenario.
func TestAuditChain_VerifyDeepCatchesPayloadTamper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	disableAuditImmutableTrigger(t, h)
	tenantID, _ := h.makeTenant(t, "tamper-payload-"+uuid.NewString()[:6])

	// Write three rows we control.
	for i := 0; i < 3; i++ {
		if err := h.audit.Record(ctx, audit.Entry{
			PlatformID: platformID,
			TenantID:   &tenantID,
			Event:      "tamper.probe",
			ActorType:  "test",
			Payload:    map[string]any{"i": i, "nonce": uuid.NewString()},
		}); err != nil {
			t.Fatalf("write row %d: %v", i, err)
		}
	}

	// Pick one of our three rows by event prefix and a fresh
	// tenant filter. The middle one tests that the verifier finds
	// the FIRST break (so we can locate the rest by ancestry).
	var rowIDs []int64
	rows, err := h.pool.Query(ctx, `
		SELECT id FROM audit_logs
		 WHERE event = 'tamper.probe' AND tenant_id = $1
		 ORDER BY id ASC`, tenantID)
	if err != nil {
		t.Fatalf("list our rows: %v", err)
	}
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		rowIDs = append(rowIDs, id)
	}
	rows.Close()
	if len(rowIDs) < 2 {
		t.Fatalf("need ≥2 probe rows, got %d", len(rowIDs))
	}

	target := rowIDs[1]
	// Snapshot the row's current payload so we can RESTORE it at
	// cleanup — a persistent tamper would poison every subsequent
	// VerifyDeep call run by the rest of the suite.
	var originalPayload string
	if err := h.pool.QueryRow(ctx,
		`SELECT payload FROM audit_logs WHERE id = $1`, target).Scan(&originalPayload); err != nil {
		t.Fatalf("snapshot payload: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE audit_logs SET payload = $2 WHERE id = $1`, target, originalPayload)
	})
	// Directly UPDATE payload — bypassing audit.Record. The
	// chain_hash on this row was computed over the OLD payload;
	// rewriting payload without recomputing the hash creates a
	// detectable mismatch.
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET payload = $2 WHERE id = $1`,
		target, `{"i":1,"nonce":"TAMPERED"}`); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	}
	// First bad must equal our target — that's the audit-trail's
	// forensic value. last_good must be the row immediately
	// before it (or any earlier row, depending on prior tenants'
	// rows in the chain).
	if res.FirstBadID == 0 {
		t.Fatalf("VerifyDeep MISSED the tamper. The verifier is broken.")
	}
	if res.FirstBadID != target {
		t.Errorf("first_bad_id=%d, want=%d (tampered row). last_good=%d detail=%s",
			res.FirstBadID, target, res.LastGoodID, res.Detail)
	}
	if res.Detail == "" {
		t.Error("VerifyDeep should populate detail with the row+event for forensic triage")
	}
}

// TestAuditChain_VerifyDeepCatchesActorTamper proves the chain
// catches actor-id rewrites — the highest-impact tamper class
// because it lets an attacker re-attribute their own actions to a
// different user.
//
// The chain hash includes actor_id (added in the HS-02 deepening
// referenced in audit.go); without that, an attacker with row-level
// UPDATE could rewrite WHO did an action while keeping the
// payload byte-identical. This test confirms actor_id is in the
// hash by detecting precisely that tamper.
func TestAuditChain_VerifyDeepCatchesActorTamper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	disableAuditImmutableTrigger(t, h)
	tenantID, _ := h.makeTenant(t, "tamper-actor-"+uuid.NewString()[:6])

	actor := uuid.New()
	if err := h.audit.Record(ctx, audit.Entry{
		PlatformID: platformID,
		TenantID:   &tenantID,
		ActorID:    &actor,
		Event:      "tamper.actor.probe",
		ActorType:  "user",
		Payload:    map[string]any{"action": "delete_finding"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Get the id of the row we just wrote.
	var target int64
	if err := h.pool.QueryRow(ctx, `
		SELECT id FROM audit_logs
		 WHERE event = 'tamper.actor.probe' AND tenant_id = $1
		 ORDER BY id DESC LIMIT 1`, tenantID).Scan(&target); err != nil {
		t.Fatalf("locate row: %v", err)
	}

	// Snapshot + restore on cleanup so this test doesn't poison
	// any later VerifyDeep call.
	var originalActor *uuid.UUID
	if err := h.pool.QueryRow(ctx,
		`SELECT actor_id FROM audit_logs WHERE id = $1`, target).Scan(&originalActor); err != nil {
		t.Fatalf("snapshot actor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE audit_logs SET actor_id = $2 WHERE id = $1`, target, originalActor)
	})

	// Rewrite the actor_id only. payload + everything else stays
	// the same. The chain hash MUST include actor_id for this to be
	// detectable.
	newActor := uuid.New()
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET actor_id = $2 WHERE id = $1`, target, newActor); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	}
	if res.FirstBadID != target {
		t.Errorf("actor-tamper not detected at the right row: first_bad=%d want=%d (detail: %s)",
			res.FirstBadID, target, res.Detail)
	}
}
