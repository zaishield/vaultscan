//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
)

// helper: ingest one finding + return its id.
func ingestRetestable(t *testing.T, h *harness, tenantID, eng uuid.UUID, title, severity string) uuid.UUID {
	t.Helper()
	f, _, err := h.findings.Upsert(context.Background(), findings.IngestInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: eng,
		Title: title, Severity: severity, Scanner: "nmap",
		AffectedEndpoint: "globex.example",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return f.ID
}

// TestVS09_AutoLaunchOnRemediated: with tenant flag enabled, calling
// AutoLaunchIfEnabled for a remediated finding files a retest. Repeat
// is a no-op (existing in-flight returns same id, launched=false).
func TestVS09_AutoLaunchOnRemediated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs09-auto")
	svc := retesting.New(h.pool, h.audit, h.bus, h.findings, h.scanorch)

	findingID := ingestRetestable(t, h, tenantID, eng, "Open port detected", "medium")
	// triage path then mark remediated (transition table).
	_ = h.findings.Transition(ctx, &adminID, findingID, "triaged", "")
	_ = h.findings.Transition(ctx, &adminID, findingID, "in_progress", "")
	_ = h.findings.Transition(ctx, &adminID, findingID, "remediated", "fixed by ops")

	// First: flag OFF → no launch.
	if err := svc.SetAutoRetestEnabled(ctx, tenantID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	id1, launched1, err := svc.AutoLaunchIfEnabled(ctx, findingID, &adminID)
	if err != nil {
		t.Fatalf("auto1: %v", err)
	}
	if launched1 || id1 != uuid.Nil {
		t.Fatalf("expected no launch when flag off, got launched=%v id=%v", launched1, id1)
	}

	// Enable + retry → launches.
	if err := svc.SetAutoRetestEnabled(ctx, tenantID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	id2, launched2, err := svc.AutoLaunchIfEnabled(ctx, findingID, &adminID)
	if err != nil {
		t.Fatalf("auto2: %v", err)
	}
	if !launched2 || id2 == uuid.Nil {
		t.Fatalf("expected launch, got launched=%v id=%v", launched2, id2)
	}

	// Idempotent: calling again returns the same in-flight retest.
	id3, launched3, err := svc.AutoLaunchIfEnabled(ctx, findingID, &adminID)
	if err != nil {
		t.Fatal(err)
	}
	if id3 != id2 || launched3 {
		t.Fatalf("expected idempotent skip, got id=%v launched=%v", id3, launched3)
	}

	// Diff baseline was captured.
	var snap string
	if err := h.pool.QueryRow(ctx,
		`SELECT original_snapshot::text FROM retest_diffs WHERE retest_request_id=$1`,
		id2).Scan(&snap); err != nil {
		t.Fatalf("baseline snap: %v", err)
	}
	if snap == "" || snap == "{}" {
		t.Fatalf("expected non-empty baseline snapshot, got %q", snap)
	}
}

// TestVS09_BulkRetestBatch: a batch of 3 findings creates a batch row
// with total_items=3 and three batch items.
func TestVS09_BulkRetestBatch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs09-bulk")
	svc := retesting.New(h.pool, h.audit, h.bus, h.findings, h.scanorch)

	var ids []uuid.UUID
	for _, title := range []string{"port 22 weak ciphers", "tls 1.0 enabled", "directory listing exposed"} {
		ids = append(ids, ingestRetestable(t, h, tenantID, eng, title, "medium"))
	}
	batchID, queued, err := svc.CreateBatch(ctx, tenantID, &adminID, "quarterly retest cycle", ids)
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	if queued != 3 {
		t.Fatalf("expected 3 queued, got %d", queued)
	}
	b, err := svc.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatal(err)
	}
	if b.TotalItems != 3 || b.Status != "open" {
		t.Fatalf("unexpected batch state: %+v", b)
	}

	// Mark items progressing.
	var retestIDs []uuid.UUID
	rows, _ := h.pool.Query(ctx,
		`SELECT retest_request_id FROM retest_batch_items WHERE batch_id=$1 ORDER BY ordinal`, batchID)
	for rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		retestIDs = append(retestIDs, id)
	}
	rows.Close()

	if err := svc.MarkBatchItem(ctx, batchID, retestIDs[0], "done"); err != nil {
		t.Fatal(err)
	}
	if err := svc.MarkBatchItem(ctx, batchID, retestIDs[1], "failed"); err != nil {
		t.Fatal(err)
	}
	if err := svc.MarkBatchItem(ctx, batchID, retestIDs[2], "done"); err != nil {
		t.Fatal(err)
	}

	b, _ = svc.GetBatch(ctx, batchID)
	if b.CompletedItems != 2 || b.FailedItems != 1 {
		t.Fatalf("expected 2 completed / 1 failed, got %+v", b)
	}
	if b.Status != "completed" {
		t.Fatalf("expected status completed, got %s", b.Status)
	}
}

// TestVS09_DiffPassedVsFailed: a retest that 'passed' yields verdict
// "resolved"; one that 'failed' yields "regressed".
func TestVS09_DiffPassedVsFailed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs09-diff")
	svc := retesting.New(h.pool, h.audit, h.bus, h.findings, h.scanorch)

	// PASSED case ----------------------------------------------------
	fid1 := ingestRetestable(t, h, tenantID, eng, "tls weak ciphers", "high")
	_ = h.findings.Transition(ctx, &adminID, fid1, "triaged", "")
	_ = h.findings.Transition(ctx, &adminID, fid1, "in_progress", "")
	_ = h.findings.Transition(ctx, &adminID, fid1, "remediated", "fixed")

	rid1, err := svc.Request(ctx, retesting.RequestInput{
		FindingID: fid1, RequestedBy: &adminID, Note: "passed-case",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Capture baseline before result.
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO retest_diffs(retest_request_id, original_snapshot)
		 VALUES ($1, jsonb_build_object(
		     'id', $2::text, 'title', 'tls weak ciphers',
		     'severity', 'high', 'status', 'retest_requested'))`,
		rid1, fid1); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := svc.RecordResult(ctx, retesting.ResultInput{
		RetestRequestID: rid1, Outcome: "passed",
		Summary: "scanner found nothing", DecidedBy: &adminID,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := svc.ComputeDiff(ctx, rid1)
	if err != nil {
		t.Fatalf("diff1: %v", err)
	}
	if d.Verdict != "resolved" {
		t.Fatalf("expected verdict=resolved, got %s", d.Verdict)
	}

	// last_retest_outcome stamped.
	var last string
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(last_retest_outcome,'') FROM findings WHERE id=$1`,
		fid1).Scan(&last)
	if last != "passed" {
		t.Fatalf("expected last_retest_outcome=passed, got %q", last)
	}

	// FAILED case ----------------------------------------------------
	fid2 := ingestRetestable(t, h, tenantID, eng, "directory listing", "medium")
	_ = h.findings.Transition(ctx, &adminID, fid2, "triaged", "")
	_ = h.findings.Transition(ctx, &adminID, fid2, "in_progress", "")
	_ = h.findings.Transition(ctx, &adminID, fid2, "remediated", "fixed")
	rid2, _ := svc.Request(ctx, retesting.RequestInput{
		FindingID: fid2, RequestedBy: &adminID, Note: "failed-case",
	})
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO retest_diffs(retest_request_id, original_snapshot)
		 VALUES ($1, jsonb_build_object(
		     'id', $2::text, 'title', 'directory listing',
		     'severity', 'medium', 'status', 'retest_requested'))`,
		rid2, fid2); err != nil {
		t.Fatal(err)
	}
	_ = svc.RecordResult(ctx, retesting.ResultInput{
		RetestRequestID: rid2, Outcome: "failed",
		Summary: "still present", DecidedBy: &adminID,
	})
	d2, _ := svc.ComputeDiff(ctx, rid2)
	if d2.Verdict != "regressed" {
		t.Fatalf("expected verdict=regressed, got %s", d2.Verdict)
	}
}
