//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// TestFindings_DueAtAndSLABreach: every freshly-ingested finding gets a
// due_at derived from the tenant's severity SLA. SweepSLABreaches stamps
// sla_breached_at for findings whose due_at has passed.
func TestFindings_DueAtAndSLABreach(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "findings-sla")

	in := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		Title:    "Outdated OpenSSL",
		Severity: "high",
		Scanner:  "openvas",
		ScanType: "vulnerability",
		AffectedEndpoint: "10.0.0.42",
	}
	f, _, err := h.findings.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var dueAt *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT due_at FROM findings WHERE id=$1`, f.ID).Scan(&dueAt); err != nil {
		t.Fatalf("read due_at: %v", err)
	}
	if dueAt == nil {
		t.Fatalf("expected due_at to be set on insert")
	}
	// Default tenant_settings has high=14 days. due_at must be within 15 days.
	delta := time.Until(*dueAt)
	if delta > 15*24*time.Hour || delta < 13*24*time.Hour {
		t.Fatalf("expected ~14d due_at, got %v from now", delta)
	}

	// Force the finding into the past so the sweep flips it.
	if _, err := h.pool.Exec(ctx,
		`UPDATE findings SET due_at=now() - INTERVAL '1 hour' WHERE id=$1`, f.ID); err != nil {
		t.Fatalf("force past due: %v", err)
	}
	n, err := h.findings.SweepSLABreaches(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected sweep to mark >=1, got %d", n)
	}
	var breachedAt *time.Time
	_ = h.pool.QueryRow(ctx,
		`SELECT sla_breached_at FROM findings WHERE id=$1`, f.ID).Scan(&breachedAt)
	if breachedAt == nil {
		t.Fatalf("expected sla_breached_at to be set")
	}

	// Remediated findings should NOT be marked again on a second sweep.
	if err := h.findings.Transition(ctx, &adminID, f.ID, "triaged", ""); err != nil {
		t.Fatalf("transition triaged: %v", err)
	}
	if err := h.findings.Transition(ctx, &adminID, f.ID, "assigned", ""); err != nil {
		t.Fatalf("transition assigned: %v", err)
	}
	if err := h.findings.Transition(ctx, &adminID, f.ID, "remediated", ""); err != nil {
		t.Fatalf("transition remediated: %v", err)
	}
	// Reset breach flag + push due_at to past again. Sweep must not flip
	// remediated findings.
	if _, err := h.pool.Exec(ctx,
		`UPDATE findings SET sla_breached_at=NULL, due_at=now() - INTERVAL '1 hour' WHERE id=$1`, f.ID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n, _ = h.findings.SweepSLABreaches(ctx)
	if n != 0 {
		t.Fatalf("expected 0 breaches for remediated finding, got %d", n)
	}
}

// TestFindings_BulkAndComments: bulk-transition + add comment + list.
func TestFindings_BulkAndComments(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "findings-bulk")

	var ids []uuid.UUID
	for i := 0; i < 5; i++ {
		f, _, err := h.findings.Upsert(ctx, findings.IngestInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: engagementID,
			Title:    "Vuln " + string(rune('A'+i)),
			Severity: "medium",
			Scanner:  "zap",
			ScanType: "web",
			AffectedEndpoint: "https://x/" + string(rune('A'+i)),
		})
		if err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		ids = append(ids, f.ID)
	}

	n, err := h.findings.BulkPatch(ctx, findings.BulkPatchInput{
		TenantID: tenantID, IDs: ids, Action: "status",
		Status: "triaged", Actor: &adminID,
	})
	if err != nil {
		t.Fatalf("bulk triage: %v", err)
	}
	if n != len(ids) {
		t.Fatalf("expected %d triaged, got %d", len(ids), n)
	}

	// Add a comment to the first finding.
	cid, err := h.findings.AddComment(ctx, findings.CommentInput{
		FindingID: ids[0], AuthorID: &adminID, Body: "Confirmed in staging — assigning to AppSec",
	})
	if err != nil {
		t.Fatalf("add comment: %v", err)
	}
	if cid == uuid.Nil {
		t.Fatalf("comment id empty")
	}
	comments, err := h.findings.ListComments(ctx, ids[0])
	if err != nil {
		t.Fatalf("list comments: %v", err)
	}
	if len(comments) != 1 || comments[0].Body == "" {
		t.Fatalf("expected 1 comment, got %+v", comments)
	}
}

// TestAssets_BulkAndRiskScore: bulk recriticality + composite risk score.
func TestAssets_BulkAndRiskScore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "assets-bulk")

	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		a, err := h.assets.Create(ctx, assets.CreateInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: &engagementID,
			AssetType: "ip", Value: "203.0.113." + string(rune('1'+i)),
			Plane: "external", Criticality: "medium",
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		ids = append(ids, a.ID)
	}

	// Bulk re-criticality → all 3 to critical.
	n, err := h.assets.Bulk(ctx, tenantID, assets.BulkOp{
		IDs: ids, Action: "recriticality", Criticality: "critical", Actor: &adminID,
	})
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 updated, got %d", n)
	}

	// Add findings for the first asset and recompute its risk score. Each
	// finding gets a distinct title so the 9-field dedup key doesn't
	// collapse the two highs into one.
	for _, c := range []struct{ title, sev string }{
		{"crit-1", "critical"},
		{"high-1", "high"},
		{"high-2", "high"},
		{"med-1", "medium"},
	} {
		_, _, err := h.findings.Upsert(ctx, findings.IngestInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: engagementID,
			AssetID:  &ids[0],
			Title:    c.title,
			Severity: c.sev,
			Scanner:  "openvas",
			ScanType: "vulnerability",
			AffectedEndpoint: "203.0.113.1",
		})
		if err != nil {
			t.Fatalf("upsert finding: %v", err)
		}
	}
	if err := h.assets.RecomputeRiskScore(ctx, ids[0]); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	// Debug: dump the findings for ids[0] so future regressions are obvious.
	type fdump struct {
		title, sev, status string
	}
	rows, _ := h.pool.Query(ctx,
		`SELECT title, severity, status FROM findings WHERE asset_id=$1 ORDER BY severity`, ids[0])
	var ingested []fdump
	for rows.Next() {
		var f fdump
		_ = rows.Scan(&f.title, &f.sev, &f.status)
		ingested = append(ingested, f)
	}
	rows.Close()
	t.Logf("findings tied to asset %s: %+v", ids[0], ingested)

	var score float64
	_ = h.pool.QueryRow(ctx, `SELECT risk_score FROM assets WHERE id=$1`, ids[0]).
		Scan(&score)
	if score <= 0 {
		t.Fatalf("expected non-zero risk score, got %f", score)
	}

	// Asset with no findings stays at 0.
	if err := h.assets.RecomputeRiskScore(ctx, ids[2]); err != nil {
		t.Fatalf("recompute idle: %v", err)
	}
	var idle float64
	_ = h.pool.QueryRow(ctx, `SELECT risk_score FROM assets WHERE id=$1`, ids[2]).Scan(&idle)
	if idle != 0 {
		t.Fatalf("expected 0 risk for asset with no findings, got %f", idle)
	}
}
