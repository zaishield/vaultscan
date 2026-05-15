//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
)

// fakePDFRenderer simulates the chromium path without needing the
// binary installed — produces a byte-correct PDF header.
type fakePDFRenderer struct{ called int }

func (f *fakePDFRenderer) Name() string { return "chromium" }
func (f *fakePDFRenderer) Render(_ context.Context, html []byte) ([]byte, error) {
	f.called++
	out := append([]byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), html...)
	return out, nil
}

// TestVS10_PDFRendererProducesBinary: when AttachPDFRenderer is wired,
// the FormatPDF export carries a true PDF header.
func TestVS10_PDFRendererProducesBinary(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs10-pdf")

	// Seed one finding so the report has content.
	_, _, _ = h.findings.Upsert(ctx, findings.IngestInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: eng, Title: "tls weak ciphers", Severity: "high",
		Scanner: "nmap", AffectedEndpoint: "globex.example",
	})

	r := &fakePDFRenderer{}
	h.reports.AttachPDFRenderer(r)
	t.Cleanup(func() { h.reports.AttachPDFRenderer(nil) })

	rep, err := h.reports.Generate(ctx, reporting.GenerateInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: eng,
		ReportType: "technical",
		Title:      "VS10 test",
		Formats:    []string{"html", "json", "pdf"},
		GeneratedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if r.called == 0 {
		t.Fatal("renderer was not invoked")
	}

	// The PDF export blob must start with %PDF-.
	var found bool
	for _, e := range rep.Exports {
		if e.Format != "pdf" {
			continue
		}
		blob, _, err := h.vault.Read(ctx, mustEvidenceID(t, h, e.StorageURL),
			&adminID, nil, "go-test")
		if err != nil {
			t.Fatalf("read pdf evidence: %v", err)
		}
		if !strings.HasPrefix(string(blob), "%PDF-") {
			t.Fatalf("PDF export missing magic header: %.10s...", blob)
		}
		found = true
	}
	if !found {
		t.Fatal("no PDF export in report")
	}

	// pdf_renderer column stamped.
	var rendererName string
	if err := h.pool.QueryRow(ctx,
		`SELECT pdf_renderer FROM reports WHERE id=$1`, rep.ID).Scan(&rendererName); err != nil {
		t.Fatal(err)
	}
	if rendererName != "chromium" {
		t.Fatalf("expected pdf_renderer=chromium, got %s", rendererName)
	}
}

// TestVS10_ComplianceMatrix: ingest 4 findings spanning several controls
// and confirm the coverage table groups them correctly.
func TestVS10_ComplianceMatrix(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs10-comp")
	for _, fi := range []findings.IngestInput{
		{Title: "TLS 1.0 enabled on tcp/443", Severity: "high", Scanner: "testssl"},
		{Title: "Weak cipher RC4 negotiated", Severity: "medium", Scanner: "testssl"},
		{Title: "Open port 23 telnet detected", Severity: "high", Scanner: "nmap"},
		{Title: "SQL injection on /login", Severity: "critical", Scanner: "zap"},
	} {
		fi.PlatformID = platformID
		fi.PartnerID = directID
		fi.TenantID = tenantID
		fi.EngagementID = eng
		if _, _, err := h.findings.Upsert(ctx, fi); err != nil {
			t.Fatal(err)
		}
	}

	matrix, err := h.reports.ComplianceMatrix(ctx, "pci_dss", eng)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	if len(matrix) == 0 {
		t.Fatal("no controls in matrix")
	}
	got := map[string]int{}
	for _, c := range matrix {
		got[c.Control.ControlCode] = c.Matches
	}
	// 2.2.4 (Insecure services) should match the telnet finding.
	if got["2.2.4"] < 1 {
		t.Fatalf("expected pci 2.2.4 to match telnet, got %d (%+v)", got["2.2.4"], got)
	}
	// 4.2.1 (Strong cryptography) should match TLS 1.0 + weak cipher.
	if got["4.2.1"] < 2 {
		t.Fatalf("expected pci 4.2.1 to match >=2 findings, got %d", got["4.2.1"])
	}
	// 6.4.1 (Public-facing web apps) should match SQL injection.
	if got["6.4.1"] < 1 {
		t.Fatalf("expected pci 6.4.1 to match sqli, got %d", got["6.4.1"])
	}

	md, _ := h.reports.ComplianceMarkdown(ctx, "pci_dss", eng)
	if !strings.Contains(md, "# Compliance Coverage — PCI_DSS") {
		t.Fatalf("markdown missing heading:\n%s", md[:200])
	}
}

// TestVS10_ScheduleRunDue: create a schedule whose next_run_at is in the
// past, call RunDue, confirm the schedule fired exactly once and
// next_run_at advanced by one day.
func TestVS10_ScheduleRunDue(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs10-sched")

	id, err := h.reports.CreateSchedule(ctx, reporting.CreateScheduleInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: &eng, Name: "daily-tech",
		ReportType: "technical", Cadence: "daily",
		FirstRunAt: time.Now().Add(-time.Hour),
		CreatedBy:  &adminID,
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}

	ran, err := h.reports.RunDue(ctx)
	if err != nil {
		t.Fatalf("rundue: %v", err)
	}
	hit := false
	for _, x := range ran {
		if x == id {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected schedule %s to run, got %v", id, ran)
	}

	// next_run_at advanced.
	var next, last time.Time
	var reportID *uuid.UUID
	if err := h.pool.QueryRow(ctx, `
		SELECT next_run_at, last_run_at, last_report_id
		  FROM report_schedules WHERE id=$1`, id).
		Scan(&next, &last, &reportID); err != nil {
		t.Fatal(err)
	}
	if !next.After(time.Now().Add(20 * time.Hour)) {
		t.Fatalf("next_run_at should advance ~24h, got %s", next)
	}
	if reportID == nil {
		t.Fatal("schedule didn't record last_report_id")
	}

	// Second RunDue: nothing more due, no double-fire.
	ran2, _ := h.reports.RunDue(ctx)
	for _, x := range ran2 {
		if x == id {
			t.Fatalf("schedule re-fired without next_run_at elapsing")
		}
	}
}

// mustEvidenceID extracts the evidence UUID from a `vaultscan://tenant/uuid`
// storage URL. The reporting service stores reports via vault.Put which
// doesn't insert into finding_evidence, so we can't go through GetMeta —
// fall back to parsing.
func mustEvidenceID(t *testing.T, h *harness, storageURL string) uuid.UUID {
	t.Helper()
	// vault.Put writes to disk but doesn't record a finding_evidence row,
	// so for this test we cheat: insert a thin row pointing at the same
	// blob, then return its id.
	parts := strings.Split(storageURL, "/")
	if len(parts) < 2 {
		t.Fatalf("bad url: %s", storageURL)
	}
	tenantID, err := uuid.Parse(parts[len(parts)-2])
	if err != nil {
		t.Fatalf("bad tenant uuid: %v", err)
	}
	var id uuid.UUID
	if err := h.pool.QueryRow(context.Background(), `
		INSERT INTO finding_evidence(tenant_id, partner_id, evidence_type,
		    storage_url, sha256, size_bytes, content_type, encrypted)
		VALUES ($1, $2, 'report', $3, '00', 0, 'application/pdf', true)
		RETURNING id`,
		tenantID, directID, storageURL).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
