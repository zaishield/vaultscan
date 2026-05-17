// default_renderers.go — concrete DOCXRenderer / XLSXRenderer
// implementations that ship with the binary. Operators can override
// at startup via Service.SetDOCXRenderer / SetXLSXRenderer to plug
// in unioffice / excelize for richer output (charts, conditional
// formatting, page headers). The defaults are intentionally
// minimal: a tabular dump of findings sufficient for compliance
// import workflows, audit handover, and ticketing tools.

package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/reporting/docxgen"
	"github.com/zaishield/vaultscan/backend/internal/reporting/xlsxgen"
)

// defaultXLSXRenderer emits a single-sheet workbook with one row
// per finding. The header row is bold; columns match the CSV
// exporter so consumers comparing the two formats see identical
// data.
type defaultXLSXRenderer struct{}

func (defaultXLSXRenderer) Name() string { return "xlsxgen-default" }

func (defaultXLSXRenderer) Render(_ context.Context, d *Dataset) ([]byte, error) {
	header := []string{
		"finding_id", "title", "severity", "cvss", "cve", "cwe",
		"scanner", "endpoint", "port", "status", "first_seen", "last_seen",
	}
	rows := make([][]xlsxgen.Cell, 0, len(d.Findings))
	for _, f := range d.Findings {
		rows = append(rows, []xlsxgen.Cell{
			xlsxgen.S(f.ID.String()),
			xlsxgen.S(f.Title),
			xlsxgen.S(f.Severity),
			xlsxgen.N(f.CVSSScore),
			xlsxgen.S(f.CVE),
			xlsxgen.S(f.CWE),
			xlsxgen.S(f.Scanner),
			xlsxgen.S(f.AffectedEndpoint),
			xlsxgen.N(float64(f.Port)),
			xlsxgen.S(f.Status),
			xlsxgen.S(formatTimeXLSX(f.FirstSeen)),
			xlsxgen.S(formatTimeXLSX(f.LastSeen)),
		})
	}
	// Default workbook UX: column widths so titles don't wrap to
	// one-char columns, conditional-format severities + statuses
	// for at-a-glance triage, and an autoFilter on the header row
	// so the reader can sort+filter in Excel without retyping the
	// data into a "Format as Table".
	return xlsxgen.Build([]xlsxgen.Sheet{{
		Name:   "Findings",
		Header: header,
		Rows:   rows,
		ColumnWidths: []float64{
			36, 60, 11, 8, 17, 10, 14, 32, 7, 12, 22, 22,
		},
		AutoFilter: true,
		ConditionalFormats: []xlsxgen.CondRule{
			// Severity column (col=2).
			{Col: 2, Match: "critical", Fill: "FF6B6B", Bold: true},
			{Col: 2, Match: "high", Fill: "FFA64D", Bold: true},
			{Col: 2, Match: "medium", Fill: "FFD56B"},
			{Col: 2, Match: "low", Fill: "BDE7BD"},
			{Col: 2, Match: "info", Fill: "D9D9D9"},
			// Status column (col=9).
			{Col: 9, Match: "open", Fill: "FFE5E5", Bold: true},
			{Col: 9, Match: "in_progress", Fill: "FFF1CC"},
			{Col: 9, Match: "resolved", Fill: "D6F5D6"},
			{Col: 9, Match: "closed", Fill: "D9D9D9"},
		},
	}})
}

func formatTimeXLSX(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// defaultDOCXRenderer emits a structured narrative document:
// title page (engagement + partner + generated date), severity
// summary, then one section per finding with its evidence summary.
// No images, no tables (cells require complex DrawingML); the
// goal is "readable Word doc that imports cleanly into ticketing
// systems and compliance binders", not a designer-grade report.
// For glossy output operators wire a real renderer.
type defaultDOCXRenderer struct{}

func (defaultDOCXRenderer) Name() string { return "docxgen-default" }

func (defaultDOCXRenderer) Render(_ context.Context, d *Dataset) ([]byte, error) {
	title := fmt.Sprintf("VaultScan %s Report", titleCase(d.ReportType))
	blocks := []docxgen.Block{
		docxgen.H2("Engagement"),
		docxgen.P(
			docxgen.TBold("Name: "), docxgen.T(d.Engagement.Name),
		),
		docxgen.P(
			docxgen.TBold("Tenant: "), docxgen.T(d.Tenant.Name),
		),
		docxgen.P(
			docxgen.TBold("Partner: "), docxgen.T(d.Partner.Name),
		),
		docxgen.P(
			docxgen.TBold("Generated: "), docxgen.T(d.GeneratedAt.UTC().Format(time.RFC1123)),
		),
		docxgen.H2("Severity summary"),
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := d.SeverityCounts[sev]; n > 0 {
			blocks = append(blocks, docxgen.P(
				docxgen.TBold(fmt.Sprintf("%s: ", titleCase(sev))),
				docxgen.T(fmt.Sprintf("%d", n)),
			))
		}
	}
	// Findings table first (the at-a-glance compliance summary),
	// then per-finding detail sections (the audit-grade context).
	// Two-phase layout matches the format compliance binders expect.
	blocks = append(blocks, docxgen.H2("Findings summary"))
	if len(d.Findings) > 0 {
		header := []string{"ID", "Severity", "CVSS", "Title", "Affected"}
		// Twentieths-of-a-point widths sum to ~14000 (~9.7 inches),
		// fitting a portrait page with default margins.
		widths := []int{2200, 1400, 1100, 5800, 3500}
		rows := make([][]string, 0, len(d.Findings))
		for _, f := range d.Findings {
			cvss := ""
			if f.CVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f", f.CVSSScore)
			}
			rows = append(rows, []string{
				shortID(f.ID.String()),
				titleCase(f.Severity),
				cvss,
				f.Title,
				f.AffectedEndpoint,
			})
		}
		blocks = append(blocks, docxgen.TblWithWidths(header, widths, rows))
	}
	blocks = append(blocks, docxgen.H2("Findings detail"))
	for _, f := range d.Findings {
		blocks = append(blocks,
			docxgen.H3(fmt.Sprintf("[%s] %s", titleCase(f.Severity), f.Title)),
			docxgen.P(
				docxgen.TBold("ID: "), docxgen.T(f.ID.String()),
			),
		)
		if f.CVE != "" {
			blocks = append(blocks, docxgen.P(
				docxgen.TBold("CVE: "), docxgen.T(f.CVE),
			))
		}
		if f.CVSSScore > 0 {
			blocks = append(blocks, docxgen.P(
				docxgen.TBold("CVSS: "), docxgen.T(fmt.Sprintf("%.1f", f.CVSSScore)),
			))
		}
		if f.AffectedEndpoint != "" {
			blocks = append(blocks, docxgen.P(
				docxgen.TBold("Affected: "), docxgen.T(f.AffectedEndpoint),
			))
		}
		if f.Description != "" {
			blocks = append(blocks,
				docxgen.P(docxgen.TBold("Description")),
				docxgen.P(docxgen.T(f.Description)),
			)
		}
		if f.EvidenceSummary != "" {
			blocks = append(blocks,
				docxgen.P(docxgen.TBold("Evidence")),
				docxgen.P(docxgen.T(f.EvidenceSummary)),
			)
		}
	}
	return docxgen.Build(title, blocks)
}

// shortID returns the first 8 chars of a UUID. UUIDs are 36 chars
// which is too wide for a summary-table cell; the short form is
// still locally unique within a single report.
func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// titleCase upper-cases the first rune of s; cheap stand-in for
// the deprecated strings.Title without dragging in golang.org/x/text.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}
