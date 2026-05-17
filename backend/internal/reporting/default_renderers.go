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
	return xlsxgen.Build([]xlsxgen.Sheet{{
		Name:   "Findings",
		Header: header,
		Rows:   rows,
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
	blocks = append(blocks, docxgen.H2("Findings"))
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
