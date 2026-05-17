package xlsxgen

import (
	"archive/zip"
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"
)

// readPart returns the body of the named file inside the XLSX zip.
func readPart(t *testing.T, body []byte, name string) string {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	for _, f := range r.File {
		if f.Name == name {
			rc, _ := f.Open()
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return string(b)
		}
	}
	t.Fatalf("part %q not in zip; have: %v", name, fileNames(r.File))
	return ""
}

func fileNames(files []*zip.File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}
	return out
}

func TestBuild_ProducesValidStructure(t *testing.T) {
	t.Parallel()
	body, err := Build([]Sheet{{
		Name:   "Findings",
		Header: []string{"ID", "Severity", "Title", "CVSS"},
		Rows: [][]Cell{
			{S("F-1"), S("critical"), S("RCE in foo"), N(9.8)},
			{S("F-2"), S("high"), S("XSS in bar"), N(7.5)},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Required parts must all be present.
	for _, name := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"xl/workbook.xml",
		"xl/_rels/workbook.xml.rels",
		"xl/worksheets/sheet1.xml",
		"xl/styles.xml",
		"xl/sharedStrings.xml",
	} {
		readPart(t, body, name) // fails inside if missing
	}
	// Sheet1 should contain the rows. Both string-indexed (shared
	// strings) and numeric.
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	if !strings.Contains(sheet, `t="n"><v>9.8</v>`) {
		t.Errorf("numeric value 9.8 missing from sheet:\n%s", sheet)
	}
	if !strings.Contains(sheet, `t="s"`) {
		t.Errorf("shared-string-typed cell missing")
	}
	// Header row should reference style id 1 (bold).
	if !strings.Contains(sheet, `s="1"`) {
		t.Errorf("header row missing bold style: %s", sheet)
	}
}

func TestBuild_DeduplicatesStrings(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{{
		Header: []string{"sev"},
		Rows: [][]Cell{
			{S("high")}, {S("high")}, {S("high")}, {S("high")},
		},
	}})
	ss := readPart(t, body, "xl/sharedStrings.xml")
	// "high" appears once + the header "sev" once = 2 unique
	if !strings.Contains(ss, `uniqueCount="2"`) {
		t.Errorf("expected uniqueCount=2 (sev + high), got: %s", ss)
	}
}

func TestBuild_EscapesXMLSpecials(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{{
		Header: []string{"col"},
		Rows: [][]Cell{
			{S(`<script>&"'`)},
		},
	}})
	ss := readPart(t, body, "xl/sharedStrings.xml")
	if strings.Contains(ss, "<script>") {
		t.Errorf("raw <script> leaked into sharedStrings — escaping broken: %s", ss)
	}
	if !strings.Contains(ss, "&lt;script&gt;") {
		t.Errorf("expected escaped <script> in: %s", ss)
	}
}

func TestColLetter(t *testing.T) {
	t.Parallel()
	cases := map[int]string{0: "A", 1: "B", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"}
	for n, want := range cases {
		if got := colLetter(n); got != want {
			t.Errorf("colLetter(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestBuild_HandlesEmptyInput(t *testing.T) {
	t.Parallel()
	body, err := Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Should still be a valid zip with all the structural parts.
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
		t.Errorf("empty Build did not produce a valid zip: %v", err)
	}
}

func TestBuild_ConditionalFormatPaintsCells(t *testing.T) {
	t.Parallel()
	body, err := Build([]Sheet{{
		Header: []string{"id", "severity"},
		Rows: [][]Cell{
			{S("F-1"), S("critical")},
			{S("F-2"), S("low")},
			{S("F-3"), S("info")}, // no rule for "info" — should get default
		},
		ConditionalFormats: []CondRule{
			{Col: 1, Match: "critical", Fill: "FF6B6B", Bold: true},
			{Col: 1, Match: "low", Fill: "BDE7BD"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	// "critical" cell should reference a non-default style ID
	// (s="N" with N > 1, since 0=default + 1=header).
	if !strings.Contains(sheet, `s="2"`) && !strings.Contains(sheet, `s="3"`) {
		t.Errorf("expected styled cell for critical/low, got: %s", sheet)
	}
	styles := readPart(t, body, "xl/styles.xml")
	// Both fills should appear in the styles table.
	if !strings.Contains(styles, "FF6B6B") {
		t.Errorf("critical fill color not in styles: %s", styles)
	}
	if !strings.Contains(styles, "BDE7BD") {
		t.Errorf("low fill color not in styles: %s", styles)
	}
}

func TestBuild_ConditionalFormatCaseInsensitive(t *testing.T) {
	t.Parallel()
	// Rule matches "critical" but the cell value is "CRITICAL".
	body, _ := Build([]Sheet{{
		Header: []string{"sev"},
		Rows:   [][]Cell{{S("CRITICAL")}},
		ConditionalFormats: []CondRule{
			{Col: 0, Match: "critical", Fill: "FF6B6B"},
		},
	}})
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	// Data row should carry a styled cell (s="N" with N >= 2).
	// Header is s="1", default is s="0" — anything else means the
	// rule matched.
	if !regexpMatchesStyle(sheet) {
		t.Errorf("expected styled cell for case-insensitive match, got: %s", sheet)
	}
}

func regexpMatchesStyle(sheet string) bool {
	// Look for any s="N" with N >= 2 (rule styles start at 2).
	for n := 2; n < 20; n++ {
		if strings.Contains(sheet, `s="`+strconv.Itoa(n)+`"`) {
			return true
		}
	}
	return false
}

func TestBuild_ColumnWidthsEmitted(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{{
		Header:       []string{"a", "b"},
		Rows:         [][]Cell{{S("x"), S("y")}},
		ColumnWidths: []float64{20, 40.5},
	}})
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	if !strings.Contains(sheet, `<cols>`) {
		t.Errorf("<cols> block missing: %s", sheet)
	}
	if !strings.Contains(sheet, `width="20"`) || !strings.Contains(sheet, `width="40.5"`) {
		t.Errorf("column widths not preserved: %s", sheet)
	}
}

func TestBuild_AutoFilterEmitted(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{{
		Header:     []string{"id", "sev", "title"},
		Rows:       [][]Cell{{S("1"), S("high"), S("foo")}, {S("2"), S("low"), S("bar")}},
		AutoFilter: true,
	}})
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	if !strings.Contains(sheet, `<autoFilter ref="A1:C3"`) {
		t.Errorf("autoFilter range A1:C3 not emitted: %s", sheet)
	}
}

func TestBuild_AutoFilterPositionedAfterSheetData(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{{
		Header:     []string{"x"},
		Rows:       [][]Cell{{S("v")}},
		AutoFilter: true,
	}})
	sheet := readPart(t, body, "xl/worksheets/sheet1.xml")
	idxData := strings.Index(sheet, "</sheetData>")
	idxFilter := strings.Index(sheet, "<autoFilter")
	if idxData < 0 || idxFilter < 0 || idxFilter < idxData {
		t.Errorf("autoFilter must come AFTER </sheetData> per OOXML schema: %s", sheet)
	}
}

func TestBuild_MultipleSheets(t *testing.T) {
	t.Parallel()
	body, _ := Build([]Sheet{
		{Name: "Findings", Header: []string{"id"}, Rows: [][]Cell{{S("F-1")}}},
		{Name: "Assets", Header: []string{"host"}, Rows: [][]Cell{{S("foo.com")}}},
	})
	wb := readPart(t, body, "xl/workbook.xml")
	if !strings.Contains(wb, `name="Findings"`) || !strings.Contains(wb, `name="Assets"`) {
		t.Errorf("workbook missing both sheet names: %s", wb)
	}
	// Both sheets emitted.
	readPart(t, body, "xl/worksheets/sheet1.xml")
	readPart(t, body, "xl/worksheets/sheet2.xml")
}
