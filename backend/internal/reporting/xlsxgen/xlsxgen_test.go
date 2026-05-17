package xlsxgen

import (
	"archive/zip"
	"bytes"
	"io"
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
