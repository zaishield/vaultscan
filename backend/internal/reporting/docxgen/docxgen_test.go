package docxgen

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

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
	t.Fatalf("part %q not in zip", name)
	return ""
}

func TestBuild_ProducesValidStructure(t *testing.T) {
	t.Parallel()
	body, err := Build("VaultScan Report", []Block{
		H2("Summary"),
		P(T("This engagement found "), TBold("3 critical"), T(" findings.")),
		H2("Details"),
		P(TItalic("See appendix for full output.")),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"word/document.xml",
		"word/_rels/document.xml.rels",
		"word/styles.xml",
	} {
		readPart(t, body, name)
	}
	doc := readPart(t, body, "word/document.xml")
	if !strings.Contains(doc, `<w:t xml:space="preserve">VaultScan Report</w:t>`) {
		t.Errorf("title not in body: %s", doc)
	}
	if !strings.Contains(doc, `<w:pStyle w:val="Heading2"/>`) {
		t.Errorf("Heading2 pStyle missing: %s", doc)
	}
	if !strings.Contains(doc, `<w:b/>`) {
		t.Errorf("bold run not encoded: %s", doc)
	}
	if !strings.Contains(doc, `<w:i/>`) {
		t.Errorf("italic run not encoded: %s", doc)
	}
}

func TestBuild_EscapesXMLSpecials(t *testing.T) {
	t.Parallel()
	body, _ := Build("", []Block{P(T(`<script>alert("xss")</script>`))})
	doc := readPart(t, body, "word/document.xml")
	if strings.Contains(doc, "<script>") {
		t.Errorf("raw <script> leaked into document.xml: %s", doc)
	}
	if !strings.Contains(doc, "&lt;script&gt;") {
		t.Errorf("expected escaped <script> in: %s", doc)
	}
}

func TestBuild_NoBlocksStillValid(t *testing.T) {
	t.Parallel()
	body, err := Build("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
		t.Errorf("empty Build did not produce a valid zip: %v", err)
	}
}

func TestBuild_TableRendersAsRealOOXML(t *testing.T) {
	t.Parallel()
	body, err := Build("", []Block{
		Tbl(
			[]string{"id", "severity", "title"},
			[][]string{
				{"F-1", "critical", "RCE in foo"},
				{"F-2", "high", "XSS in bar"},
			},
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := readPart(t, body, "word/document.xml")
	// Real <w:tbl> element (not a fake monospace paragraph).
	if !strings.Contains(doc, `<w:tbl>`) {
		t.Errorf("table not rendered as <w:tbl>: %s", doc)
	}
	// Header cell should be bold.
	// Find the first <w:tc> ... first run ... <w:b/>.
	tblStart := strings.Index(doc, "<w:tbl>")
	tblEnd := strings.Index(doc, "</w:tbl>")
	if tblStart < 0 || tblEnd < 0 {
		t.Fatal("table tags missing")
	}
	tblBody := doc[tblStart:tblEnd]
	if !strings.Contains(tblBody, "<w:b/>") {
		t.Errorf("header row not bold: %s", tblBody)
	}
	// Both data rows should appear with their content.
	if !strings.Contains(tblBody, "RCE in foo") || !strings.Contains(tblBody, "XSS in bar") {
		t.Errorf("data rows missing from table body")
	}
}

func TestBuild_TableWithExplicitWidths(t *testing.T) {
	t.Parallel()
	body, _ := Build("", []Block{
		TblWithWidths(
			[]string{"a", "b"},
			[]int{1440, 2880},
			[][]string{{"x", "y"}},
		),
	})
	doc := readPart(t, body, "word/document.xml")
	if !strings.Contains(doc, `<w:gridCol w:w="1440"/>`) ||
		!strings.Contains(doc, `<w:gridCol w:w="2880"/>`) {
		t.Errorf("explicit column widths not emitted: %s", doc)
	}
	if !strings.Contains(doc, `w:type="dxa" w:w="1440"`) {
		t.Errorf("per-cell width not emitted: %s", doc)
	}
}

func TestBuild_TableCellWithNewlinesUsesSoftBreaks(t *testing.T) {
	t.Parallel()
	body, _ := Build("", []Block{
		Tbl(
			[]string{"col"},
			[][]string{{"line1\nline2"}},
		),
	})
	doc := readPart(t, body, "word/document.xml")
	if !strings.Contains(doc, `<w:br/>`) {
		t.Errorf("expected <w:br/> for newline inside table cell: %s", doc)
	}
}

func TestBuild_TableEscapesXMLSpecials(t *testing.T) {
	t.Parallel()
	body, _ := Build("", []Block{
		Tbl(
			[]string{"col"},
			[][]string{{`<script>`}},
		),
	})
	doc := readPart(t, body, "word/document.xml")
	if strings.Contains(doc, "<script>") {
		t.Errorf("raw <script> leaked into table cell: %s", doc)
	}
	if !strings.Contains(doc, "&lt;script&gt;") {
		t.Errorf("expected escaped <script>: %s", doc)
	}
}
