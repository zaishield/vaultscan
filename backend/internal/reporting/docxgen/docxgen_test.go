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
