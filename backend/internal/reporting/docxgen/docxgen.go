// Package docxgen builds minimal but valid DOCX (Office Open XML
// WordprocessingML) files from a flat block-list representation.
//
// DOCX is a zip of strict-schema XML parts. We emit the minimum set
// Word / LibreOffice Writer / Pages require to open as a real doc:
//
//   [Content_Types].xml      — MIME types for the parts
//   _rels/.rels              — top-level rel pointing at document
//   word/document.xml        — the body (paragraphs + headings)
//   word/_rels/document.xml.rels — empty rels for the document
//
// Block model: callers pass a flat slice of Blocks; each Block is
// either a heading (Level 1-3) or a body paragraph. Bold / italic
// runs within a paragraph are supported via inline runs.
//
// This is deliberately small — well under 400 LOC, no deps beyond
// stdlib — for the same reason xlsxgen exists: the alternative
// (unioffice, godocx) is hundreds of packages for what is
// fundamentally a structured text dump.
package docxgen

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
)

// Block is one document block. Most callers stick to Heading or
// Paragraph; Table is for tabular content that Word renders as a
// real native table (not a fake monospace grid in a paragraph).
type Block struct {
	Kind  BlockKind
	Text  string // used for Heading
	Runs  []Run  // used for Paragraph; if empty, no content
	Table *Table // used for Table
}

type BlockKind int

const (
	BlockParagraph BlockKind = iota
	BlockHeading1
	BlockHeading2
	BlockHeading3
	BlockTable
)

// Table is a simple m×n grid of cell text. The first row is rendered
// bold (table header convention). Cells with newlines render as
// soft line breaks within the cell.
type Table struct {
	Header []string
	Rows   [][]string
	// ColumnWidths is optional. Values are twentieths-of-a-point
	// (Word's unit, 1/1440 of an inch); len(ColumnWidths) must
	// match len(Header) when non-nil. Set to nil to let Word
	// auto-size.
	ColumnWidths []int
}

// Tbl is a concise constructor.
func Tbl(header []string, rows [][]string) Block {
	return Block{Kind: BlockTable, Table: &Table{Header: header, Rows: rows}}
}

// TblWithWidths constructs a Table with explicit column widths in
// twentieths-of-a-point. Useful for compliance reports that need
// stable column sizing across renders.
func TblWithWidths(header []string, widths []int, rows [][]string) Block {
	return Block{Kind: BlockTable, Table: &Table{
		Header: header, Rows: rows, ColumnWidths: widths,
	}}
}

// Run is one styled span within a paragraph. Use Heading() / Para()
// helpers for the common case; reach for Run for mixed-style lines.
type Run struct {
	Text   string
	Bold   bool
	Italic bool
}

// H1 / H2 / H3 / P are concise constructors.
func H1(s string) Block { return Block{Kind: BlockHeading1, Text: s} }
func H2(s string) Block { return Block{Kind: BlockHeading2, Text: s} }
func H3(s string) Block { return Block{Kind: BlockHeading3, Text: s} }
func P(runs ...Run) Block {
	return Block{Kind: BlockParagraph, Runs: runs}
}
func T(s string) Run           { return Run{Text: s} }
func TBold(s string) Run       { return Run{Text: s, Bold: true} }
func TItalic(s string) Run     { return Run{Text: s, Italic: true} }
func TBoldIt(s string) Run     { return Run{Text: s, Bold: true, Italic: true} }

// Build returns the DOCX bytes for the given blocks.
func Build(title string, blocks []Block) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	writeFile := func(name, body string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write([]byte(body))
		return err
	}

	if err := writeFile("[Content_Types].xml", contentTypes); err != nil {
		return nil, err
	}
	if err := writeFile("_rels/.rels", topRels); err != nil {
		return nil, err
	}
	if err := writeFile("word/_rels/document.xml.rels", emptyDocRels); err != nil {
		return nil, err
	}
	if err := writeFile("word/styles.xml", stylesXML); err != nil {
		return nil, err
	}
	if err := writeFile("word/document.xml", documentXML(title, blocks)); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`</Types>`

const topRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

const emptyDocRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`</Relationships>`

// stylesXML defines four named styles: Normal (default) and
// Heading1/2/3 (progressively smaller bold). Word/Writer use the
// w:styleId to bind these to <w:pStyle>.
const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>` +
	`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="200" w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>` +
	`</w:styles>`

func documentXML(title string, blocks []Block) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	if title != "" {
		writeHeading(&b, "Heading1", title)
	}
	for _, blk := range blocks {
		switch blk.Kind {
		case BlockHeading1:
			writeHeading(&b, "Heading1", blk.Text)
		case BlockHeading2:
			writeHeading(&b, "Heading2", blk.Text)
		case BlockHeading3:
			writeHeading(&b, "Heading3", blk.Text)
		case BlockParagraph:
			writeParagraph(&b, blk.Runs)
		case BlockTable:
			if blk.Table != nil {
				writeTable(&b, blk.Table)
			}
		}
	}
	// sectPr is required for Word to consider the body valid.
	b.WriteString(`<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>`)
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

func writeHeading(b *bytes.Buffer, styleID, text string) {
	fmt.Fprintf(b, `<w:p><w:pPr><w:pStyle w:val="%s"/></w:pPr><w:r><w:t xml:space="preserve">`,
		styleID)
	xml.EscapeText(b, []byte(text))
	b.WriteString(`</w:t></w:r></w:p>`)
}

// writeTable emits a <w:tbl> element with a header row in bold,
// optional explicit column widths, and a 1pt border on every side
// + cell. Word and LibreOffice both render this as a real table.
func writeTable(b *bytes.Buffer, t *Table) {
	b.WriteString(`<w:tbl>`)
	// Table properties: full-width, borders.
	b.WriteString(`<w:tblPr>`)
	b.WriteString(`<w:tblW w:type="auto" w:w="0"/>`)
	b.WriteString(`<w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		fmt.Fprintf(b, `<w:%s w:val="single" w:sz="4" w:color="888888"/>`, side)
	}
	b.WriteString(`</w:tblBorders></w:tblPr>`)
	// Column-grid: required for Word to size columns when explicit
	// widths are supplied (otherwise it auto-sizes).
	if len(t.ColumnWidths) == len(t.Header) {
		b.WriteString(`<w:tblGrid>`)
		for _, w := range t.ColumnWidths {
			fmt.Fprintf(b, `<w:gridCol w:w="%d"/>`, w)
		}
		b.WriteString(`</w:tblGrid>`)
	}
	// Header row — bold.
	if len(t.Header) > 0 {
		b.WriteString(`<w:tr>`)
		for i, cellText := range t.Header {
			width := 0
			if len(t.ColumnWidths) == len(t.Header) {
				width = t.ColumnWidths[i]
			}
			writeTableCell(b, cellText, true, width)
		}
		b.WriteString(`</w:tr>`)
	}
	for _, row := range t.Rows {
		b.WriteString(`<w:tr>`)
		for i, cellText := range row {
			width := 0
			if len(t.ColumnWidths) == len(t.Header) && i < len(t.ColumnWidths) {
				width = t.ColumnWidths[i]
			}
			writeTableCell(b, cellText, false, width)
		}
		b.WriteString(`</w:tr>`)
	}
	b.WriteString(`</w:tbl>`)
	// Word treats a table as a single block. Append an empty
	// paragraph after so the next content has spacing room and the
	// document body is well-formed for the spec parser.
	b.WriteString(`<w:p/>`)
}

// writeTableCell emits a single <w:tc>. text may contain newlines;
// they're rendered as soft breaks (<w:br/>) inside one paragraph.
func writeTableCell(b *bytes.Buffer, text string, bold bool, width int) {
	b.WriteString(`<w:tc>`)
	if width > 0 {
		fmt.Fprintf(b, `<w:tcPr><w:tcW w:type="dxa" w:w="%d"/></w:tcPr>`, width)
	}
	b.WriteString(`<w:p>`)
	parts := splitLines(text)
	for i, line := range parts {
		if i > 0 {
			b.WriteString(`<w:r><w:br/></w:r>`)
		}
		b.WriteString(`<w:r>`)
		if bold {
			b.WriteString(`<w:rPr><w:b/></w:rPr>`)
		}
		b.WriteString(`<w:t xml:space="preserve">`)
		xml.EscapeText(b, []byte(line))
		b.WriteString(`</w:t></w:r>`)
	}
	b.WriteString(`</w:p></w:tc>`)
}

// splitLines is a strings.Split shim that doesn't require the
// `strings` import (kept the import set minimal so this file is
// self-contained).
func splitLines(s string) []string {
	out := []string{}
	cur := []byte{}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, string(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, s[i])
	}
	out = append(out, string(cur))
	return out
}

func writeParagraph(b *bytes.Buffer, runs []Run) {
	b.WriteString(`<w:p>`)
	for _, r := range runs {
		b.WriteString(`<w:r>`)
		if r.Bold || r.Italic {
			b.WriteString(`<w:rPr>`)
			if r.Bold {
				b.WriteString(`<w:b/>`)
			}
			if r.Italic {
				b.WriteString(`<w:i/>`)
			}
			b.WriteString(`</w:rPr>`)
		}
		b.WriteString(`<w:t xml:space="preserve">`)
		xml.EscapeText(b, []byte(r.Text))
		b.WriteString(`</w:t></w:r>`)
	}
	b.WriteString(`</w:p>`)
}
