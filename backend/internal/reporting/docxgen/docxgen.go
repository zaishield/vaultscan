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

// Block is one document block — either a heading or a paragraph of
// inline runs.
type Block struct {
	Kind  BlockKind
	Text  string // used for Heading
	Runs  []Run  // used for Paragraph; if empty, no content
}

type BlockKind int

const (
	BlockParagraph BlockKind = iota
	BlockHeading1
	BlockHeading2
	BlockHeading3
)

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
