// Package xlsxgen builds minimal but valid XLSX (Office Open XML
// SpreadsheetML) files from a flat row-of-cells representation.
//
// XLSX is a zip of strict-schema XML parts. This generator emits the
// minimum set Office / LibreOffice / Numbers actually require to open
// the file as a real spreadsheet:
//
//   [Content_Types].xml      — MIME types for the parts
//   _rels/.rels              — top-level relationship pointing at workbook
//   xl/workbook.xml          — workbook + sheet list
//   xl/_rels/workbook.xml.rels — sheet relationship
//   xl/worksheets/sheet1.xml — actual cells
//   xl/sharedStrings.xml     — pooled strings (one entry per unique string)
//   xl/styles.xml            — bare-minimum styles (header bold)
//
// Numbers are emitted as raw <c t="n"><v>NN</v></c>; everything else
// is shared-strings indexed and emitted as <c t="s"><v>idx</v></c>.
// Header row is styled bold via a single styles.xml cellXf entry.
//
// This is deliberately small — under 400 LOC, no deps beyond stdlib —
// because the alternative (excelize / unioffice) drags in 200+ packages
// for what is fundamentally a tabular dump of findings.
package xlsxgen

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Cell is one cell's content. Numeric values use Number; everything
// else uses String. A nil-zero value falls back to empty string.
type Cell struct {
	String string
	Number float64
	IsNum  bool
}

// S returns a string cell.
func S(s string) Cell { return Cell{String: s} }

// N returns a numeric cell.
func N(n float64) Cell { return Cell{Number: n, IsNum: true} }

// Sheet is a single worksheet with optional name, header row, and
// data rows. Header row gets bold styling.
type Sheet struct {
	Name   string
	Header []string
	Rows   [][]Cell
}

// Build returns the XLSX bytes for the given sheets. Sheets are
// emitted in slice order. An empty sheets slice produces a single
// empty Sheet1.
func Build(sheets []Sheet) ([]byte, error) {
	if len(sheets) == 0 {
		sheets = []Sheet{{Name: "Sheet1"}}
	}
	// Shared-strings pool. Strings are deduplicated to keep the
	// generated file small for repeated values like "high",
	// "open", scanner names.
	pool := newStringPool()
	for _, s := range sheets {
		for _, h := range s.Header {
			pool.intern(h)
		}
		for _, row := range s.Rows {
			for _, c := range row {
				if !c.IsNum {
					pool.intern(c.String)
				}
			}
		}
	}

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

	if err := writeFile("[Content_Types].xml", contentTypes(len(sheets))); err != nil {
		return nil, err
	}
	if err := writeFile("_rels/.rels", topRels); err != nil {
		return nil, err
	}
	if err := writeFile("xl/workbook.xml", workbookXML(sheets)); err != nil {
		return nil, err
	}
	if err := writeFile("xl/_rels/workbook.xml.rels", workbookRels(len(sheets))); err != nil {
		return nil, err
	}
	if err := writeFile("xl/styles.xml", stylesXML); err != nil {
		return nil, err
	}
	if err := writeFile("xl/sharedStrings.xml", pool.xml()); err != nil {
		return nil, err
	}
	for i, s := range sheets {
		if err := writeFile(fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1),
			sheetXML(s, pool)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// stringPool deduplicates strings and assigns each a stable index.
type stringPool struct {
	idx map[string]int
}

func newStringPool() *stringPool { return &stringPool{idx: map[string]int{}} }

func (p *stringPool) intern(s string) int {
	if v, ok := p.idx[s]; ok {
		return v
	}
	v := len(p.idx)
	p.idx[s] = v
	return v
}

func (p *stringPool) xml() string {
	// Materialise in stable order so byte-identical builds produce
	// byte-identical pools (helps test determinism).
	type kv struct {
		s   string
		idx int
	}
	all := make([]kv, 0, len(p.idx))
	for s, i := range p.idx {
		all = append(all, kv{s, i})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].idx < all[j].idx })

	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	fmt.Fprintf(&b, `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" uniqueCount="%d">`,
		len(all), len(all))
	for _, k := range all {
		b.WriteString(`<si><t xml:space="preserve">`)
		xml.EscapeText(&b, []byte(k.s))
		b.WriteString(`</t></si>`)
	}
	b.WriteString(`</sst>`)
	return b.String()
}

func contentTypes(numSheets int) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`)
	b.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	b.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	b.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	for i := 1; i <= numSheets; i++ {
		fmt.Fprintf(&b, `<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i)
	}
	b.WriteString(`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	b.WriteString(`<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>`)
	b.WriteString(`</Types>`)
	return b.String()
}

const topRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

func workbookXML(sheets []Sheet) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`)
	b.WriteString(`<sheets>`)
	for i, s := range sheets {
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("Sheet%d", i+1)
		}
		fmt.Fprintf(&b, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`,
			xmlAttrEscape(name), i+1, i+1)
	}
	b.WriteString(`</sheets></workbook>`)
	return b.String()
}

func workbookRels(numSheets int) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := 1; i <= numSheets; i++ {
		fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`,
			i, i)
	}
	// Styles + sharedStrings get the next rIds.
	fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`,
		numSheets+1)
	fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>`,
		numSheets+2)
	b.WriteString(`</Relationships>`)
	return b.String()
}

// stylesXML defines two cell formats:
//   0 — default
//   1 — bold (used for header row)
const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
	`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>` +
	`<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
	`<fills count="1"><fill><patternFill patternType="none"/></fill></fills>` +
	`<borders count="1"><border/></borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="2">` +
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +
	`</cellXfs>` +
	`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>` +
	`</styleSheet>`

func sheetXML(s Sheet, pool *stringPool) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	b.WriteString(`<sheetData>`)
	rowNum := 1
	if len(s.Header) > 0 {
		fmt.Fprintf(&b, `<row r="%d">`, rowNum)
		for col, h := range s.Header {
			fmt.Fprintf(&b, `<c r="%s%d" s="1" t="s"><v>%d</v></c>`,
				colLetter(col), rowNum, pool.intern(h))
		}
		b.WriteString(`</row>`)
		rowNum++
	}
	for _, row := range s.Rows {
		fmt.Fprintf(&b, `<row r="%d">`, rowNum)
		for col, c := range row {
			if c.IsNum {
				fmt.Fprintf(&b, `<c r="%s%d" t="n"><v>%s</v></c>`,
					colLetter(col), rowNum, strconv.FormatFloat(c.Number, 'f', -1, 64))
			} else {
				fmt.Fprintf(&b, `<c r="%s%d" t="s"><v>%d</v></c>`,
					colLetter(col), rowNum, pool.intern(c.String))
			}
		}
		b.WriteString(`</row>`)
		rowNum++
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

// colLetter converts a 0-indexed column number to its Excel letter
// (0=A, 25=Z, 26=AA, etc).
func colLetter(n int) string {
	var b []byte
	for n >= 0 {
		b = append([]byte{byte('A' + n%26)}, b...)
		n = n/26 - 1
	}
	return string(b)
}

func xmlAttrEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// FormatTime produces an XLSX-friendly string for a time.Time
// (ISO 8601 in UTC). We emit it as a regular shared string rather
// than wrestling with Excel serial-date numerics — the output is
// readable and consistent across locales.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
