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
	"strings"
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

// Sheet is a single worksheet with optional name, header row, data
// rows, and optional column widths / conditional-formatting rules /
// auto-filter. Header row gets bold styling.
type Sheet struct {
	Name   string
	Header []string
	Rows   [][]Cell
	// ColumnWidths is optional. Values are Excel "character widths"
	// (the same unit Format Columns / Width dialog reports). Empty
	// slice or nil → Excel auto-sizes.
	ColumnWidths []float64
	// AutoFilter, when true, adds a filter dropdown across the
	// header row. Lets readers sort + filter the table in Excel.
	AutoFilter bool
	// ConditionalFormats is an ordered list of severity-style rules
	// applied AFTER the cell is written. The rule's column index
	// must be 0-based into the row. Rule order matters — first
	// match wins.
	ConditionalFormats []CondRule
}

// CondRule is a "if cell in COL matches VALUE, paint it COLOR" rule.
// Excel supports CEL-style formulas but we keep this narrow: exact
// case-insensitive string match. Sufficient for severity columns
// ("critical" → red, "high" → orange, etc.) — the most common case.
type CondRule struct {
	Col   int    // 0-based column index
	Match string // case-insensitive exact match against the cell string
	Fill  string // 6-char hex RGB, no leading # (e.g. "FF6B6B")
	Bold  bool   // bold the cell as well
	// styleID is populated by Build() — internal; do not set.
	styleID int
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

	// Build the style table. Each distinct (fill, bold) combination
	// across all conditional-format rules becomes one cellXf entry;
	// the worksheet writer looks up the right s="N" attribute via
	// rule.styleID.
	st := newStyles()
	for si := range sheets {
		// Validate every rule's column is in-range against the
		// sheet's known width (length of Header, or max row width
		// if Header is empty). An out-of-range rule is a silent
		// no-op which is fine at runtime but masks operator typos.
		maxCol := len(sheets[si].Header) - 1
		if maxCol < 0 {
			for _, row := range sheets[si].Rows {
				if len(row)-1 > maxCol {
					maxCol = len(row) - 1
				}
			}
		}
		for ri := range sheets[si].ConditionalFormats {
			rule := &sheets[si].ConditionalFormats[ri]
			if rule.Col < 0 || rule.Col > maxCol {
				return nil, fmt.Errorf(
					"xlsxgen: sheet %q ConditionalFormat rule[%d].Col=%d out of range [0..%d]",
					sheets[si].Name, ri, rule.Col, maxCol)
			}
			rule.styleID = st.addRule(rule.Fill, rule.Bold)
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
	if err := writeFile("xl/styles.xml", st.xml()); err != nil {
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

// styleID is the index into cellXfs; assigned by Build before any
// worksheet is written so sheetXML can reference it via s="N".
// Stored unexported so callers can't set it directly.
//
//nolint:unused // referenced via field name on CondRule above
type _unusedCondRuleField int

// styles accumulates fonts/fills/cellXfs across the workbook so the
// styles.xml emitted at the top of the zip is the source of truth.
type styles struct {
	// fontIDs: 0 = normal, 1 = bold (header). Conditional-format
	// rules with Bold=true reuse fontID 1.
	// fills: 0 = none (default), 1 = "gray125" (Excel reserves this),
	// then one entry per unique conditional-format fill.
	fills []string
	// xfs: 0 = default (no fill, fontID 0), 1 = header (fontID 1),
	// then one per (fillIdx, bold) tuple.
	xfs []xfEntry
}

type xfEntry struct {
	fontID, fillID int
}

func newStyles() *styles {
	return &styles{
		fills: []string{"none", "gray125"}, // Excel quirk: gray125 must be index 1
		xfs: []xfEntry{
			{0, 0}, // default
			{1, 0}, // bold header
		},
	}
}

// addRule registers a (fill, bold) pair and returns the resulting
// cellXfs index. Duplicate calls with the same args dedupe.
func (s *styles) addRule(fillHex string, bold bool) int {
	// Normalise fill: empty → default fill 0.
	if fillHex == "" {
		// No fill, optionally bold. Still need a distinct xf.
		fid := 0 // default font
		if bold {
			fid = 1
		}
		return s.findOrAddXf(xfEntry{fontID: fid, fillID: 0})
	}
	// Find or add the fill.
	fillIdx := -1
	for i, f := range s.fills {
		if f == fillHex {
			fillIdx = i
			break
		}
	}
	if fillIdx < 0 {
		s.fills = append(s.fills, fillHex)
		fillIdx = len(s.fills) - 1
	}
	fid := 0
	if bold {
		fid = 1
	}
	return s.findOrAddXf(xfEntry{fontID: fid, fillID: fillIdx})
}

func (s *styles) findOrAddXf(e xfEntry) int {
	for i, x := range s.xfs {
		if x == e {
			return i
		}
	}
	s.xfs = append(s.xfs, e)
	return len(s.xfs) - 1
}

func (s *styles) xml() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	// Two fonts: regular + bold (header / rule-bold).
	b.WriteString(`<fonts count="2">`)
	b.WriteString(`<font><sz val="11"/><name val="Calibri"/></font>`)
	b.WriteString(`<font><b/><sz val="11"/><name val="Calibri"/></font>`)
	b.WriteString(`</fonts>`)
	// Fills: none, gray125, then each conditional-format fill as a
	// solid pattern.
	fmt.Fprintf(&b, `<fills count="%d">`, len(s.fills))
	b.WriteString(`<fill><patternFill patternType="none"/></fill>`)
	b.WriteString(`<fill><patternFill patternType="gray125"/></fill>`)
	for _, f := range s.fills[2:] {
		fmt.Fprintf(&b, `<fill><patternFill patternType="solid"><fgColor rgb="FF%s"/></patternFill></fill>`, f)
	}
	b.WriteString(`</fills>`)
	b.WriteString(`<borders count="1"><border/></borders>`)
	b.WriteString(`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>`)
	fmt.Fprintf(&b, `<cellXfs count="%d">`, len(s.xfs))
	for _, x := range s.xfs {
		applyFont := ""
		if x.fontID != 0 {
			applyFont = ` applyFont="1"`
		}
		applyFill := ""
		if x.fillID != 0 {
			applyFill = ` applyFill="1"`
		}
		fmt.Fprintf(&b, `<xf numFmtId="0" fontId="%d" fillId="%d" borderId="0" xfId="0"%s%s/>`,
			x.fontID, x.fillID, applyFont, applyFill)
	}
	b.WriteString(`</cellXfs>`)
	b.WriteString(`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>`)
	b.WriteString(`</styleSheet>`)
	return b.String()
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

func sheetXML(s Sheet, pool *stringPool) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	// <cols> must come before <sheetData> per the OOXML schema.
	if len(s.ColumnWidths) > 0 {
		b.WriteString(`<cols>`)
		for i, w := range s.ColumnWidths {
			if w <= 0 {
				continue
			}
			fmt.Fprintf(&b, `<col min="%d" max="%d" width="%s" customWidth="1"/>`,
				i+1, i+1, strconv.FormatFloat(w, 'f', -1, 64))
		}
		b.WriteString(`</cols>`)
	}
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
			styleAttr := ""
			// Apply matching conditional-format rule. First match wins.
			if !c.IsNum {
				for _, rule := range s.ConditionalFormats {
					if rule.Col == col && strings.EqualFold(rule.Match, c.String) {
						styleAttr = fmt.Sprintf(` s="%d"`, rule.styleID)
						break
					}
				}
			}
			if c.IsNum {
				fmt.Fprintf(&b, `<c r="%s%d" t="n"%s><v>%s</v></c>`,
					colLetter(col), rowNum, styleAttr,
					strconv.FormatFloat(c.Number, 'f', -1, 64))
			} else {
				fmt.Fprintf(&b, `<c r="%s%d" t="s"%s><v>%d</v></c>`,
					colLetter(col), rowNum, styleAttr, pool.intern(c.String))
			}
		}
		b.WriteString(`</row>`)
		rowNum++
	}
	b.WriteString(`</sheetData>`)
	// autoFilter is OUTSIDE sheetData. Ref spans the header row
	// across all defined columns. Excel needs the inclusive A1:Xn
	// notation. If there's a header AND data, the filter ranges
	// the entire used area so the dropdown applies sort-as-table.
	if s.AutoFilter && len(s.Header) > 0 {
		lastCol := colLetter(len(s.Header) - 1)
		lastRow := 1
		if len(s.Rows) > 0 {
			lastRow = len(s.Rows) + 1
		}
		fmt.Fprintf(&b, `<autoFilter ref="A1:%s%d"/>`, lastCol, lastRow)
	}
	b.WriteString(`</worksheet>`)
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
