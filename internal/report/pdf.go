package report

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"codeberg.org/go-pdf/fpdf"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
)

const (
	pdfPageW     = 210.0
	pdfPageH     = 297.0
	pdfMargin    = 15.0
	pdfFooterH   = 8.0
	pdfWrapSlack = 0.5
	pdfFamily    = "go"
	mmPerPt      = 25.4 / 72
)

type pdfStyle struct {
	bold  bool
	size  float64
	color [3]int
}

var (
	pdfFG    = [3]int{0x1b, 0x1f, 0x24}
	pdfMuted = [3]int{0x57, 0x60, 0x6a}

	stTitle   = pdfStyle{bold: true, size: 16, color: pdfFG}
	stH2      = pdfStyle{bold: true, size: 13, color: pdfFG}
	stH3      = pdfStyle{bold: true, size: 11, color: pdfFG}
	stH4      = pdfStyle{bold: true, size: 8.5, color: pdfMuted}
	stBody    = pdfStyle{size: 10, color: pdfFG}
	stSmall   = pdfStyle{size: 9, color: pdfFG}
	stSmallB  = pdfStyle{bold: true, size: 9, color: pdfFG}
	stMuted   = pdfStyle{size: 9, color: pdfMuted}
	stLabel   = pdfStyle{size: 8.5, color: pdfMuted}
	stValue   = pdfStyle{size: 8.5, color: pdfFG}
	stFooter  = pdfStyle{size: 8, color: pdfMuted}
	stFinding = pdfStyle{size: 9.5, color: pdfFG}
)

func verdictRGB(v string) [3]int {
	switch v {
	case VerdictFail:
		return [3]int{0xb4, 0x23, 0x18}
	case VerdictWarn:
		return [3]int{0x9a, 0x67, 0x00}
	case VerdictPass:
		return [3]int{0x1a, 0x7f, 0x37}
	case VerdictInfo:
		return [3]int{0x0b, 0x5c, 0xad}
	case VerdictUnknown:
		return [3]int{0x66, 0x39, 0xba}
	}
	return [3]int{0x6e, 0x77, 0x81}
}

func verdictStyle(v string, size float64) pdfStyle {
	return pdfStyle{bold: true, size: size, color: verdictRGB(v)}
}

type pdfFonts struct {
	reg, bold *sfnt.Font
	asc, desc float64
}

var loadPDFFonts = sync.OnceValues(func() (*pdfFonts, error) {
	reg, err := sfnt.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}
	bold, err := sfnt.Parse(gobold.TTF)
	if err != nil {
		return nil, err
	}
	fs := &pdfFonts{reg: reg, bold: bold}
	var buf sfnt.Buffer
	for _, f := range []*sfnt.Font{reg, bold} {
		upem := int(f.UnitsPerEm())
		m, err := f.Metrics(&buf, fixed.I(upem), font.HintingNone)
		if err != nil {
			return nil, err
		}
		fs.asc = max(fs.asc, float64(m.Ascent)/64/float64(upem))
		fs.desc = max(fs.desc, float64(m.Descent)/64/float64(upem))
	}
	return fs, nil
})

type glyphSet struct {
	fonts *pdfFonts
	buf   sfnt.Buffer
	known map[rune]bool
}

func newGlyphSet() (*glyphSet, error) {
	fs, err := loadPDFFonts()
	if err != nil {
		return nil, err
	}
	return &glyphSet{fonts: fs, known: map[rune]bool{}}, nil
}

func (g *glyphSet) has(r rune) bool {
	if ok, seen := g.known[r]; seen {
		return ok
	}
	ok := r > 0 && r <= 0xFFFF && r != 0xFFFD
	for _, f := range []*sfnt.Font{g.fonts.reg, g.fonts.bold} {
		if !ok {
			break
		}
		idx, err := f.GlyphIndex(&g.buf, r)
		ok = err == nil && idx != 0
	}
	g.known[r] = ok
	return ok
}

func (g *glyphSet) show(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || g.has(r) {
			b.WriteRune(r)
			continue
		}
		fmt.Fprintf(&b, "<U+%04X>", r)
	}
	return b.String()
}

type pdfSeg struct {
	x    float64
	st   pdfStyle
	text string
}

type pdfRow struct {
	segs []pdfSeg
	h    float64
	rule bool
}

type pdfCount struct {
	n int
	v string
}

type pdfDoc struct {
	p      *fpdf.Fpdf
	g      *glyphSet
	y      float64
	footer string
}

func WritePDF(w io.Writer, r *Report) error {
	page, err := buildHTMLPage(r)
	if err != nil {
		return err
	}
	g, err := newGlyphSet()
	if err != nil {
		return err
	}
	d := newPDFDoc(g, page, pdfDate(r.Scan.StartedAt))
	d.render(page)
	var buf bytes.Buffer
	if err := d.p.Output(&buf); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func pdfDate(startedAt string) time.Time {
	t, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return time.Unix(0, 0).UTC()
	}
	return t.UTC()
}

func newPDFDoc(g *glyphSet, page *htmlPage, date time.Time) *pdfDoc {
	p := fpdf.New("P", "mm", "A4", "")
	p.SetCatalogSort(true)
	p.SetCreationDate(date)
	p.SetModificationDate(date)
	p.SetTitle("kshield report - "+page.Title, true)
	p.SetCreator("kshield", true)
	p.SetMargins(pdfMargin, pdfMargin, pdfMargin)
	p.SetAutoPageBreak(false, 0)
	p.SetCellMargin(0)
	p.AddUTF8FontFromBytes(pdfFamily, "", goregular.TTF)
	p.AddUTF8FontFromBytes(pdfFamily, "B", gobold.TTF)
	d := &pdfDoc{p: p, g: g, footer: g.show("kshield " + page.R.Tool.Version + " - page ")}
	p.SetFooterFunc(d.drawFooter)
	d.newPage()
	return d
}

func (d *pdfDoc) bottom() float64 {
	return pdfPageH - pdfMargin - pdfFooterH
}

func (d *pdfDoc) newPage() {
	d.p.AddPage()
	d.y = pdfMargin
}

func (d *pdfDoc) setStyle(st pdfStyle) {
	style := ""
	if st.bold {
		style = "B"
	}
	d.p.SetFont(pdfFamily, style, st.size)
	d.p.SetTextColor(st.color[0], st.color[1], st.color[2])
}

func (d *pdfDoc) drawFooter() {
	text := fmt.Sprintf("%s%d", d.footer, d.p.PageNo())
	d.setStyle(stFooter)
	maxW := pdfPageW - 2*pdfMargin
	if d.p.GetStringWidth(text) > maxW-pdfWrapSlack {
		text = fmt.Sprintf("kshield - page %d", d.p.PageNo())
	}
	x := pdfMargin + (maxW-d.p.GetStringWidth(text))/2
	d.p.Text(x, pdfPageH-pdfMargin-d.g.fonts.desc*stFooter.size*mmPerPt, text)
}

func (d *pdfDoc) lineH(st pdfStyle) float64 {
	return st.size * mmPerPt * max(1.3, d.g.fonts.asc+d.g.fonts.desc+0.1)
}

func (d *pdfDoc) wrap(st pdfStyle, width float64, text string) []string {
	d.setStyle(st)
	var out []string
	for _, par := range strings.Split(d.g.show(text), "\n") {
		lines := d.p.SplitText(par, width-pdfWrapSlack)
		if len(lines) == 0 {
			lines = []string{""}
		}
		out = append(out, lines...)
	}
	return out
}

func (d *pdfDoc) para(x float64, st pdfStyle, text string) []pdfRow {
	var rows []pdfRow
	for _, l := range d.wrap(st, pdfPageW-pdfMargin-x, text) {
		rows = append(rows, pdfRow{segs: []pdfSeg{{x: x, st: st, text: l}}, h: d.lineH(st)})
	}
	return rows
}

func (d *pdfDoc) labeled(x, labelW float64, lst pdfStyle, label string, vst pdfStyle, value string) []pdfRow {
	rows := d.para(x+labelW, vst, value)
	for i, l := range d.wrap(lst, labelW-1, label) {
		if i == len(rows) {
			rows = append(rows, pdfRow{})
		}
		rows[i].segs = append([]pdfSeg{{x: x, st: lst, text: l}}, rows[i].segs...)
		rows[i].h = max(rows[i].h, d.lineH(lst))
	}
	return rows
}

func gap(h float64) pdfRow {
	return pdfRow{h: h}
}

func (d *pdfDoc) place(keep bool, rows ...pdfRow) {
	var total float64
	for _, r := range rows {
		total += r.h
	}
	if keep && total <= d.bottom()-pdfMargin {
		d.need(total)
	}
	for _, r := range rows {
		if len(r.segs) == 0 && !r.rule {
			if d.y > pdfMargin {
				d.y = min(d.y+r.h, d.bottom())
			}
			continue
		}
		if d.y+r.h > d.bottom() {
			d.newPage()
		}
		if r.rule {
			d.p.SetDrawColor(0xd0, 0xd7, 0xde)
			d.p.SetLineWidth(0.2)
			mid := d.y + r.h/2
			d.p.Line(pdfMargin, mid, pdfPageW-pdfMargin, mid)
		}
		for _, s := range r.segs {
			if s.text == "" {
				continue
			}
			d.setStyle(s.st)
			d.p.Text(s.x, d.y+d.g.fonts.asc*s.st.size*mmPerPt, s.text)
		}
		d.y += r.h
	}
}

func (d *pdfDoc) need(h float64) {
	if d.y > pdfMargin && d.y+h > d.bottom() {
		d.newPage()
	}
}

func (d *pdfDoc) keepWithNext(rows ...pdfRow) {
	h := 3 * d.lineH(stSmall)
	for _, r := range rows {
		h += r.h
	}
	d.need(h)
	d.place(false, rows...)
}

func (d *pdfDoc) heading(st pdfStyle, text string, before float64) {
	rows := append([]pdfRow{gap(before)}, d.para(pdfMargin, st, text)...)
	d.keepWithNext(append(rows, gap(1.5))...)
}

func (d *pdfDoc) render(page *htmlPage) {
	r := page.R
	d.place(false, d.para(pdfMargin, stTitle, "kshield report - "+page.Title)...)
	d.place(false, gap(2))
	d.place(false, d.para(pdfMargin, stBody, page.Disclaimer)...)

	d.heading(stH2, "Scan", 6)
	kv := func(label, value string) {
		d.place(true, d.labeled(pdfMargin, 34, stSmallB, label, stSmall, value)...)
	}
	kv("Tool", r.Tool.Name+" "+r.Tool.Version)
	kv("Profile", fmt.Sprintf("%s v%d", r.Profile.ID, r.Profile.Version))
	kv("Profile sha256", r.Profile.SHA256)
	kv("Mode", r.Scan.Mode)
	if c := page.Cluster; c != nil {
		kv("Context", c.Context)
		kv("Server", c.Server)
		kv("Namespaces", c.Namespaces)
		kv("Node probe", c.NodeProbe)
	} else {
		pdfInputRows(page, kv)
	}
	kv("Namespace", page.Namespace)
	kv("Started at", r.Scan.StartedAt)
	kv("Objects", fmt.Sprint(r.Scan.Objects))
	kv("AI workloads", fmt.Sprint(r.Scan.AIWorkloads))

	if r.Summary.Incomplete {
		d.place(false, gap(5))
		d.place(true, d.para(pdfMargin, verdictStyle(VerdictFail, 11), "INCOMPLETE - the scan did not finish. The results below are partial. See Errors.")...)
	}

	d.heading(stH2, "Summary", 6)
	counts := []pdfCount{{r.Summary.Fail, VerdictFail}, {r.Summary.Warn, VerdictWarn}, {r.Summary.Pass, VerdictPass}, {r.Summary.Info, VerdictInfo}, {r.Summary.NA, VerdictNA}}
	step := 34.0
	if r.Summary.Unknown > 0 {
		counts = slices.Insert(counts, 1, pdfCount{r.Summary.Unknown, VerdictUnknown})
		step = 30
	}
	row := pdfRow{h: d.lineH(stH3)}
	for i, c := range counts {
		row.segs = append(row.segs, pdfSeg{x: pdfMargin + float64(i)*step, st: verdictStyle(c.v, 11), text: fmt.Sprintf("%d %s", c.n, c.v)})
	}
	d.place(false, row)
	if page.Note != "" {
		d.place(false, d.para(pdfMargin, stMuted, page.Note)...)
	}

	checkW, headW := 14.0, 16.0
	if page.HasUnknown {
		checkW, headW = 22, 26
	}

	d.heading(stH2, "Checks", 6)
	if len(page.Checks) == 0 {
		d.place(false, d.para(pdfMargin, stSmall, "No checks.")...)
	}
	for _, c := range page.Checks {
		text := fmt.Sprintf("%s %s %s - severity %s, fix: %s", c.Display, c.ID, c.Title, c.Severity, c.FixLabel)
		d.place(true, append(d.labeled(pdfMargin, checkW, verdictStyle(c.Verdict, 9), c.Verdict, stSmall, text), gap(0.8))...)
	}

	d.heading(stH2, "Findings", 6)
	if len(page.Details) == 0 {
		d.place(false, d.para(pdfMargin, stSmall, "No findings.")...)
	}
	for i, c := range page.Details {
		if i > 0 {
			d.place(false, gap(5))
		}
		head := d.labeled(pdfMargin, headW, verdictStyle(c.Verdict, 11), c.Verdict, stH3, c.Display+" "+c.ID+" "+c.Title)
		head = append(head, d.para(pdfMargin, stMuted, "severity "+c.Severity+" | fix: "+c.FixLabel)...)
		lead := head
		if len(c.Refs) > 0 {
			lead = append(append(lead, gap(2)), d.para(pdfMargin, stH4, "Supports evidence for")...)
		}
		for _, ref := range c.Refs {
			rows := append(lead, gap(1))
			rows = append(rows, d.para(pdfMargin, stSmallB, ref.Label)...)
			rows = append(rows, d.para(pdfMargin, stMuted, ref.Short+", CELEX "+ref.CELEX+", "+ref.URL)...)
			rows = append(rows, d.para(pdfMargin+5, stMuted, ref.Text)...)
			d.place(true, rows...)
			lead = nil
		}
		lead = append(append(lead, gap(2)), d.para(pdfMargin, stH4, fmt.Sprintf("Findings (%d)", len(c.Findings)))...)
		for _, f := range c.Findings {
			d.place(true, append(lead, d.findingRows(c, f)...)...)
			lead = nil
		}
		if len(c.Findings) == 0 {
			d.place(true, lead...)
		}
	}

	d.heading(stH2, "Errors", 6)
	if len(r.Errors) == 0 {
		d.place(false, d.para(pdfMargin, stSmall, "No errors.")...)
	}
	for _, e := range r.Errors {
		d.place(true, d.labeled(pdfMargin, 4, verdictStyle(VerdictFail, 9), "-", verdictStyle(VerdictFail, 9), e)...)
	}
}

func pdfInputRows(page *htmlPage, kv func(label, value string)) {
	inputs := strings.Join(page.Inputs, ", ")
	if inputs == "" {
		inputs = "none"
	}
	kv("Inputs", inputs)
	if len(page.Digests) == 0 {
		kv("Input files", "none")
	}
	for i, dg := range page.Digests {
		label := ""
		if i == 0 {
			label = "Input files"
		}
		kv(label, dg.Path+"  sha256 "+dg.SHA256)
	}
}

func (d *pdfDoc) findingRows(c htmlCheck, f htmlFinding) []pdfRow {
	const x, lw = pdfMargin + 3, 20
	rows := []pdfRow{{rule: true, h: 2.5}}
	rows = append(rows, d.para(x, stFinding, c.Display+" "+f.Object+" "+f.Message)...)
	field := func(label string, vst pdfStyle, value string) {
		rows = append(rows, d.labeled(x, lw, stLabel, label, vst, value)...)
	}
	field("verdict", verdictStyle(f.Verdict, 8.5), f.Verdict)
	if f.Group != "" {
		field("group", stValue, f.Group)
	}
	if f.Container != "" {
		field("container", stValue, f.Container)
	}
	field("path", stValue, f.Path)
	if f.Source != "" {
		field("source", stValue, f.Source)
	}
	return rows
}
