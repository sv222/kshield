package report

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/pdftext"
)

const toxicPDF = "../../test/golden/toxic.pdf"

func renderPDF(t *testing.T, r *Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WritePDF(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pdfPages(t *testing.T, pdf []byte) []string {
	t.Helper()
	pages, err := pdftext.Extract(pdf)
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

func pdfRuns(t *testing.T, pdf []byte) [][]pdftext.Run {
	t.Helper()
	pages, err := pdftext.Runs(pdf)
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

type testFont struct {
	f    *sfnt.Font
	upem float64
	asc  float64
	desc float64
}

func loadTestFont(t *testing.T, ttf []byte) testFont {
	t.Helper()
	f, err := sfnt.Parse(ttf)
	if err != nil {
		t.Fatal(err)
	}
	upem := int(f.UnitsPerEm())
	m, err := f.Metrics(&sfnt.Buffer{}, fixed.I(upem), font.HintingNone)
	if err != nil {
		t.Fatal(err)
	}
	return testFont{f: f, upem: float64(upem), asc: float64(m.Ascent) / 64 / float64(upem), desc: float64(m.Descent) / 64 / float64(upem)}
}

type layoutChecker struct {
	t         *testing.T
	reg, bold testFont
	buf       sfnt.Buffer
}

func newLayoutChecker(t *testing.T) *layoutChecker {
	return &layoutChecker{t: t, reg: loadTestFont(t, goregular.TTF), bold: loadTestFont(t, gobold.TTF)}
}

func (c *layoutChecker) font(name string) testFont {
	switch name {
	case "utf8go":
		return c.reg
	case "utf8goB":
		return c.bold
	}
	c.t.Fatalf("unexpected font %q", name)
	return testFont{}
}

func (c *layoutChecker) width(tf testFont, sizeMM float64, s string) float64 {
	var w float64
	for _, r := range s {
		idx, err := tf.f.GlyphIndex(&c.buf, r)
		if err != nil || idx == 0 {
			c.t.Errorf("rune %U %q has no glyph in the embedded font", r, r)
			continue
		}
		adv, err := tf.f.GlyphAdvance(&c.buf, idx, fixed.I(int(tf.upem)), font.HintingNone)
		if err != nil {
			c.t.Fatal(err)
		}
		w += float64(adv) / 64 / tf.upem * sizeMM
	}
	return w
}

func (c *layoutChecker) check(pages [][]pdftext.Run) {
	const k = 72 / 25.4
	const eps = 0.3
	for pi, runs := range pages {
		last := -1.0
		for _, r := range runs {
			tf := c.font(r.Font)
			size := r.Size / k
			x := r.X / k
			base := 297 - r.Y/k
			w := c.width(tf, size, r.Text)
			if x < 15-eps || x+w > 195+eps || base-tf.asc*size < 15-eps || base+tf.desc*size > 282+eps {
				c.t.Errorf("page %d: line %q outside the margins: x %.2f..%.2f, baseline %.2f, size %.2f mm", pi+1, r.Text, x, x+w, base, size)
			}
			if base < last-0.01 {
				c.t.Errorf("page %d: line %q at baseline %.2f is above the line before it (%.2f)", pi+1, r.Text, base, last)
			}
			last = base
		}
	}
}

func pdfShown(t *testing.T, s string) string {
	t.Helper()
	g, err := newGlyphSet()
	if err != nil {
		t.Fatal(err)
	}
	return g.show(showBidi(s))
}

func TestPDFDeterministic(t *testing.T) {
	a := renderPDF(t, toxicReport(t))
	b := renderPDF(t, toxicReport(t))
	if !bytes.Equal(a, b) {
		t.Fatal("two renders of the same report differ")
	}
	for _, want := range []string{"/CreationDate (D:19700101000000)", "/ModDate (D:19700101000000)"} {
		if !bytes.Contains(a, []byte(want)) {
			t.Errorf("PDF misses %q", want)
		}
	}
	r := sampleReport()
	r.Scan.StartedAt = "2026-10-17T09:30:05+02:00"
	if c := renderPDF(t, r); !bytes.Contains(c, []byte("/CreationDate (D:20261017073005)")) {
		t.Error("creation date is not taken from scan.startedAt (UTC)")
	}
}

func TestPDFGolden(t *testing.T) {
	got := renderPDF(t, toxicReport(t))
	if *update {
		if err := os.WriteFile(toxicPDF, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(toxicPDF)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PDF differs from %s (run with -update and review it)", toxicPDF)
	}
}

func TestPDFTextMatchesJSON(t *testing.T) {
	r := toxicReport(t)
	pdf := renderPDF(t, r)
	pages := pdfPages(t, pdf)
	if !strings.Contains(pdftext.Squash(pages[0]), pdftext.Squash(Disclaimer)) {
		t.Fatal("disclaimer is not on page 1")
	}
	all := pdftext.Squash(strings.Join(pages, "\n"))
	n := 0
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			n++
			want := pdftext.Squash(pdfShown(t, c.Display+" "+f.Object.String()+" "+f.Message))
			if !strings.Contains(all, want) {
				t.Errorf("check %s: finding text %q not in PDF", c.ID, want)
			}
			if p := pdftext.Squash(pdfShown(t, f.Path)); !strings.Contains(all, p) {
				t.Errorf("check %s: path %q not in PDF", c.ID, p)
			}
		}
	}
	if n == 0 {
		t.Fatal("toxic report has no findings")
	}
	newLayoutChecker(t).check(pdfRuns(t, pdf))
}

func TestPDFNoComplianceClaim(t *testing.T) {
	r := toxicReport(t)
	text := strings.Join(pdfPages(t, renderPDF(t, r)), "\n")
	assertNoComplianceClaim(t, text, r)
}

func TestPDFUnicode(t *testing.T) {
	r := sampleReport()
	const msg = "Grüße ä é ’ Ж - runAsNonRoot"
	r.Checks[0].Findings[0].Message = msg
	pages := pdfPages(t, renderPDF(t, r))
	if !strings.Contains(strings.Join(pages, "\n"), msg) {
		t.Fatalf("message %q not found in:\n%s", msg, strings.Join(pages, "\n"))
	}
}

func TestPDFHostileStrings(t *testing.T) {
	var hostile = "<script>\"x\" & " + string(rune(0x202E)) + "evil" + string(rune(0x2066)) + " Жук 漢字 (a\\b)"
	const shown = "<script>\"x\" & <U+202E>evil<U+2066> Жук <U+6F22><U+5B57> (a\\b)"
	cases := []struct {
		field string
		set   func(r *Report)
	}{
		{"object name", func(r *Report) { r.Checks[0].Findings[0].Object.Name = hostile }},
		{"object namespace", func(r *Report) { r.Checks[0].Findings[0].Object.Namespace = hostile }},
		{"path", func(r *Report) { r.Checks[0].Findings[0].Path = hostile }},
		{"container", func(r *Report) { r.Checks[0].Findings[0].Container = hostile }},
		{"group", func(r *Report) { r.Checks[0].Findings[0].Group = hostile }},
		{"message", func(r *Report) { r.Checks[0].Findings[0].Message = hostile }},
		{"source file", func(r *Report) { r.Checks[0].Findings[0].Source.File = hostile }},
		{"check title", func(r *Report) { r.Checks[0].Title = hostile }},
		{"ref label", func(r *Report) { r.Checks[0].Refs[0].Label = hostile }},
		{"profile title", func(r *Report) { r.Profile.Title = hostile }},
		{"scan input", func(r *Report) { r.Scan.Inputs = []string{hostile} }},
		{"scan namespace", func(r *Report) { r.Scan.Namespace = hostile }},
		{"input digest path", func(r *Report) { r.Scan.InputDigests[0].Path = hostile }},
		{"tool version", func(r *Report) { r.Tool.Version = hostile }},
		{"error", func(r *Report) { r.Errors = []string{hostile} }},
	}
	if got := pdfShown(t, hostile); got != shown {
		t.Fatalf("display form = %q, want %q", got, shown)
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			r := sampleReport()
			tc.set(r)
			pdf := renderPDF(t, r)
			text := strings.Join(pdfPages(t, pdf), "\n")
			if !strings.Contains(pdftext.Squash(text), pdftext.Squash(shown)) {
				t.Errorf("display form %q missing", shown)
			}
			for _, bad := range []string{string(rune(0x202E)), string(rune(0x2066)), "漢", "字"} {
				if strings.Contains(text, bad) {
					t.Errorf("text contains raw %q", bad)
				}
			}
			newLayoutChecker(t).check(pdfRuns(t, pdf))
		})
	}
}

func TestPDFGlyphFallback(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"cjk":         "<U+6F22>",
		"non-BMP":     "<U+1F600>",
		"tab":         "a<U+0009>b",
		"invalid utf": "a<U+FFFD>b",
		"newline":     "a\nb",
	}
	in := map[string]string{
		"plain":       "plain",
		"cjk":         "漢",
		"non-BMP":     "\U0001F600",
		"tab":         "a\tb",
		"invalid utf": "a\xffb",
		"newline":     "a\nb",
	}
	for name, want := range cases {
		if got := pdfShown(t, in[name]); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

func TestPDFSectionOrder(t *testing.T) {
	r := toxicReport(t)
	var runs []string
	for _, p := range pdfRuns(t, renderPDF(t, r)) {
		for _, run := range p {
			runs = append(runs, run.Text)
		}
	}
	title := pdftext.Squash("kshield report - " + r.Profile.Title + Disclaimer)
	if got := pdftext.Squash(strings.Join(runs, "")); !strings.HasPrefix(got, title) {
		t.Fatalf("PDF does not start with the title and the disclaimer: %.200q", got)
	}
	marks := []string{"Scan", "Summary", "Checks", "Findings", "Errors"}
	at := -1
	for _, m := range marks {
		i := -1
		for j := at + 1; j < len(runs); j++ {
			if runs[j] == m {
				i = j
				break
			}
		}
		if i < 0 {
			t.Fatalf("heading %q missing or out of order", m)
		}
		at = i
	}
}

func TestPDFScanBox(t *testing.T) {
	r := sampleReport()
	r.Scan.Inputs = []string{"-", "deploy/"}
	r.Scan.InputDigests = []load.Digest{{Path: "-", SHA256: strings.Repeat("ef", 32)}, {Path: "deploy/vllm.yaml", SHA256: strings.Repeat("cd", 32)}}
	all := pdftext.Squash(strings.Join(pdfPages(t, renderPDF(t, r)), "\n"))
	for _, want := range []string{
		"kshield 0.0.0-deterministic",
		"dora v1",
		strings.Repeat("ab", 32),
		"manifest",
		"- (stdin)",
		strings.Repeat("ef", 32),
		"deploy/vllm.yaml",
		strings.Repeat("cd", 32),
		"ai-inference",
		"1970-01-01T00:00:00Z",
		"1 FAIL",
		"DORA-CH2-001",
		"KS-WL-001",
		"workload patch (kshield remediate)",
		"DORA Art. 9(4)(c)",
		"kshield 0.0.0-deterministic - page 1",
	} {
		if !strings.Contains(all, pdftext.Squash(want)) {
			t.Errorf("PDF misses %q", want)
		}
	}
}

func TestPDFFindingFields(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings = append(r.Checks[0].Findings, Finding{
		Object:  r.Checks[0].Findings[0].Object,
		Group:   "headgroup",
		Path:    "/metadata/labels",
		Message: "no source here",
		Verdict: VerdictWarn,
	})
	runs := pdfRuns(t, renderPDF(t, r))
	var texts []string
	for _, p := range runs {
		for _, run := range p {
			texts = append(texts, run.Text)
		}
	}
	joined := strings.Join(texts, "\n")
	want := "DORA-CH2-001 Deployment/ai-inference/vllm runAsNonRoot is not true and runAsUser is not set\nverdict\nFAIL\ncontainer\nvllm\npath\n/spec/template/spec/containers/0/securityContext/runAsNonRoot\nsource\ndeploy/vllm.yaml:1\n" +
		"DORA-CH2-001 Deployment/ai-inference/vllm no source here\nverdict\nWARN\ngroup\nheadgroup\npath\n/metadata/labels\n"
	if !strings.Contains(joined, want) {
		t.Fatalf("finding blocks not as expected:\n%s", joined)
	}
	if n := strings.Count(joined, "\nsource\n"); n != 1 {
		t.Errorf("source rows = %d, want 1", n)
	}
}

func TestPDFEmptyAndIncomplete(t *testing.T) {
	text := strings.Join(pdfPages(t, renderPDF(t, &Report{})), "\n")
	for _, want := range []string{"No checks.", "No findings.", "No errors."} {
		if !strings.Contains(text, want) {
			t.Errorf("empty report misses %q", want)
		}
	}
	if !strings.Contains(pdftext.Squash(text), pdftext.Squash(Disclaimer)) {
		t.Error("empty report misses the disclaimer")
	}
	if strings.Contains(text, "INCOMPLETE") {
		t.Error("complete report shows INCOMPLETE")
	}
	r := oneCheckReport(CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictPass})
	r.Summary.Incomplete = true
	r.Scan.Objects = 3
	r.Errors = []string{"cluster: unreachable", "node <probe> failed"}
	text = strings.Join(pdfPages(t, renderPDF(t, r)), "\n")
	for _, want := range []string{"INCOMPLETE", "cluster: unreachable", "node <probe> failed", noAIWorkloadsNote} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Index(text, "INCOMPLETE") > strings.Index(text, "\nSummary\n") {
		t.Error("INCOMPLETE banner must come before the summary")
	}
}

func TestPDFUnknownRef(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Refs = []Ref{{ID: "no-such-ref", Label: "X"}}
	if err := WritePDF(&bytes.Buffer{}, r); err == nil || !strings.Contains(err.Error(), "no-such-ref") {
		t.Fatalf("err = %v, want unknown ref error", err)
	}
}

func TestPDFWriterError(t *testing.T) {
	if err := WritePDF(failWriter{}, sampleReport()); !errors.Is(err, errWrite) {
		t.Fatalf("err = %v", err)
	}
}

func largeReport(n int) *Report {
	r := sampleReport()
	base := r.Checks[0].Findings[0]
	r.Checks[0].Findings = make([]Finding, n)
	for i := range r.Checks[0].Findings {
		r.Checks[0].Findings[i] = base
	}
	r.Checks[0].Findings[n-1].Path = strings.Repeat("/averyveryverylongpathsegmentwithoutanyspaces", 12)
	r.Checks[0].Findings[n-1].Message = strings.Repeat("word ", 400)
	return r
}

func TestPDFLarge(t *testing.T) {
	start := time.Now()
	small := renderPDF(t, largeReport(1000))
	dSmall := time.Since(start)
	start = time.Now()
	pdf := renderPDF(t, largeReport(5000))
	d := time.Since(start)
	if d > 20*time.Second {
		t.Fatalf("render of 5000 findings took %s", d)
	}
	if d > 12*dSmall+time.Second {
		t.Errorf("5000 findings took %s, 1000 took %s: slower than linear", d, dSmall)
	}
	t.Logf("1000 findings: %s, %d bytes; 5000 findings: %s, %d bytes", dSmall, len(small), d, len(pdf))
	runs := pdfRuns(t, pdf)
	if len(runs) < 2 {
		t.Fatalf("pages = %d, want more than 1", len(runs))
	}
	for i, p := range runs {
		want := fmt.Sprintf("kshield 0.0.0-deterministic - page %d", i+1)
		if len(p) == 0 || p[len(p)-1].Text != want {
			t.Fatalf("page %d does not end with footer %q", i+1, want)
		}
	}
	newLayoutChecker(t).check(runs)
	var texts []string
	for _, p := range runs {
		for _, run := range p {
			texts = append(texts, run.Text)
		}
	}
	all := pdftext.Squash(strings.Join(texts, "\n"))
	f := sampleReport().Checks[0].Findings[0]
	first := pdftext.Squash("DORA-CH2-001 " + f.Object.String() + " " + f.Message)
	if n := strings.Count(all, first); n != 4999 {
		t.Errorf("finding blocks = %d, want 4999", n)
	}
	if !strings.Contains(all, pdftext.Squash(largeReport(1).Checks[0].Findings[0].Path)) {
		t.Error("long path lost")
	}
}
