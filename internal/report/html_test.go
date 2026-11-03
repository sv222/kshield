package report

import (
	"bytes"
	"errors"
	"html"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sv222/kshield/internal/htmlcheck"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/regtext"
)

const toxicHTML = "../../test/golden/toxic.html"

func renderHTML(t *testing.T, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestHTMLGolden(t *testing.T) {
	got := []byte(renderHTML(t, toxicReport(t)))
	if again := renderHTML(t, toxicReport(t)); again != string(got) {
		t.Fatal("two renders of the same report differ")
	}
	if *update {
		if err := os.WriteFile(toxicHTML, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(toxicHTML)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HTML differs from %s (run with -update and review the diff)", toxicHTML)
	}
}

func TestHTMLNoNetwork(t *testing.T) {
	page := renderHTML(t, toxicReport(t))
	if v := htmlcheck.NoNetwork([]byte(page)); len(v) != 0 {
		t.Fatalf("network violations: %v", v)
	}
	if !strings.Contains(page, htmlcheck.CSPMeta) {
		t.Fatal("CSP meta missing")
	}
}

func TestHTMLNoComplianceClaim(t *testing.T) {
	r := toxicReport(t)
	page := html.UnescapeString(renderHTML(t, r))
	if !strings.Contains(page, Disclaimer) {
		t.Fatalf("disclaimer %q missing", Disclaimer)
	}
	assertNoComplianceClaim(t, page, r)
}

func TestHTMLEscapes(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Message = `<script>alert("x")</script> & é`
	page := renderHTML(t, r)
	if !strings.Contains(page, `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; é`) {
		t.Fatalf("message not escaped as expected:\n%s", page)
	}
	if strings.Contains(page, `<script>`) {
		t.Fatal("raw <script> in page")
	}
	if v := htmlcheck.NoNetwork([]byte(page)); len(v) != 0 {
		t.Fatalf("network violations: %v", v)
	}
}

func TestHTMLHostileStrings(t *testing.T) {
	const hostile = "<script>\"x\" & \u202Eevil\u2066 Жук 漢字"
	const escaped = "&lt;script&gt;&#34;x&#34; &amp; &lt;U&#43;202E&gt;evil&lt;U&#43;2066&gt; Жук 漢字"
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
		{"profile title", func(r *Report) { r.Profile.Title = hostile }},
		{"scan namespace", func(r *Report) { r.Scan.Namespace = hostile }},
		{"input digest path", func(r *Report) { r.Scan.InputDigests[0].Path = hostile }},
		{"error", func(r *Report) { r.Errors = []string{hostile} }},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			r := sampleReport()
			tc.set(r)
			page := renderHTML(t, r)
			if !strings.Contains(page, escaped) {
				t.Errorf("escaped form %q missing", escaped)
			}
			if !strings.Contains(page, "Жук 漢字") {
				t.Error("non-Latin text not kept as UTF-8")
			}
			for _, bad := range []string{"<script>", "\u202E", "\u2066"} {
				if strings.Contains(page, bad) {
					t.Errorf("page contains raw %q", bad)
				}
			}
			if v := htmlcheck.NoNetwork([]byte(page)); len(v) != 0 {
				t.Errorf("network violations: %v", v)
			}
		})
	}
}

func TestHTMLExcerptQuoted(t *testing.T) {
	r := toxicReport(t)
	page := html.UnescapeString(renderHTML(t, r))
	fails := 0
	for _, c := range r.Checks {
		if c.Verdict != VerdictFail {
			continue
		}
		fails++
		if len(c.Refs) == 0 {
			t.Errorf("FAIL check %s has no refs", c.ID)
		}
		for _, ref := range c.Refs {
			ex, src, ok := regtext.Lookup(ref.ID)
			if !ok {
				t.Fatalf("unknown ref %q", ref.ID)
			}
			for _, want := range []string{"<blockquote>" + ex.Text + "</blockquote>", ref.Label, src.Short, src.CELEX, src.URL} {
				if !strings.Contains(page, want) {
					t.Errorf("check %s ref %s: missing %q", c.ID, ref.ID, want)
				}
			}
		}
	}
	if fails == 0 {
		t.Fatal("toxic report has no FAIL checks")
	}
}

func TestHTMLSectionOrder(t *testing.T) {
	page := renderHTML(t, toxicReport(t))
	marks := []string{
		"<title>kshield report - DORA Chapter II - Regulation (EU) 2022/2554 and RTS (EU) 2024/1774</title>",
		Disclaimer,
		`<section id="scan">`,
		`<section id="summary">`,
		`<section id="checks">`,
		`<section id="findings">`,
		`<section id="errors">`,
	}
	at := -1
	for _, m := range marks {
		i := strings.Index(page, m)
		if i < 0 {
			t.Fatalf("missing %q", m)
		}
		if i < at {
			t.Fatalf("%q is out of order", m)
		}
		at = i
	}
}

func TestHTMLScanBox(t *testing.T) {
	r := sampleReport()
	r.Scan.Inputs = []string{"-", "deploy/"}
	r.Scan.InputDigests = []load.Digest{{Path: "-", SHA256: strings.Repeat("ef", 32)}, {Path: "deploy/vllm.yaml", SHA256: strings.Repeat("cd", 32)}}
	page := renderHTML(t, r)
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
	} {
		if !strings.Contains(page, want) {
			t.Errorf("scan box misses %q", want)
		}
	}
}

func TestHTMLFindingFields(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings = append(r.Checks[0].Findings, Finding{
		Object:  load.ObjectRef{APIVersion: "v1", Kind: "Namespace", Name: "ai"},
		Group:   "head",
		Path:    "/metadata/labels",
		Message: "no source",
		Verdict: VerdictWarn,
	})
	page := renderHTML(t, r)
	for _, want := range []string{
		"Deployment/ai-inference/vllm",
		"/spec/template/spec/containers/0/securityContext/runAsNonRoot",
		"deploy/vllm.yaml:1",
		"Namespace/ai",
		">head<",
		`class="verdict v-warn"`,
		`class="verdict v-fail"`,
		`class="verdict v-na"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if n := strings.Count(page, `<dt>source</dt>`); n != 1 {
		t.Errorf("source rows = %d, want 1 (sourceless finding has none)", n)
	}
}

func TestHTMLEmptyAndIncomplete(t *testing.T) {
	page := renderHTML(t, &Report{})
	if !strings.Contains(page, Disclaimer) || !strings.Contains(page, "No checks.") {
		t.Fatalf("empty report page:\n%s", page)
	}
	if strings.Contains(page, "INCOMPLETE") {
		t.Fatal("complete report shows INCOMPLETE")
	}
	if v := htmlcheck.NoNetwork([]byte(page)); len(v) != 0 {
		t.Fatalf("network violations: %v", v)
	}
	r := oneCheckReport(CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictPass})
	r.Summary.Incomplete = true
	r.Errors = []string{"cluster: unreachable", "node <probe> failed"}
	page = renderHTML(t, r)
	for _, want := range []string{`class="banner incomplete"`, "INCOMPLETE", "cluster: unreachable", "node &lt;probe&gt; failed"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	banner, summary := strings.Index(page, "INCOMPLETE"), strings.Index(page, `<section id="summary">`)
	if banner > summary {
		t.Error("INCOMPLETE banner must come before the summary")
	}
}

func TestHTMLUnknownRef(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Refs = []Ref{{ID: "no-such-ref", Label: "X"}}
	if err := WriteHTML(&bytes.Buffer{}, r); err == nil || !strings.Contains(err.Error(), "no-such-ref") {
		t.Fatalf("err = %v, want unknown ref error", err)
	}
}

func TestHTMLWriterError(t *testing.T) {
	if err := WriteHTML(failWriter{}, sampleReport()); !errors.Is(err, errWrite) {
		t.Fatalf("err = %v", err)
	}
}

func TestHTMLLarge(t *testing.T) {
	r := sampleReport()
	base := r.Checks[0].Findings[0]
	r.Checks[0].Findings = make([]Finding, 5000)
	for i := range r.Checks[0].Findings {
		r.Checks[0].Findings[i] = base
	}
	start := time.Now()
	page := renderHTML(t, r)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("render took %s", d)
	}
	if n := strings.Count(page, `<div class="finding">`); n != 5000 {
		t.Fatalf("findings rendered = %d, want 5000", n)
	}
}
