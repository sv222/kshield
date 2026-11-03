package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/pdftext"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func sampleReport() *Report {
	refC := Ref{ID: "dora-art9-4-c", Label: "DORA Art. 9(4)(c)", Source: "dora", URL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"}
	refDetect := Ref{ID: "dora-art10-1", Label: "DORA Art. 10(1)", Source: "dora", URL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"}
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "kshield", Version: "0.0.0-deterministic"},
		Profile: ProfileInfo{
			ID:      "dora",
			Version: 1,
			Title:   "DORA Chapter II - Regulation (EU) 2022/2554 and RTS (EU) 2024/1774",
			SHA256:  strings.Repeat("ab", 32),
		},
		Scan: ScanInfo{
			Mode:   ModeManifest,
			Inputs: []string{"deploy/vllm.yaml"},
			InputDigests: []load.Digest{
				{Path: "deploy/vllm.yaml", SHA256: strings.Repeat("cd", 32)},
			},
			Namespace:   "ai-inference",
			StartedAt:   "1970-01-01T00:00:00Z",
			Objects:     4,
			AIWorkloads: 1,
		},
		Summary: Summary{Pass: 1, Fail: 1, NA: 1},
		Checks: []CheckResult{
			{
				ID:       "KS-WL-001",
				Display:  "DORA-CH2-001",
				Title:    "Container may run as root",
				Verdict:  VerdictFail,
				Severity: "fail",
				Fix:      "patch",
				Refs:     []Ref{refC},
				Findings: []Finding{{
					Object:    load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ai-inference", Name: "vllm"},
					Source:    &Source{File: "deploy/vllm.yaml", Line: 1},
					Container: "vllm",
					Path:      "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
					Message:   "runAsNonRoot is not true and runAsUser is not set",
					Verdict:   VerdictFail,
				}},
			},
			{
				ID:       "KS-WL-002",
				Display:  "DORA-CH2-002",
				Title:    "Privileged container or privilege escalation allowed",
				Verdict:  VerdictPass,
				Severity: "fail",
				Fix:      "patch",
				Refs:     []Ref{refC},
				Findings: []Finding{},
			},
			{
				ID:       "KS-PRE-001",
				Display:  "DORA-CH2-030",
				Title:    "Tetragon missing or unhealthy",
				Verdict:  VerdictNA,
				Severity: "warn",
				Fix:      "manual",
				Refs:     []Ref{refDetect},
				Findings: []Finding{},
			},
		},
		Errors: []string{},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestWritersGolden(t *testing.T) {
	var txt, js bytes.Buffer
	if err := WriteText(&txt, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&js, sampleReport()); err != nil {
		t.Fatal(err)
	}
	golden(t, "sample.txt.golden", txt.Bytes())
	golden(t, "sample.json.golden", js.Bytes())
}

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "kshield.report/v1" {
		t.Fatalf("got %q", SchemaVersion)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&got, sampleReport()) {
		t.Fatalf("round trip changed the report:\n got %+v\nwant %+v", got, sampleReport())
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "}\n") || strings.HasSuffix(out, "\n\n") {
		t.Fatalf("want exactly one trailing newline, got %q", out[len(out)-4:])
	}
	if !strings.HasPrefix(out, "{\n  \"schemaVersion\": ") {
		t.Fatalf("want 2-space indent, got %q", out[:30])
	}
}

func TestJSONNilSlicesAreEmptyArrays(t *testing.T) {
	r := &Report{Checks: []CheckResult{{ID: "KS-T-001"}}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Scan   map[string]any `json:"scan"`
		Checks []struct {
			Refs     any `json:"refs"`
			Findings any `json:"findings"`
		} `json:"checks"`
		Errors any `json:"errors"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	empty := func(name string, v any) {
		t.Helper()
		if s, ok := v.([]any); !ok || len(s) != 0 {
			t.Errorf("%s = %#v, want []", name, v)
		}
	}
	empty("scan.inputs", raw.Scan["inputs"])
	empty("scan.inputDigests", raw.Scan["inputDigests"])
	empty("errors", raw.Errors)
	empty("checks[0].refs", raw.Checks[0].Refs)
	empty("checks[0].findings", raw.Checks[0].Findings)
	if r.Checks[0].Refs != nil || r.Checks[0].Findings != nil || r.Errors != nil || r.Scan.Inputs != nil || r.Scan.InputDigests != nil {
		t.Fatal("WriteJSON must not change the report it is given")
	}
}

func TestJSONNoHTMLEscape(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Message = "a && b <c>"
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"message": "a && b <c>"`) {
		t.Fatalf("message was escaped:\n%s", buf.String())
	}
}

func TestJSONFindingKeys(t *testing.T) {
	obj := load.ObjectRef{APIVersion: "v1", Kind: "Namespace", Name: "ai"}
	cases := []struct {
		name    string
		f       Finding
		present []string
		absent  []string
	}{
		{"object level", Finding{Object: obj, Path: "/p", Message: "m", Verdict: VerdictWarn},
			nil, []string{`"group"`, `"container"`, `"namespace"`, `"source"`}},
		{"group and container", Finding{Object: obj, Group: "head", Container: "c", Path: "/p", Message: "m", Verdict: VerdictWarn},
			[]string{`"group": "head"`, `"container": "c"`}, []string{`"namespace"`, `"source"`}},
		{"source", Finding{Object: obj, Source: &Source{File: "deploy/a.yaml", Line: 12}, Path: "/p", Message: "m", Verdict: VerdictWarn},
			[]string{`"source": {"file": "deploy/a.yaml", "line": 12}`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.f)
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			var back Finding
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(back, tc.f) {
				t.Fatalf("round trip: got %+v want %+v", back, tc.f)
			}
			for _, p := range tc.present {
				compact := strings.NewReplacer(`": `, `":`, `, "`, `,"`).Replace(p)
				if !strings.Contains(s, compact) {
					t.Errorf("missing %s in %s", p, s)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(s, a) {
					t.Errorf("unexpected %s in %s", a, s)
				}
			}
		})
	}
}

func renderText(t *testing.T, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteText(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func oneCheckReport(c CheckResult) *Report {
	return &Report{
		Tool:    Tool{Name: "kshield", Version: "v"},
		Profile: ProfileInfo{ID: "p", Version: 2},
		Scan:    ScanInfo{Mode: ModeManifest},
		Checks:  []CheckResult{c},
	}
}

func TestTextFindingLineForms(t *testing.T) {
	dep := load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "d"}
	cluster := load.ObjectRef{APIVersion: "v1", Kind: "Namespace", Name: "ns"}
	c := CheckResult{
		ID: "KS-T-001", Display: "P-1", Title: "Title", Verdict: VerdictFail, Severity: "fail", Fix: "patch",
		Findings: []Finding{
			{Object: dep, Group: "workers", Container: "c1", Message: "both", Verdict: VerdictFail},
			{Object: dep, Group: "head", Message: "group only", Verdict: VerdictWarn},
			{Object: dep, Container: "c2", Message: "container only", Verdict: VerdictInfo},
			{Object: cluster, Message: "neither", Verdict: VerdictWarn},
		},
	}
	got := renderText(t, oneCheckReport(c))
	for _, want := range []string{
		"\n       FAIL Deployment/ns/d group=workers container=c1: both\n",
		"\n       WARN Deployment/ns/d group=head: group only\n",
		"\n       INFO Deployment/ns/d container=c2: container only\n",
		"\n       WARN Namespace/ns: neither\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestTextFixLabelsAndRefs(t *testing.T) {
	f := []Finding{{Object: load.ObjectRef{Kind: "Pod", Name: "p"}, Message: "m", Verdict: VerdictWarn}}
	two := []Ref{{ID: "a", Label: "DORA Art. 9(2)"}, {ID: "b", Label: "DORA Art. 9(3)(a)"}}
	cases := []struct {
		fix, want string
	}{
		{"patch", "       fix: workload patch (kshield remediate) | supports evidence for: DORA Art. 9(2), DORA Art. 9(3)(a)\n"},
		{"policy", "       fix: guardrail policy (kshield remediate) | supports evidence for: DORA Art. 9(2), DORA Art. 9(3)(a)\n"},
		{"manual", "       fix: manual (kshield checks explain KS-T-001) | supports evidence for: DORA Art. 9(2), DORA Art. 9(3)(a)\n"},
	}
	for _, tc := range cases {
		t.Run(tc.fix, func(t *testing.T) {
			c := CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictWarn, Fix: tc.fix, Refs: two, Findings: f}
			if got := renderText(t, oneCheckReport(c)); !strings.Contains(got, tc.want) {
				t.Fatalf("missing %q in:\n%s", tc.want, got)
			}
		})
	}
}

func TestTextFixLineOnlyWithFindings(t *testing.T) {
	refs := []Ref{{ID: "a", Label: "DORA Art. 9(2)"}}
	for _, verdict := range []string{VerdictPass, VerdictNA} {
		c := CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: verdict, Fix: "patch", Refs: refs}
		got := renderText(t, oneCheckReport(c))
		if strings.Contains(got, "fix:") || strings.Contains(got, "supports evidence for") {
			t.Errorf("%s check must be one line:\n%s", verdict, got)
		}
	}
}

func TestTextVerdictTagsAlign(t *testing.T) {
	r := &Report{Tool: Tool{Name: "kshield", Version: "v"}, Profile: ProfileInfo{ID: "p", Version: 1}, Scan: ScanInfo{Mode: ModeManifest}}
	for _, v := range []string{VerdictFail, VerdictWarn, VerdictPass, VerdictInfo, VerdictNA} {
		r.Checks = append(r.Checks, CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: v})
	}
	got := renderText(t, r)
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line[7:], "P-1 KS-T-001 T") {
			t.Errorf("display column is not at offset 7: %q", line)
		}
	}
	if !strings.Contains(got, "\n[N/A]  P-1 KS-T-001 T\n") {
		t.Fatalf("N/A tag must be padded:\n%s", got)
	}
}

func TestTextErrorsAndIncomplete(t *testing.T) {
	r := oneCheckReport(CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictPass})
	r.Errors = []string{"cluster: unreachable", "node probe failed"}
	r.Summary.Incomplete = true
	got := renderText(t, r)
	for _, want := range []string{"error: cluster: unreachable\n", "error: node probe failed\n", "scan incomplete\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if clean := renderText(t, oneCheckReport(CheckResult{ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictPass})); strings.Contains(clean, "error:") || strings.Contains(clean, "incomplete") {
		t.Fatalf("clean report must not mention errors:\n%s", clean)
	}
}

func TestTextNoChecks(t *testing.T) {
	r := &Report{Tool: Tool{Name: "kshield", Version: "v"}, Profile: ProfileInfo{ID: "dora", Version: 1}, Scan: ScanInfo{Mode: ModeManifest, Objects: 3, AIWorkloads: 2}}
	want := "kshield v | profile dora v1 | manifest scan | 3 objects, 2 AI workloads\n\nSummary: 0 FAIL, 0 WARN, 0 PASS, 0 INFO, 0 N/A\n"
	if got := renderText(t, r); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

type failWriter struct{}

var errWrite = errors.New("write failed")

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestWritersReturnWriterError(t *testing.T) {
	if err := WriteText(failWriter{}, sampleReport()); !errors.Is(err, errWrite) {
		t.Errorf("WriteText: %v", err)
	}
	if err := WriteJSON(failWriter{}, sampleReport()); !errors.Is(err, errWrite) {
		t.Errorf("WriteJSON: %v", err)
	}
}

func TestJSONScanInputDigests(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Scan struct {
			InputDigests []map[string]any `json:"inputDigests"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{{"path": "deploy/vllm.yaml", "sha256": strings.Repeat("cd", 32)}}
	if !reflect.DeepEqual(raw.Scan.InputDigests, want) {
		t.Fatalf("inputDigests = %v, want %v", raw.Scan.InputDigests, want)
	}
}

func unknownReport() *Report {
	r := oneCheckReport(CheckResult{
		ID: "KS-T-001", Display: "P-1", Title: "T", Verdict: VerdictUnknown, Severity: "warn", Fix: "manual",
		Findings: []Finding{
			{Object: load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: "n1"}, Path: "/", Message: "probe denied", Verdict: VerdictUnknown},
		},
	})
	r.Summary = Summary{Unknown: 1, Incomplete: true}
	r.Errors = []string{"node probe: n1: probe denied"}
	return r
}

func pdfText(t *testing.T, r *Report) string {
	t.Helper()
	pdf := renderPDF(t, r)
	newLayoutChecker(t).check(pdfRuns(t, pdf))
	return pdftext.Squash(strings.Join(pdfPages(t, pdf), "\n"))
}

func TestUnknownRendered(t *testing.T) {
	r := unknownReport()
	txt := renderText(t, r)
	for _, want := range []string{
		"\n[UNKNOWN] P-1 KS-T-001 T\n",
		"\n       UNKNOWN Node/n1: probe denied\n",
		"\nSummary: 0 FAIL, 1 UNKNOWN, 0 WARN, 0 PASS, 0 INFO, 0 N/A\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("text misses %q:\n%s", want, txt)
		}
	}
	page := renderHTML(t, r)
	for _, want := range []string{
		`<span class="verdict v-unknown">UNKNOWN</span>`,
		`<article class="check v-unknown"`,
		`<li class="v-unknown"><b>1</b>UNKNOWN</li>`,
		".verdict.v-unknown {",
		".counts .v-unknown {",
		".check.v-unknown {",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML misses %q", want)
		}
	}
	pdf := pdfText(t, r)
	for _, want := range []string{"0 FAIL", "1 UNKNOWN", "0 N/A", "UNKNOWN P-1 KS-T-001 T", "verdict UNKNOWN"} {
		if !strings.Contains(pdf, pdftext.Squash(want)) {
			t.Errorf("PDF misses %q", want)
		}
	}
	whole := 0
	for _, p := range pdfRuns(t, renderPDF(t, r)) {
		for _, run := range p {
			if run.Text == VerdictUnknown {
				whole++
			}
		}
	}
	if whole != 3 {
		t.Errorf("PDF has %d runs that are exactly UNKNOWN, want 3 (check row, finding head, verdict field)", whole)
	}
	if verdictRGB(VerdictUnknown) == verdictRGB(VerdictNA) || verdictClass(VerdictUnknown) != "v-unknown" {
		t.Error("UNKNOWN needs its own colour and class")
	}

	clean := sampleReport()
	if txt := renderText(t, clean); strings.Contains(txt, "UNKNOWN") {
		t.Errorf("text without UNKNOWN shows it:\n%s", txt)
	}
	if page := renderHTML(t, clean); strings.Contains(page, "UNKNOWN") || strings.Contains(page, "v-unknown") {
		t.Error("HTML without UNKNOWN shows it")
	}
	if pdf := pdfText(t, clean); strings.Contains(pdf, "UNKNOWN") {
		t.Error("PDF without UNKNOWN shows it")
	}
}

func clusterReport() *Report {
	r := sampleReport()
	r.Scan.Mode = ModeCluster
	r.Scan.Inputs = []string{}
	r.Scan.InputDigests = []load.Digest{}
	r.Scan.Cluster = &ClusterInfo{
		Context:        "kind-kshield-test",
		Server:         "https://127.0.0.1:6443",
		Namespaces:     []string{"ai", "ai-batch"},
		NodeProbe:      true,
		ProbeNamespace: "kshield-probe",
	}
	return r
}

func TestClusterInfoRendered(t *testing.T) {
	r := clusterReport()
	txt := renderText(t, r)
	if want := "\ncluster: context kind-kshield-test | server https://127.0.0.1:6443 | namespaces ai, ai-batch | node probe on (namespace kshield-probe)\n"; !strings.Contains(txt, want) {
		t.Errorf("text misses %q:\n%s", want, txt)
	}
	if !strings.Contains(txt, "| cluster scan |") {
		t.Errorf("text misses the cluster mode:\n%s", txt)
	}
	page := renderHTML(t, r)
	for _, want := range []string{
		"<tr><th>Mode</th><td>cluster</td></tr>",
		"<tr><th>Context</th><td><code>kind-kshield-test</code></td></tr>",
		"<tr><th>Server</th><td><code>https://127.0.0.1:6443</code></td></tr>",
		"<tr><th>Namespaces</th><td>ai, ai-batch</td></tr>",
		"<tr><th>Node probe</th><td>on (namespace kshield-probe)</td></tr>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML misses %q", want)
		}
	}
	pdf := pdfText(t, r)
	for _, want := range []string{"Mode cluster", "Context kind-kshield-test", "Server https://127.0.0.1:6443", "Namespaces ai, ai-batch", "Node probe on (namespace kshield-probe)"} {
		if !strings.Contains(pdf, pdftext.Squash(want)) {
			t.Errorf("PDF misses %q", want)
		}
	}
	for _, absent := range []string{"Inputs", "Input files"} {
		if strings.Contains(page, "<th>"+absent+"</th>") || strings.Contains(pdf, pdftext.Squash(absent)) {
			t.Errorf("cluster scan box shows %q", absent)
		}
	}

	r.Scan.Cluster = &ClusterInfo{Context: "c", Server: "s"}
	txt = renderText(t, r)
	if want := "\ncluster: context c | server s | namespaces all | node probe off\n"; !strings.Contains(txt, want) {
		t.Errorf("text misses %q:\n%s", want, txt)
	}
	page = renderHTML(t, r)
	for _, want := range []string{"<tr><th>Namespaces</th><td>all</td></tr>", "<tr><th>Node probe</th><td>off</td></tr>"} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML misses %q", want)
		}
	}
	pdf = pdfText(t, r)
	for _, want := range []string{"Namespaces all", "Node probe off"} {
		if !strings.Contains(pdf, pdftext.Squash(want)) {
			t.Errorf("PDF misses %q", want)
		}
	}
	if txt := renderText(t, sampleReport()); strings.Contains(txt, "cluster:") {
		t.Errorf("manifest text shows cluster info:\n%s", txt)
	}
}

func TestJSONClusterInfo(t *testing.T) {
	r := clusterReport()
	r.Scan.Cluster.Namespaces = nil
	r.Summary.Unknown = 2
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Scan struct {
			Inputs       []any          `json:"inputs"`
			InputDigests []any          `json:"inputDigests"`
			Cluster      map[string]any `json:"cluster"`
		} `json:"scan"`
		Summary map[string]any `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"context":        "kind-kshield-test",
		"server":         "https://127.0.0.1:6443",
		"namespaces":     []any{},
		"nodeProbe":      true,
		"probeNamespace": "kshield-probe",
	}
	if !reflect.DeepEqual(raw.Scan.Cluster, want) {
		t.Fatalf("scan.cluster = %#v, want %#v", raw.Scan.Cluster, want)
	}
	if raw.Scan.Inputs == nil || len(raw.Scan.Inputs) != 0 || raw.Scan.InputDigests == nil || len(raw.Scan.InputDigests) != 0 {
		t.Fatalf("inputs = %#v, inputDigests = %#v, want []", raw.Scan.Inputs, raw.Scan.InputDigests)
	}
	if raw.Summary["unknown"] != float64(2) {
		t.Fatalf("summary.unknown = %#v", raw.Summary["unknown"])
	}
	if r.Scan.Cluster.Namespaces != nil {
		t.Fatal("WriteJSON must not change the report it is given")
	}

	r.Scan.Cluster.NodeProbe = false
	r.Scan.Cluster.ProbeNamespace = ""
	r.Scan.Cluster.Namespaces = []string{"ai"}
	buf.Reset()
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "probeNamespace") {
		t.Error("empty probeNamespace is written")
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&back, r) {
		t.Fatalf("round trip changed the report:\n got %+v\nwant %+v", back.Scan, r.Scan)
	}
}

func TestJSONManifestOmitsClusterAndUnknown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"cluster"`, `"unknown"`} {
		if strings.Contains(buf.String(), key) {
			t.Errorf("manifest report has %s", key)
		}
	}
}
