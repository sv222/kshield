package corpus

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadSpecText(t *testing.T, content string) (Spec, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "expected.yaml")
	writeFile(t, path, content)
	return LoadSpec(path)
}

func TestLoadSpec(t *testing.T) {
	spec, err := loadSpecText(t, `namespace: ai-inference
checks: [KS-WL-001, KS-WL-002]
expect:
  - {check: KS-WL-001, object: Deployment/ai-inference/vllm, container: vllm, verdict: FAIL}
  - {check: KS-WL-002, object: RayCluster/ai-inference/rc, group: head, verdict: WARN}
na: [KS-PRE-001]
`)
	if err != nil {
		t.Fatal(err)
	}
	want := Spec{
		Namespace: "ai-inference",
		Checks:    []string{"KS-WL-001", "KS-WL-002"},
		Expect: []Expect{
			{Check: "KS-WL-001", Object: "Deployment/ai-inference/vllm", Container: "vllm", Verdict: "FAIL"},
			{Check: "KS-WL-002", Object: "RayCluster/ai-inference/rc", Group: "head", Verdict: "WARN"},
		},
		NA: []string{"KS-PRE-001"},
	}
	if !reflect.DeepEqual(spec, want) {
		t.Fatalf("got %+v want %+v", spec, want)
	}
}

func TestLoadSpecChecksAll(t *testing.T) {
	spec, err := loadSpecText(t, "namespace: ns\nchecks: all\nexpect: []\nna: []\n")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Checks != nil {
		t.Fatalf("checks: all must give nil, got %#v", spec.Checks)
	}
}

func TestLoadSpecOptionalFields(t *testing.T) {
	spec, err := loadSpecText(t, "checks: [KS-WL-001]\n")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Namespace != "" || len(spec.Expect) != 0 || len(spec.NA) != 0 {
		t.Fatalf("got %+v", spec)
	}
}

func TestLoadSpecErrors(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"missing checks", "namespace: ns\nexpect: []\n", "checks"},
		{"empty checks", "checks: []\n", "checks"},
		{"checks word", "checks: some\n", "checks"},
		{"checks number", "checks: 3\n", "checks"},
		{"checks null", "checks:\n", "checks"},
		{"unknown field", "checks: all\nexpects: []\n", "expects"},
		{"unknown expect field", "checks: all\nexpect:\n  - {check: KS-WL-001, object: Pod/x, verdict: FAIL, extra: 1}\n", "extra"},
		{"expect without check", "checks: all\nexpect:\n  - {object: Pod/x, verdict: FAIL}\n", "check"},
		{"expect without object", "checks: all\nexpect:\n  - {check: KS-WL-001, verdict: FAIL}\n", "object"},
		{"bad verdict", "checks: all\nexpect:\n  - {check: KS-WL-001, object: Pod/x, verdict: PASS}\n", "verdict"},
		{"invalid yaml", "checks: [\n", ""},
		{"duplicate key", "checks: all\nchecks: all\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSpecText(t, tc.content)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadSpecAcceptsUnknown(t *testing.T) {
	s, err := loadSpecText(t, "checks: all\nexpect:\n  - {check: KS-PRE-004, object: Node/n1, verdict: UNKNOWN}\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Expect) != 1 || s.Expect[0].Verdict != report.VerdictUnknown {
		t.Fatalf("expect = %+v", s.Expect)
	}
}

func TestLoadSpecMissingFile(t *testing.T) {
	if _, err := LoadSpec(filepath.Join(t.TempDir(), "expected.yaml")); err == nil {
		t.Fatal("want an error")
	}
}

func TestLoadSpecErrorNamesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case", "expected.yaml")
	writeFile(t, path, "checks: all\nbogus: 1\n")
	_, err := LoadSpec(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error must name the file: %v", err)
	}
}

func sampleReport() *report.Report {
	dep := load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ai", Name: "vllm"}
	ray := load.ObjectRef{APIVersion: "ray.io/v1", Kind: "RayCluster", Namespace: "ai", Name: "rc"}
	return &report.Report{Checks: []report.CheckResult{
		{ID: "KS-WL-001", Verdict: report.VerdictFail, Findings: []report.Finding{
			{Object: dep, Container: "vllm", Verdict: report.VerdictFail},
			{Object: ray, Group: "head", Container: "ray", Verdict: report.VerdictWarn},
		}},
		{ID: "KS-WL-002", Verdict: report.VerdictInfo, Findings: []report.Finding{{Object: dep, Verdict: report.VerdictInfo}}},
		{ID: "KS-WL-003", Verdict: report.VerdictPass},
		{ID: "KS-PRE-001", Verdict: report.VerdictNA},
	}}
}

func TestActual(t *testing.T) {
	got := Actual(sampleReport(), nil)
	want := []Expect{
		{Check: "KS-WL-001", Object: "Deployment/ai/vllm", Container: "vllm", Verdict: "FAIL"},
		{Check: "KS-WL-001", Object: "RayCluster/ai/rc", Group: "head", Container: "ray", Verdict: "WARN"},
		{Check: "KS-WL-002", Object: "Deployment/ai/vllm", Verdict: "INFO"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestActualFiltersChecks(t *testing.T) {
	got := Actual(sampleReport(), []string{"KS-WL-002", "KS-WL-003"})
	if len(got) != 1 || got[0].Check != "KS-WL-002" {
		t.Fatalf("got %+v", got)
	}
	if got := Actual(sampleReport(), []string{"KS-NONE-001"}); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestDiff(t *testing.T) {
	a := Expect{Check: "KS-WL-001", Object: "Pod/ns/a", Verdict: "FAIL"}
	b := Expect{Check: "KS-WL-001", Object: "Pod/ns/b", Verdict: "FAIL"}
	c := Expect{Check: "KS-WL-001", Object: "Pod/ns/c", Container: "x", Verdict: "WARN"}
	d := Expect{Check: "KS-WL-002", Object: "Pod/ns/a", Group: "g", Verdict: "INFO"}

	missing, extra := Diff([]Expect{a, b, c}, []Expect{c, d, a})
	if !slices.Equal(missing, []Expect{b}) || !slices.Equal(extra, []Expect{d}) {
		t.Fatalf("missing=%+v extra=%+v", missing, extra)
	}

	missing, extra = Diff([]Expect{a, b}, []Expect{b, a})
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("order must not matter: missing=%+v extra=%+v", missing, extra)
	}

	missing, extra = Diff(nil, nil)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("missing=%+v extra=%+v", missing, extra)
	}
}

func TestDiffMultisetSemantics(t *testing.T) {
	a := Expect{Check: "KS-WL-001", Object: "Pod/ns/a", Verdict: "FAIL"}
	b := Expect{Check: "KS-WL-001", Object: "Pod/ns/b", Verdict: "FAIL"}
	missing, extra := Diff([]Expect{a}, []Expect{a, a})
	if len(missing) != 0 || !slices.Equal(extra, []Expect{a}) {
		t.Fatalf("a repeat in got must be extra: missing=%+v extra=%+v", missing, extra)
	}
	missing, extra = Diff([]Expect{a, a}, nil)
	if !slices.Equal(missing, []Expect{a, a}) || len(extra) != 0 {
		t.Fatalf("each repeat in want must be missing: missing=%+v extra=%+v", missing, extra)
	}
	missing, extra = Diff([]Expect{a, a, b}, []Expect{b, a, a})
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("equal multisets: missing=%+v extra=%+v", missing, extra)
	}
	missing, extra = Diff([]Expect{a, a, b}, []Expect{a, b, b})
	if !slices.Equal(missing, []Expect{a}) || !slices.Equal(extra, []Expect{b}) {
		t.Fatalf("missing=%+v extra=%+v", missing, extra)
	}
}

func TestDiffEveryFieldCounts(t *testing.T) {
	base := Expect{Check: "KS-WL-001", Object: "Pod/ns/a", Group: "g", Container: "c", Verdict: "FAIL"}
	variants := []Expect{base, base, base, base, base}
	variants[0].Check = "KS-WL-002"
	variants[1].Object = "Pod/ns/b"
	variants[2].Group = "h"
	variants[3].Container = "d"
	variants[4].Verdict = "WARN"
	for i, v := range variants {
		missing, extra := Diff([]Expect{base}, []Expect{v})
		if len(missing) != 1 || len(extra) != 1 {
			t.Errorf("variant %d: missing=%+v extra=%+v", i, missing, extra)
		}
	}
}

func TestExpectString(t *testing.T) {
	e := Expect{Check: "KS-WL-001", Object: "Deployment/ns/d", Container: "c", Verdict: "FAIL"}
	if got, want := e.String(), "{check: KS-WL-001, object: Deployment/ns/d, container: c, verdict: FAIL}"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	e.Group = "head"
	if got, want := e.String(), "{check: KS-WL-001, object: Deployment/ns/d, group: head, container: c, verdict: FAIL}"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNAMismatches(t *testing.T) {
	r := sampleReport()
	if got := NAMismatches(r, []string{"KS-PRE-001"}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	got := NAMismatches(r, []string{"KS-WL-001", "KS-WL-003", "KS-NONE-001", "KS-PRE-001"})
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	for i, id := range []string{"KS-WL-001", "KS-WL-003", "KS-NONE-001"} {
		if !strings.Contains(got[i], id) {
			t.Errorf("message %d %q does not name %s", i, got[i], id)
		}
	}
	if !strings.Contains(got[0], "FAIL") || !strings.Contains(got[1], "PASS") || !strings.Contains(got[2], "not in the report") {
		t.Errorf("messages must say what was found: %v", got)
	}
}

func TestUnknownChecks(t *testing.T) {
	r := sampleReport()
	if got := UnknownChecks(r, nil); len(got) != 0 {
		t.Fatalf("all checks: got %v", got)
	}
	if got := UnknownChecks(r, []string{"KS-WL-001", "KS-PRE-001"}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	got := UnknownChecks(r, []string{"KS-WL-001", "KS-TYPO-001", "KS-WL-999"})
	if !slices.Equal(got, []string{"KS-TYPO-001", "KS-WL-999"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCases(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "README.md"), "x")
	writeFile(t, filepath.Join(root, "b", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "a", "nested", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "a", "other", "input.yaml"), "x")
	writeFile(t, filepath.Join(root, "charts", "charts.yaml"), "x")
	got, err := Cases(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "a", "nested"), filepath.Join(root, "b")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCasesMissingRoot(t *testing.T) {
	if _, err := Cases(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("want an error")
	}
}

func TestInputPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "plain", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "plain", "input.yaml"), "x")
	writeFile(t, filepath.Join(root, "chart", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "chart", "rendered.yaml"), "x")
	writeFile(t, filepath.Join(root, "none", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "both", "expected.yaml"), "checks: all\n")
	writeFile(t, filepath.Join(root, "both", "input.yaml"), "x")
	writeFile(t, filepath.Join(root, "both", "rendered.yaml"), "x")

	if got, err := InputPath(filepath.Join(root, "plain")); err != nil || got != filepath.Join(root, "plain", "input.yaml") {
		t.Errorf("plain: %q %v", got, err)
	}
	if got, err := InputPath(filepath.Join(root, "chart")); err != nil || got != filepath.Join(root, "chart", "rendered.yaml") {
		t.Errorf("chart: %q %v", got, err)
	}
	dir := filepath.Join(root, "none")
	_, err := InputPath(dir)
	if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "input.yaml") || !strings.Contains(err.Error(), "rendered.yaml") {
		t.Errorf("none: %v", err)
	}
	dir = filepath.Join(root, "both")
	_, err = InputPath(dir)
	if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "both") {
		t.Errorf("both: %v", err)
	}
}

func TestLoadResiduals(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ResidualFile), `residuals:
  - {check: KS-WL-001, object: Deployment/ai-inference/ollama, container: ollama, mode: both}
  - {check: KS-NET-002, object: NetworkPolicy/ai-inference/open, mode: audit}
`)
	got, err := LoadResiduals(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Residual{
		{Check: "KS-WL-001", Object: "Deployment/ai-inference/ollama", Container: "ollama", Mode: ModeBoth},
		{Check: "KS-NET-002", Object: "NetworkPolicy/ai-inference/open", Mode: ModeAudit},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if !got[0].In(ModeEnforce) || !got[0].In(ModeAudit) || got[1].In(ModeEnforce) || !got[1].In(ModeAudit) {
		t.Fatalf("mode match wrong: %+v", got)
	}
}

func TestLoadResidualsMissingFile(t *testing.T) {
	got, err := LoadResiduals(t.TempDir())
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want none", got, err)
	}
}

func TestLoadResidualsErrors(t *testing.T) {
	cases := map[string]string{
		"unknown field": "residuals:\n  - {check: KS-WL-001, object: Deployment/a/b, mode: both, verdict: FAIL}\n",
		"no check":      "residuals:\n  - {object: Deployment/a/b, mode: both}\n",
		"no object":     "residuals:\n  - {check: KS-WL-001, mode: both}\n",
		"no mode":       "residuals:\n  - {check: KS-WL-001, object: Deployment/a/b}\n",
		"bad mode":      "residuals:\n  - {check: KS-WL-001, object: Deployment/a/b, mode: always}\n",
		"top level":     "- {check: KS-WL-001, object: Deployment/a/b, mode: both}\n",
	}
	for name, content := range cases {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, ResidualFile), content)
		if _, err := LoadResiduals(dir); err == nil || !strings.Contains(err.Error(), ResidualFile) {
			t.Errorf("%s: err %v, want an error that names %s", name, err, ResidualFile)
		}
	}
}
