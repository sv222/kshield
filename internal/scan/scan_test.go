package scan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/version"
)

const (
	vllmDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai
spec:
  selector:
    matchLabels:
      app: vllm
  template:
    metadata:
      labels:
        app: vllm
    spec:
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.0
`
	configMap = `apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
  namespace: ai
data:
  k: v
`
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindingVerdict(t *testing.T) {
	cases := []struct {
		sev  profile.Severity
		s    check.Strength
		want string
	}{
		{profile.SevFail, check.Violation, "FAIL"},
		{profile.SevWarn, check.Violation, "WARN"},
		{profile.SevInfo, check.Violation, "INFO"},
		{profile.SevFail, check.Suspect, "WARN"},
		{profile.SevWarn, check.Suspect, "WARN"},
		{profile.SevInfo, check.Suspect, "INFO"},
	}
	for _, tc := range cases {
		if got := FindingVerdict(tc.sev, tc.s); got != tc.want {
			t.Errorf("FindingVerdict(%s, %d) = %s, want %s", tc.sev, tc.s, got, tc.want)
		}
	}
}

func TestFindingVerdictUnknown(t *testing.T) {
	for _, sev := range []profile.Severity{profile.SevFail, profile.SevWarn, profile.SevInfo} {
		if got := FindingVerdict(sev, check.Unknown); got != report.VerdictUnknown {
			t.Errorf("FindingVerdict(%s, Unknown) = %s, want UNKNOWN", sev, got)
		}
	}
}

func TestWorstUnknownRank(t *testing.T) {
	fs := func(vs ...string) []report.Finding {
		out := make([]report.Finding, len(vs))
		for i, v := range vs {
			out[i] = report.Finding{Verdict: v}
		}
		return out
	}
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"WARN", "UNKNOWN"}, "UNKNOWN"},
		{[]string{"UNKNOWN", "WARN"}, "UNKNOWN"},
		{[]string{"UNKNOWN", "FAIL"}, "FAIL"},
		{[]string{"INFO", "UNKNOWN"}, "UNKNOWN"},
		{[]string{"UNKNOWN"}, "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := worst(fs(tc.in...)); got != tc.want {
			t.Errorf("worst(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
	for v, want := range map[string]int{"FAIL": 4, "UNKNOWN": 3, "WARN": 2, "INFO": 1, "PASS": 0} {
		if got := rank(v); got != want {
			t.Errorf("rank(%s) = %d, want %d", v, got, want)
		}
	}
}

func TestSummarizeCountsUnknown(t *testing.T) {
	got := summarize([]report.CheckResult{{Verdict: "UNKNOWN"}, {Verdict: "UNKNOWN"}, {Verdict: "FAIL"}, {Verdict: "N/A"}})
	want := report.Summary{Fail: 1, Unknown: 2, NA: 1}
	if got != want {
		t.Fatalf("summarize = %+v, want %+v", got, want)
	}
}

func testProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Parse([]byte(`id: test
version: 7
title: Test profile
checks:
  KS-T-001: {display: T-1, severity: fail, refs: [dora-art9-4-c, dora-art9-2]}
  KS-T-002: {display: T-2, severity: warn, refs: [dora-art9-3-a]}
  KS-T-003: {display: T-3, severity: info, refs: [dora-art9-3-a]}
  KS-T-004: {display: T-4, severity: fail, refs: [dora-art9-2]}
  KS-T-005: {display: T-5, severity: fail, refs: [dora-art10-1]}
  KS-T-006: {display: T-6, severity: warn, refs: [dora-art10-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func emptyProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Parse([]byte("id: empty\nversion: 1\ntitle: Empty\nchecks: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func obj(kind, name string) load.ObjectRef {
	return load.ObjectRef{APIVersion: "apps/v1", Kind: kind, Namespace: "ai", Name: name}
}

func testChecks(seen **check.Input) []check.Check {
	return []check.Check{
		{ID: "KS-T-001", Title: "first", Tier: check.Manifest, Fix: check.FixPatch, Run: func(*check.Input) check.Result {
			return check.Result{Applicable: true, Findings: []check.Finding{
				{Object: obj("Deployment", "b"), Message: "suspect", Strength: check.Suspect},
				{Object: obj("Deployment", "a"), Container: "c", Group: "g", Path: "/p", Message: "violation", Strength: check.Violation},
			}}
		}},
		{ID: "KS-T-002", Title: "second", Tier: check.Manifest, Fix: check.FixPolicy, Run: func(*check.Input) check.Result {
			return check.Result{Applicable: true, Findings: []check.Finding{{Object: obj("Deployment", "a"), Message: "m", Strength: check.Suspect}}}
		}},
		{ID: "KS-T-003", Title: "third", Tier: check.Manifest, Fix: check.FixManual, Run: func(*check.Input) check.Result {
			return check.Result{Applicable: true, Findings: []check.Finding{{Object: obj("Deployment", "a"), Message: "m", Strength: check.Violation}}}
		}},
		{ID: "KS-T-004", Title: "fourth", Tier: check.Manifest, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
			*seen = in
			return check.Result{Applicable: true}
		}},
		{ID: "KS-T-005", Title: "fifth", Tier: check.Cluster, Fix: check.FixManual, Run: func(*check.Input) check.Result {
			return check.Result{Applicable: true, Findings: []check.Finding{{Message: "must not run"}}}
		}},
		{ID: "KS-T-006", Title: "sixth", Tier: check.Manifest, Fix: check.FixPatch, Run: func(*check.Input) check.Result {
			return check.Result{Findings: []check.Finding{{Message: "dropped"}}}
		}},
	}
}

func TestManifestOrchestration(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "in.yaml", vllmDeployment+"---\n"+configMap)
	var seen *check.Input
	r, err := manifest(Options{Inputs: []string{path}, Namespace: "ai", Deterministic: true}, testProfile(t), testChecks(&seen))
	if err != nil {
		t.Fatal(err)
	}

	if r.SchemaVersion != "kshield.report/v1" {
		t.Errorf("schemaVersion %q", r.SchemaVersion)
	}
	if r.Profile.ID != "test" || r.Profile.Version != 7 || r.Profile.Title != "Test profile" || len(r.Profile.SHA256) != 64 {
		t.Errorf("profile %+v", r.Profile)
	}
	if seen == nil {
		t.Fatal("check KS-T-004 did not run")
	}
	if len(seen.Objects) != 2 || len(seen.Workloads) != 1 || seen.Cluster != nil {
		t.Errorf("checks got %d objects, %d workloads, cluster %v", len(seen.Objects), len(seen.Workloads), seen.Cluster)
	}

	type want struct {
		id, display, verdict, severity, fix string
		findings                            []string
	}
	wants := []want{
		{"KS-T-001", "T-1", "FAIL", "fail", "patch", []string{"FAIL", "WARN"}},
		{"KS-T-002", "T-2", "WARN", "warn", "policy", []string{"WARN"}},
		{"KS-T-003", "T-3", "INFO", "info", "manual", []string{"INFO"}},
		{"KS-T-004", "T-4", "PASS", "fail", "patch", nil},
		{"KS-T-005", "T-5", "N/A", "fail", "manual", nil},
		{"KS-T-006", "T-6", "N/A", "warn", "patch", nil},
	}
	if len(r.Checks) != len(wants) {
		t.Fatalf("got %d checks", len(r.Checks))
	}
	for i, w := range wants {
		c := r.Checks[i]
		var verdicts []string
		for _, f := range c.Findings {
			verdicts = append(verdicts, f.Verdict)
		}
		if c.ID != w.id || c.Display != w.display || c.Verdict != w.verdict || c.Severity != w.severity || c.Fix != w.fix || !slices.Equal(verdicts, w.findings) {
			t.Errorf("check %d: got %+v, want %+v", i, c, w)
		}
		if c.Findings == nil || c.Refs == nil {
			t.Errorf("%s: Findings and Refs must be non-nil", c.ID)
		}
	}

	first := r.Checks[0]
	if first.Title != "first" {
		t.Errorf("title %q", first.Title)
	}
	if first.Findings[0].Message != "violation" || first.Findings[1].Message != "suspect" {
		t.Errorf("findings must be sorted: %+v", first.Findings)
	}
	f := first.Findings[0]
	if f.Object != obj("Deployment", "a") || f.Group != "g" || f.Container != "c" || f.Path != "/p" {
		t.Errorf("finding fields: %+v", f)
	}
	wantRefs := []report.Ref{
		{ID: "dora-art9-4-c", Label: "DORA Art. 9(4)(c)", Source: "dora", URL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"},
		{ID: "dora-art9-2", Label: "DORA Art. 9(2)", Source: "dora", URL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"},
	}
	if !slices.Equal(first.Refs, wantRefs) {
		t.Errorf("refs: got %+v want %+v", first.Refs, wantRefs)
	}

	if r.Summary != (report.Summary{Pass: 1, Fail: 1, Warn: 1, Info: 1, NA: 2}) {
		t.Errorf("summary %+v", r.Summary)
	}
	if r.Errors == nil || len(r.Errors) != 0 {
		t.Errorf("errors %#v", r.Errors)
	}
}

func TestManifestScanInfo(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "in.yaml", vllmDeployment+"---\n"+configMap)
	r, err := manifest(Options{Inputs: []string{path, "-"}, Namespace: "ai", Stdin: strings.NewReader(configMap + "---\n" + strings.Replace(configMap, "name: cfg", "name: cfg2", 1))}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	slash := filepath.ToSlash(path)
	if r.Scan.Mode != "manifest" || !slices.Equal(r.Scan.Inputs, []string{slash, "-"}) || r.Scan.Namespace != "ai" {
		t.Errorf("scan %+v", r.Scan)
	}
	if r.Scan.Objects != 4 || r.Scan.AIWorkloads != 1 {
		t.Errorf("objects=%d aiWorkloads=%d", r.Scan.Objects, r.Scan.AIWorkloads)
	}
	if r.Checks == nil || len(r.Checks) != 0 {
		t.Errorf("checks %#v", r.Checks)
	}
}

func TestManifestInputsUseForwardSlashes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/in.yaml", configMap)
	r, err := manifest(Options{Inputs: []string{filepath.Join(dir, "a")}}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Scan.Inputs[0]; strings.Contains(got, `\`) {
		t.Fatalf("input %q has a backslash", got)
	}
}

func TestManifestToolAndClock(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "in.yaml", configMap)
	fixed := time.Date(2026, 10, 17, 12, 30, 5, 123, time.FixedZone("x", 3600))
	r, err := manifest(Options{Inputs: []string{path}, Now: func() time.Time { return fixed }}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool.Name != "kshield" || r.Tool.Version != version.Version {
		t.Errorf("tool %+v", r.Tool)
	}
	if r.Scan.StartedAt != "2026-10-17T11:30:05Z" {
		t.Errorf("startedAt %q", r.Scan.StartedAt)
	}

	d, err := manifest(Options{Inputs: []string{path}, Deterministic: true, Now: func() time.Time { return fixed }}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Tool.Version != "0.0.0-deterministic" || d.Scan.StartedAt != "1970-01-01T00:00:00Z" {
		t.Errorf("deterministic: tool %+v startedAt %q", d.Tool, d.Scan.StartedAt)
	}
}

func TestManifestDefaultClock(t *testing.T) {
	path := writeFile(t, t.TempDir(), "in.yaml", configMap)
	before := time.Now().UTC().Add(-time.Second)
	r, err := manifest(Options{Inputs: []string{path}}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, r.Scan.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("startedAt %s is not now", r.Scan.StartedAt)
	}
}

func TestManifestProfileValidation(t *testing.T) {
	path := writeFile(t, t.TempDir(), "in.yaml", configMap)
	noop := func(*check.Input) check.Result { return check.Result{Applicable: true} }

	missing := []check.Check{{ID: "KS-T-099", Title: "x", Tier: check.Manifest, Fix: check.FixPatch, Run: noop}}
	if _, err := manifest(Options{Inputs: []string{path}}, testProfile(t), missing); err == nil || !strings.Contains(err.Error(), "KS-T-099") {
		t.Errorf("check without profile entry: %v", err)
	}

	badRef, err := profile.Parse([]byte("id: bad\nversion: 1\ntitle: t\nchecks:\n  KS-T-001: {display: D, severity: fail, refs: [no-such-excerpt]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	one := []check.Check{{ID: "KS-T-001", Title: "x", Tier: check.Manifest, Fix: check.FixPatch, Run: noop}}
	if _, err := manifest(Options{Inputs: []string{path}}, badRef, one); err == nil || !strings.Contains(err.Error(), "no-such-excerpt") {
		t.Errorf("unknown ref: %v", err)
	}
}

func TestManifestErrors(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.yaml", configMap)
	bad := writeFile(t, dir, "bad.yaml", "kind: ConfigMap\nmetadata:\n  name: x\n")
	missing := filepath.Join(dir, "missing.yaml")

	if _, err := Manifest(Options{Inputs: []string{missing}, ProfileID: "dora"}); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Errorf("missing file: %v", err)
	}
	if _, err := Manifest(Options{Inputs: []string{good, bad}, ProfileID: "dora"}); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("bad manifest: %v", err)
	}
	if _, err := Manifest(Options{Inputs: []string{good}, ProfileID: "nope"}); err == nil || !strings.Contains(err.Error(), `unknown profile "nope"`) {
		t.Errorf("unknown profile: %v", err)
	}
	if _, err := Manifest(Options{Inputs: []string{good}}); err == nil {
		t.Error("empty profile id must fail")
	}
}

func TestManifestDoraProfile(t *testing.T) {
	path := writeFile(t, t.TempDir(), "in.yaml", vllmDeployment)
	r, err := Manifest(Options{Inputs: []string{path}, Namespace: "ai", ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Profile.ID != "dora" || r.Profile.Version != 1 || len(r.Profile.SHA256) != 64 || r.Profile.Title == "" {
		t.Errorf("profile %+v", r.Profile)
	}
	if len(r.Checks) != len(check.All()) {
		t.Errorf("got %d checks, registry has %d", len(r.Checks), len(check.All()))
	}
}

func TestDeterministicJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "in.yaml", vllmDeployment+"---\n"+configMap)
	run := func(now time.Time) []byte {
		t.Helper()
		r, err := Manifest(Options{Inputs: []string{path}, Namespace: "ai", ProfileID: "dora", Deterministic: true, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := report.WriteJSON(&buf, r); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a := run(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	b := run(time.Date(2027, 6, 6, 6, 6, 6, 0, time.UTC))
	if !bytes.Equal(a, b) {
		t.Fatalf("outputs differ:\n%s\n%s", a, b)
	}
	if !bytes.Contains(a, []byte(`"startedAt": "1970-01-01T00:00:00Z"`)) || !bytes.Contains(a, []byte(`"version": "0.0.0-deterministic"`)) {
		t.Fatalf("deterministic markers missing:\n%s", a)
	}
}

func writeCorpus(b *strings.Builder, n int) {
	fmt.Fprintf(b, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-%[1]d
  namespace: ai
spec:
  selector:
    matchLabels:
      app: vllm-%[1]d
  template:
    metadata:
      labels:
        app: vllm-%[1]d
    spec:
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.0
---
apiVersion: v1
kind: Service
metadata:
  name: vllm-%[1]d
  namespace: ai
spec:
  selector:
    app: vllm-%[1]d
  ports:
    - port: 8000
`, n)
	for i := range 3 {
		fmt.Fprintf(b, "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg-%d-%d\n  namespace: ai\ndata:\n  k: v\n", n, i)
	}
}

func TestScan10kObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("10k objects")
	}
	dir := t.TempDir()
	const files, perFile = 10, 200
	for f := range files {
		var b strings.Builder
		for i := range perFile {
			if f > 0 || i > 0 {
				b.WriteString("---\n")
			}
			writeCorpus(&b, f*perFile+i)
		}
		writeFile(t, dir, fmt.Sprintf("part-%02d.yaml", f), b.String())
	}
	start := time.Now()
	r, err := Manifest(Options{Inputs: []string{dir}, Namespace: "ai", ProfileID: "dora", Deterministic: true})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if checkScanTime && elapsed > 30*time.Second {
		t.Errorf("scan took %s, limit is 30s", elapsed)
	}
	if r.Scan.Objects != 10000 || r.Scan.AIWorkloads != 2000 {
		t.Errorf("objects=%d aiWorkloads=%d, want 10000 and 2000", r.Scan.Objects, r.Scan.AIWorkloads)
	}
	t.Logf("scanned %d objects in %s", r.Scan.Objects, elapsed)
}

func TestFindingSource(t *testing.T) {
	t.Chdir("../..")
	const input = "test/corpus/baseline/toxic/input.yaml"
	r, err := Manifest(Options{Inputs: []string{input}, Namespace: "ai-inference", ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	starts := map[string]int{
		"Deployment/ai-inference/vllm":   1,
		"Service/ai-inference/vllm":      43,
		"Deployment/ai-inference/qdrant": 57,
	}
	n := 0
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			n++
			if f.Source == nil {
				t.Errorf("%s %s: no source", c.ID, f.Object)
				continue
			}
			if f.Source.File != input || f.Source.Line <= 0 {
				t.Errorf("%s %s: source %+v", c.ID, f.Object, *f.Source)
			}
			if want, ok := starts[f.Object.String()]; ok && f.Source.Line != want {
				t.Errorf("%s %s: line %d, want %d", c.ID, f.Object, f.Source.Line, want)
			}
		}
	}
	if n == 0 {
		t.Fatal("toxic baseline gave no findings")
	}
	if len(r.Scan.InputDigests) != 1 || r.Scan.InputDigests[0].Path != input || len(r.Scan.InputDigests[0].SHA256) != 64 {
		t.Errorf("inputDigests %+v", r.Scan.InputDigests)
	}
}

func TestFindingSourceFirstOccurrence(t *testing.T) {
	named := func(name string) string {
		return strings.Replace(vllmDeployment, "  name: vllm\n", "  name: "+name+"\n", 1)
	}
	path := writeFile(t, t.TempDir(), "in.yaml", named("a")+"---\n"+named("b")+"---\n"+named("a"))
	p, err := profile.Parse([]byte("id: one\nversion: 1\ntitle: One\nchecks:\n  KS-T-001: {display: T-1, severity: fail, refs: [dora-art9-2]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Manifest, Fix: check.FixPatch, Run: func(*check.Input) check.Result {
		return check.Result{Applicable: true, Findings: []check.Finding{
			{Object: obj("Deployment", "a"), Message: "a", Strength: check.Violation},
			{Object: obj("Deployment", "b"), Message: "b", Strength: check.Violation},
			{Object: obj("Deployment", "zzz"), Message: "not in input", Strength: check.Violation},
		}}
	}}}
	r, err := manifest(Options{Inputs: []string{path}, Deterministic: true}, p, checks)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.ToSlash(path)
	want := map[string]*report.Source{
		"a":   {File: file, Line: 1},
		"b":   {File: file, Line: 19},
		"zzz": nil,
	}
	fs := r.Checks[0].Findings
	if len(fs) != 3 {
		t.Fatalf("got %d findings", len(fs))
	}
	for _, f := range fs {
		w := want[f.Object.Name]
		switch {
		case w == nil && f.Source != nil:
			t.Errorf("%s: source %+v, want none", f.Object.Name, *f.Source)
		case w != nil && (f.Source == nil || *f.Source != *w):
			t.Errorf("%s: source %v, want %+v", f.Object.Name, f.Source, *w)
		}
	}
	if fs[0].Source != nil && fs[0].Source == fs[1].Source {
		t.Error("findings must not share a source pointer")
	}
}

func TestManifestInputDigests(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "in.yaml", configMap)
	r, err := manifest(Options{Inputs: []string{path, "-"}, Stdin: strings.NewReader(strings.Replace(configMap, "name: cfg", "name: cfg2", 1))}, emptyProfile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []load.Digest{
		{Path: filepath.ToSlash(path), SHA256: "286156517ddf267db37755ecbc8f314880604b3081fd27e33f678cc97816b33f"},
		{Path: "-", SHA256: "eaedad18bd2ed14b921aaa765472c4a03a58abf89c1ccb2dc2eba6741912ed85"},
	}
	if !slices.Equal(r.Scan.InputDigests, want) {
		t.Errorf("inputDigests = %+v, want %+v", r.Scan.InputDigests, want)
	}
}

func TestSourceOfNeedsALine(t *testing.T) {
	ref := obj("Deployment", "a")
	if s := sourceOf(map[load.ObjectRef]report.Source{ref: {File: "a.yaml", Line: 0}}, ref); s != nil {
		t.Errorf("line 0 gave source %+v, want none", *s)
	}
	if s := sourceOf(map[load.ObjectRef]report.Source{ref: {File: "a.yaml", Line: 4}}, ref); s == nil || *s != (report.Source{File: "a.yaml", Line: 4}) {
		t.Errorf("source = %v", s)
	}
}
