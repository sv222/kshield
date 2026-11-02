package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/claimcheck"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
	"github.com/sv222/kshield/internal/report"
)

const (
	vllmDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
spec:
  selector:
    matchLabels:
      app: vllm
  template:
    metadata:
      labels:
        app: vllm
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: vllm
          image: vllm/vllm-openai@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          args: ["--model", "/models/llama", "--load-format", "safetensors", "--api-key", "$(VLLM_API_KEY)"]
          env:
            - name: VLLM_API_KEY
              valueFrom:
                secretKeyRef:
                  name: vllm-api
                  key: key
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              memory: 32Gi
`
	rootVLLMDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
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
	guardPolicies = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress
spec:
  podSelector: {}
  policyTypes: ["Egress"]
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: shell-exec
  labels:
    kshield.io/guard: shell-exec
spec:
  kprobes:
    - call: sys_execve
      selectors:
        - matchActions:
            - action: Sigkill
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: egress-connect
  labels:
    kshield.io/guard: egress-connect
spec:
  kprobes:
    - call: tcp_connect
      selectors:
        - matchActions:
            - action: Sigkill
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: admission
  labels:
    kshield.io/guard: admission
spec:
  validationFailureAction: Enforce
  rules:
    - name: r
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        pattern:
          spec: {}
`
	cleanVLLM = vllmDeployment + "---\n" + guardPolicies
	configMap = `apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  k: v
`
)

func writeManifest(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionCommand(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"version"}, nil, &out, &errb)
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if !regexp.MustCompile(`^kshield dev \(none\) [a-z0-9]+/[a-z0-9]+\n$`).MatchString(out.String()) {
		t.Fatalf("out=%q", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"frobnicate"}, nil, &out, &errb); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Fatalf("stderr=%q", errb.String())
	}
}

func TestNoArgsPrintsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(nil, nil, &out, &errb); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(errb.String(), "kshield scan manifest") {
		t.Fatalf("stderr=%q", errb.String())
	}
}

func TestHelpPrintsUsageToStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			code, out, errs := run(t, "", arg)
			if code != ExitOK || errs != "" || !strings.Contains(out, "kshield scan manifest") || !strings.Contains(out, "exit codes:") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
			}
		})
	}
}

func TestScanManifestNoObjects(t *testing.T) {
	empty := writeManifest(t, "empty.yaml", "---\n# nothing\n---\n")
	code, out, errs := run(t, "", "scan", "manifest", "-f", empty)
	want := "kshield: no Kubernetes objects found in " + filepath.ToSlash(empty) + "\n"
	if code != ExitUsage || out != "" || errs != want {
		t.Fatalf("code=%d stdout=%q stderr=%q, want stderr %q", code, out, errs, want)
	}
	dir := t.TempDir()
	code, _, errs = run(t, "", "scan", "manifest", "-f", dir, "-f", empty)
	if code != ExitUsage || !strings.Contains(errs, "no Kubernetes objects found in "+filepath.ToSlash(dir)+", "+filepath.ToSlash(empty)) {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
}

func TestScanManifestNoAIWorkloadsNote(t *testing.T) {
	path := writeManifest(t, "in.yaml", configMap)
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--deterministic")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	header := "kshield 0.0.0-deterministic | profile dora v1 | manifest scan | 1 objects, 0 AI workloads\nnote: no AI workloads found; all checks are N/A\n\n"
	if !strings.HasPrefix(out, header) {
		t.Fatalf("stdout=%q", out)
	}
	code, out, _ = run(t, "", "scan", "manifest", "-f", path, "--format", "json", "--deterministic")
	if code != ExitOK || strings.Contains(out, "note:") {
		t.Fatalf("code=%d json must not carry the text note: %q", code, out)
	}
}

func TestScanManifestFlags(t *testing.T) {
	good := writeManifest(t, "in.yaml", configMap)
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no -f", []string{"scan", "manifest"}, "-f"},
		{"empty -f", []string{"scan", "manifest", "-f", ""}, "-f"},
		{"format pdf without --out", []string{"scan", "manifest", "-f", good, "--format", "pdf"}, "kshield: --format pdf needs --out\n"},
		{"format pdf without --out or -f", []string{"scan", "manifest", "--format", "pdf"}, "kshield: --format pdf needs --out\n"},
		{"format html without -f", []string{"scan", "manifest", "--format", "html"}, "-f"},
		{"format unknown", []string{"scan", "manifest", "-f", good, "--format", "xml"}, `unknown format "xml"`},
		{"fail-on maybe", []string{"scan", "manifest", "-f", good, "--fail-on", "maybe"}, "maybe"},
		{"missing file", []string{"scan", "manifest", "-f", missing}, "missing.yaml"},
		{"unknown profile", []string{"scan", "manifest", "-f", good, "--profile", "nope"}, `unknown profile "nope"`},
		{"unknown flag", []string{"scan", "manifest", "-f", good, "--bogus"}, "bogus"},
		{"positional argument", []string{"scan", "manifest", "-f", good, "extra"}, `"extra"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, "", tc.args...)
			if code != ExitUsage {
				t.Fatalf("code=%d", code)
			}
			if out != "" {
				t.Fatalf("stdout=%q", out)
			}
			if !strings.Contains(errs, tc.want) {
				t.Fatalf("stderr=%q does not contain %q", errs, tc.want)
			}
		})
	}
}

func TestScanManifestBadManifest(t *testing.T) {
	bad := writeManifest(t, "bad.yaml", "kind: ConfigMap\nmetadata:\n  name: x\n")
	code, out, errs := run(t, "", "scan", "manifest", "-f", bad)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "bad.yaml") || !strings.Contains(errs, "apiVersion") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanManifestHelp(t *testing.T) {
	code, out, errs := run(t, "", "scan", "manifest", "-h")
	if code != ExitOK || out != "" || !strings.Contains(errs, "kshield scan manifest") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanManifestText(t *testing.T) {
	path := writeManifest(t, "in.yaml", cleanVLLM+"---\n"+configMap)
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--deterministic")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	header := "kshield 0.0.0-deterministic | profile dora v1 | manifest scan | 6 objects, 1 AI workloads\n\n"
	if !strings.HasPrefix(out, header) {
		t.Fatalf("stdout=%q", out)
	}
	if !strings.HasSuffix(out, "\n") || !strings.Contains(out, "\nSummary: 0 FAIL, ") {
		t.Fatalf("stdout=%q", out)
	}
}

func TestScanManifestJSON(t *testing.T) {
	path := writeManifest(t, "in.yaml", cleanVLLM+"---\n"+configMap)
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", "json", "--deterministic", "-n", "ai")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Fatalf("stdout must end with a newline: %q", out[max(0, len(out)-10):])
	}
	var r report.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.SchemaVersion != "kshield.report/v1" || r.Tool.Version != "0.0.0-deterministic" || r.Profile.ID != "dora" {
		t.Errorf("report header: %+v %+v %+v", r.SchemaVersion, r.Tool, r.Profile)
	}
	if r.Scan.Mode != "manifest" || r.Scan.Namespace != "ai" || r.Scan.Objects != 6 || r.Scan.AIWorkloads != 1 || r.Scan.StartedAt != "1970-01-01T00:00:00Z" {
		t.Errorf("scan: %+v", r.Scan)
	}
	if len(r.Scan.Inputs) != 1 || r.Scan.Inputs[0] != filepath.ToSlash(path) {
		t.Errorf("inputs: %v", r.Scan.Inputs)
	}
}

func TestScanManifestNamespaceFlags(t *testing.T) {
	path := writeManifest(t, "in.yaml", configMap)
	cases := []struct {
		args []string
		want string
	}{
		{nil, "default"},
		{[]string{"-n", "a"}, "a"},
		{[]string{"--namespace", "b"}, "b"},
		{[]string{"--namespace=c"}, "c"},
	}
	for _, tc := range cases {
		args := append([]string{"scan", "manifest", "-f", path, "--format", "json"}, tc.args...)
		code, out, errs := run(t, "", args...)
		if code != ExitOK {
			t.Fatalf("%v: code=%d stderr=%q", tc.args, code, errs)
		}
		var r report.Report
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		if r.Scan.Namespace != tc.want {
			t.Errorf("%v: namespace %q, want %q", tc.args, r.Scan.Namespace, tc.want)
		}
	}
}

func TestScanManifestRepeatedInputs(t *testing.T) {
	a := writeManifest(t, "a.yaml", cleanVLLM)
	b := writeManifest(t, "b.yaml", configMap)
	code, out, errs := run(t, configMap+"---\n"+strings.Replace(configMap, "name: cfg", "name: other", 1),
		"scan", "manifest", "-f", a, "-f", b, "-f", "-", "--format", "json")
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Scan.Objects != 8 || r.Scan.AIWorkloads != 1 {
		t.Errorf("objects=%d aiWorkloads=%d", r.Scan.Objects, r.Scan.AIWorkloads)
	}
	want := []string{filepath.ToSlash(a), filepath.ToSlash(b), "-"}
	if strings.Join(r.Scan.Inputs, "|") != strings.Join(want, "|") {
		t.Errorf("inputs %v, want %v", r.Scan.Inputs, want)
	}
}

func TestScanManifestOut(t *testing.T) {
	path := writeManifest(t, "in.yaml", cleanVLLM)
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			_, want, _ := run(t, "", "scan", "manifest", "-f", path, "--format", format, "--deterministic")
			dest := filepath.Join(t.TempDir(), "report.out")
			code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", format, "--deterministic", "--out", dest)
			if code != ExitOK || out != "" || errs != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
			}
			got, err := os.ReadFile(dest)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want || want == "" {
				t.Fatalf("file differs from stdout output:\n%s\n%s", got, want)
			}
		})
	}
}

func TestScanManifestOutReportFormats(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	cases := []struct {
		format string
		prefix string
	}{
		{"html", "<!DOCTYPE html>"},
		{"pdf", "%PDF-"},
		{"sarif", "{"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "report."+tc.format)
			code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", tc.format, "--deterministic", "--out", dest)
			if code != ExitFindings || out != "" || errs != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
			}
			got, err := os.ReadFile(dest)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 || !strings.HasPrefix(strings.ToUpper(string(got)), strings.ToUpper(tc.prefix)) {
				t.Fatalf("%s file starts with %.40q", tc.format, got)
			}
		})
	}
}

func TestScanManifestStdoutReportFormats(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	for _, format := range []string{"html", "sarif"} {
		t.Run(format, func(t *testing.T) {
			code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", format, "--deterministic")
			if code != ExitFindings || out == "" || errs != "" {
				t.Fatalf("code=%d len(stdout)=%d stderr=%q", code, len(out), errs)
			}
		})
	}
}

func TestScanManifestOutUnwritable(t *testing.T) {
	path := writeManifest(t, "in.yaml", cleanVLLM)
	dest := filepath.Join(t.TempDir(), "no", "such", "dir", "report.json")
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--out", dest)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "report.json") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanManifestExitCodeFromReport(t *testing.T) {
	path := writeManifest(t, "in.yaml", cleanVLLM)
	for _, failOn := range []string{"fail", "warn", "never"} {
		if code, _, errs := run(t, "", "scan", "manifest", "-f", path, "--fail-on", failOn); code != ExitOK {
			t.Errorf("--fail-on %s: code=%d stderr=%q", failOn, code, errs)
		}
	}
}

func TestScanManifestExitCodeFromFindings(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	cases := []struct {
		failOn string
		want   int
	}{
		{"fail", ExitFindings},
		{"warn", ExitFindings},
		{"never", ExitOK},
	}
	for _, tc := range cases {
		if code, _, errs := run(t, "", "scan", "manifest", "-f", path, "--fail-on", tc.failOn); code != tc.want {
			t.Errorf("--fail-on %s: code=%d want %d stderr=%q", tc.failOn, code, tc.want, errs)
		}
	}
}

func TestScanSubcommandErrors(t *testing.T) {
	for _, args := range [][]string{{"scan"}, {"scan", "bogus"}} {
		code, out, errs := run(t, "", args...)
		if code != ExitUsage || out != "" || errs == "" {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errs)
		}
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name   string
		s      report.Summary
		failOn string
		want   int
	}{
		{"fail with fail", report.Summary{Fail: 1}, "fail", ExitFindings},
		{"fail and warn with fail", report.Summary{Fail: 1, Warn: 2}, "fail", ExitFindings},
		{"only warn with fail", report.Summary{Warn: 1}, "fail", ExitOK},
		{"only warn with warn", report.Summary{Warn: 1}, "warn", ExitFindings},
		{"fail with warn", report.Summary{Fail: 1}, "warn", ExitFindings},
		{"fail with never", report.Summary{Fail: 1, Warn: 1}, "never", ExitOK},
		{"warn with never", report.Summary{Warn: 1}, "never", ExitOK},
		{"info and pass with warn", report.Summary{Info: 3, Pass: 2, NA: 1}, "warn", ExitOK},
		{"clean with fail", report.Summary{Pass: 4}, "fail", ExitOK},
		{"empty with fail", report.Summary{}, "fail", ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(&report.Report{Summary: tc.s}, tc.failOn); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

var update = flag.Bool("update", false, "rewrite the golden files")

const goldenDir = "../../test/golden/cli"

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(goldenDir, name)
	if *update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs (run with -update and review the diff)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errs := run(t, "", args...)
	if code != ExitOK || errs != "" || out == "" {
		t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out, errs)
	}
	return out
}

func TestScanManifestPDFNeedsOutExact(t *testing.T) {
	path := writeManifest(t, "in.yaml", configMap)
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", "pdf")
	if code != ExitUsage || out != "" || errs != "kshield: --format pdf needs --out\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestChecksListGolden(t *testing.T) {
	golden(t, "checks-list.txt", runOK(t, "checks", "list"))
	golden(t, "checks-list.json", runOK(t, "checks", "list", "--profile", "dora", "--format", "json"))
	if got := runOK(t, "checks", "list", "--format", "text", "--profile", "dora"); got != runOK(t, "checks", "list") {
		t.Fatal("explicit --format text --profile dora differs from the default")
	}
}

func TestChecksListText(t *testing.T) {
	lines := strings.Split(strings.TrimSuffix(runOK(t, "checks", "list"), "\n"), "\n")
	if !regexp.MustCompile(`^DISPLAY +CHECK +SEVERITY +TIER +FIX +TITLE$`).MatchString(lines[0]) {
		t.Fatalf("header %q", lines[0])
	}
	all := check.All()
	if len(lines) != len(all)+1 {
		t.Fatalf("%d lines, want %d", len(lines), len(all)+1)
	}
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range all {
		f := strings.Fields(lines[i+1])
		if f[0] != p.Checks[c.ID].Display || f[1] != c.ID || f[2] != string(p.Checks[c.ID].Severity) || f[3] != tierText(c.Tier) || f[4] != string(c.Fix) {
			t.Errorf("row %d: %q", i+1, lines[i+1])
		}
		if !strings.HasSuffix(lines[i+1], "  "+c.Title) {
			t.Errorf("row %d does not end with the title: %q", i+1, lines[i+1])
		}
	}
}

func TestChecksListJSON(t *testing.T) {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(runOK(t, "checks", "list", "--format", "json")), &rows); err != nil {
		t.Fatal(err)
	}
	all := check.All()
	if len(rows) != len(all) {
		t.Fatalf("%d rows, want %d", len(rows), len(all))
	}
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range all {
		row := rows[i]
		if len(row) != 7 {
			t.Errorf("%s: keys %v", c.ID, row)
		}
		e := p.Checks[c.ID]
		if row["id"] != c.ID || row["display"] != e.Display || row["title"] != c.Title || row["severity"] != string(e.Severity) || row["tier"] != tierText(c.Tier) || row["fix"] != string(c.Fix) {
			t.Errorf("row %d: %v", i, row)
		}
		refs, _ := row["refs"].([]any)
		if len(refs) != len(e.Refs) {
			t.Fatalf("%s refs %v, want %v", c.ID, refs, e.Refs)
		}
		for j, ref := range e.Refs {
			if refs[j] != ref {
				t.Errorf("%s ref %d = %v, want %s", c.ID, j, refs[j], ref)
			}
		}
	}
}

func TestTierText(t *testing.T) {
	for tier, want := range map[check.Tier]string{check.Manifest: "manifest", check.Cluster: "cluster", check.Both: "manifest+cluster"} {
		if got := tierText(tier); got != want {
			t.Errorf("tierText(%d) = %q, want %q", tier, got, want)
		}
	}
}

func TestChecksExplainGolden(t *testing.T) {
	out := runOK(t, "checks", "explain", "KS-AI-002")
	golden(t, "checks-explain-ks-ai-002.txt", out)
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	display := p.Checks["KS-AI-002"].Display
	for _, id := range []string{strings.ToLower(display), display, "ks-ai-002", "Ks-Ai-002"} {
		if got := runOK(t, "checks", "explain", id); got != out {
			t.Errorf("checks explain %s differs from checks explain KS-AI-002:\n%s", id, got)
		}
	}
	for _, args := range [][]string{
		{"checks", "explain", "--profile", "dora", "KS-AI-002"},
		{"checks", "explain", "KS-AI-002", "--profile", "dora"},
		{"checks", "explain", "KS-AI-002", "--profile=dora"},
	} {
		if got := runOK(t, args...); got != out {
			t.Errorf("%v differs from checks explain KS-AI-002:\n%s", args, got)
		}
	}
}

func TestChecksExplainContent(t *testing.T) {
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range check.All() {
		t.Run(c.ID, func(t *testing.T) {
			out := runOK(t, "checks", "explain", c.ID)
			e := p.Checks[c.ID]
			for _, want := range []string{c.ID, e.Display, c.Title, tierText(c.Tier), string(c.Fix), string(e.Severity), "\n" + report.Disclaimer + "\n"} {
				if !strings.Contains(out, want) {
					t.Errorf("output misses %q:\n%s", want, out)
				}
			}
			for _, ref := range e.Refs {
				ex, src, ok := regtext.Lookup(ref)
				if !ok {
					t.Fatalf("unknown ref %s", ref)
				}
				for _, want := range []string{regtext.Label(ref), src.Short, src.CELEX, src.URL} {
					if !strings.Contains(out, want) {
						t.Errorf("ref %s: output misses %q", ref, want)
					}
				}
				for _, line := range strings.Split(strings.TrimSpace(ex.Text), "\n") {
					if line = strings.TrimRight(line, " \t"); line != "" && !strings.Contains(out, "\n  "+line+"\n") {
						t.Errorf("ref %s: excerpt line not indented by two spaces: %q", ref, line)
					}
				}
			}
		})
	}
}

func TestChecksExplainNoComplianceClaim(t *testing.T) {
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range check.All() {
		out := runOK(t, "checks", "explain", c.ID)
		if !strings.Contains(out, report.Disclaimer) {
			t.Fatalf("%s: disclaimer missing", c.ID)
		}
		var excerpts []string
		for _, ref := range p.Checks[c.ID].Refs {
			ex, _, ok := regtext.Lookup(ref)
			if !ok {
				t.Fatalf("%s: unknown ref %s", c.ID, ref)
			}
			excerpts = append(excerpts, ex.Text)
		}
		if leak := claimcheck.Leak(out, report.Disclaimer, excerpts); leak != "" {
			t.Errorf("%s: output claims compliance outside the disclaimer and excerpts: %q", c.ID, leak)
		}
	}
}

func TestProfilesListGolden(t *testing.T) {
	out := runOK(t, "profiles", "list")
	golden(t, "profiles-list.txt", out)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !regexp.MustCompile(`^ID +VERSION +CHECKS +SHA256 +TITLE$`).MatchString(lines[0]) {
		t.Fatalf("header %q", lines[0])
	}
	ids := profile.IDs()
	if len(lines) != len(ids)+1 {
		t.Fatalf("%d lines, want %d", len(lines), len(ids)+1)
	}
	for i, id := range ids {
		p, err := profile.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(lines[i+1])
		if f[0] != p.ID || f[1] != strconv.Itoa(p.Version) || f[3] != p.SHA256 || !strings.HasSuffix(lines[i+1], "  "+p.Title) {
			t.Errorf("row %q", lines[i+1])
		}
		if f[2] != strconv.Itoa(len(p.Checks)) {
			t.Errorf("checks column %q, want %d", f[2], len(p.Checks))
		}
	}
}

func TestProfilesListJSON(t *testing.T) {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(runOK(t, "profiles", "list", "--format", "json")), &rows); err != nil {
		t.Fatal(err)
	}
	ids := profile.IDs()
	if len(rows) != len(ids) {
		t.Fatalf("%d rows, want %d", len(rows), len(ids))
	}
	for i, id := range ids {
		p, err := profile.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		row := rows[i]
		if len(row) != 5 || row["id"] != p.ID || row["version"] != float64(p.Version) || row["checks"] != float64(len(p.Checks)) || row["sha256"] != p.SHA256 || row["title"] != p.Title {
			t.Errorf("row %v", row)
		}
	}
}

func TestChecksProfilesErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"checks no subcommand", []string{"checks"}, "checks"},
		{"checks unknown subcommand", []string{"checks", "bogus"}, `"bogus"`},
		{"checks list unknown profile", []string{"checks", "list", "--profile", "nope"}, `unknown profile "nope"`},
		{"checks list unknown format", []string{"checks", "list", "--format", "html"}, `unknown format "html"`},
		{"checks list argument", []string{"checks", "list", "extra"}, `"extra"`},
		{"checks list unknown flag", []string{"checks", "list", "--bogus"}, "bogus"},
		{"checks explain unknown check", []string{"checks", "explain", "KS-NOPE-001"}, `unknown check "KS-NOPE-001"`},
		{"checks explain no id", []string{"checks", "explain"}, "check ID"},
		{"checks explain two ids", []string{"checks", "explain", "KS-AI-001", "KS-AI-002"}, `"KS-AI-002"`},
		{"checks explain unknown profile", []string{"checks", "explain", "KS-AI-002", "--profile", "nope"}, `unknown profile "nope"`},
		{"checks explain unknown flag", []string{"checks", "explain", "KS-AI-002", "--bogus"}, "bogus"},
		{"profiles no subcommand", []string{"profiles"}, "profiles"},
		{"profiles unknown subcommand", []string{"profiles", "bogus"}, `"bogus"`},
		{"profiles list unknown format", []string{"profiles", "list", "--format", "xml"}, `unknown format "xml"`},
		{"profiles list argument", []string{"profiles", "list", "extra"}, `"extra"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, "", tc.args...)
			if code != ExitUsage || out != "" || !strings.Contains(errs, tc.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q, want stderr with %q", code, out, errs, tc.want)
			}
		})
	}
}

func TestUsageListsNewForms(t *testing.T) {
	_, out, _ := run(t, "", "help")
	for _, want := range []string{
		"[--format text|json|html|pdf|sarif]",
		"kshield checks list [--profile dora] [--format text|json]",
		"kshield checks explain <check-id|display-id> [--profile dora]",
		"kshield profiles list [--format text|json]",
		"kshield remediate --from <scan.json> [-f <file|dir|-> ...] [-n <ns>] [--kubeconfig <file>] [--context <name>] [--mode audit|enforce] [--allow-fqdn <name> ...] [--allow-cidr <cidr> ...] [--out <dir>]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage misses %q", want)
		}
	}
	_, _, errs := run(t, "", "scan", "manifest", "-h")
	if !strings.Contains(errs, "[--format text|json|html|pdf|sarif]") {
		t.Errorf("scan manifest usage: %q", errs)
	}
}

func TestExitCodeIncomplete(t *testing.T) {
	for _, failOn := range []string{"fail", "warn", "never"} {
		for _, s := range []report.Summary{
			{Incomplete: true},
			{Incomplete: true, Fail: 1},
			{Incomplete: true, Warn: 1, Pass: 2},
		} {
			if got := ExitCode(&report.Report{Summary: s}, failOn); got != ExitIncomplete {
				t.Errorf("failOn=%s summary=%+v: got %d want %d", failOn, s, got, ExitIncomplete)
			}
		}
	}
}

func remediateScan(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scan.json")
	code, _, errs := run(t, stdin, append([]string{"scan", "manifest", "--format", "json", "--out", out}, args...)...)
	if code != ExitFindings && code != ExitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, errs)
	}
	return out
}

func TestRemediateWritesBundle(t *testing.T) {
	in := writeManifest(t, "in.yaml", rootVLLMDeployment)
	sj := remediateScan(t, "", "-f", in, "-n", "ai")
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errs := run(t, "", "remediate", "--from", sj, "--out", out)
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	for _, name := range []string{"MANUAL.md", "base/manifests.yaml", "infrastructure-policies.yaml", "kustomization.yaml", "remediation.json", "workload-patch.yaml"} {
		want := filepath.ToSlash(filepath.Join(out, name))
		if !slices.Contains(lines, want) {
			t.Fatalf("stdout has no line %q:\n%s", want, stdout)
		}
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	if len(lines) < 6 {
		t.Fatalf("stdout=%q", stdout)
	}
}

func TestRemediateExitCodes(t *testing.T) {
	in := writeManifest(t, "in.yaml", rootVLLMDeployment)
	sj := remediateScan(t, "", "-f", in, "-n", "ai")
	stdinScan := remediateScan(t, rootVLLMDeployment, "-f", "-", "-n", "ai")
	full := filepath.Join(t.TempDir(), "full")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sj)
	if err != nil {
		t.Fatal(err)
	}
	incomplete := filepath.Join(t.TempDir(), "incomplete.json")
	if err := os.WriteFile(incomplete, bytes.Replace(raw, []byte(`"incomplete": false`), []byte(`"incomplete": true`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want int
		msg  string
	}{
		{"non-empty out", []string{"--from", sj, "--out", full}, ExitUsage, "not empty"},
		{"missing from", []string{}, ExitUsage, "--from"},
		{"unreadable from", []string{"--from", filepath.Join(t.TempDir(), "nope.json")}, ExitUsage, "nope.json"},
		{"bad mode", []string{"--from", sj, "--mode", "strict"}, ExitUsage, "strict"},
		{"open cidr", []string{"--from", sj, "--allow-cidr", "0.0.0.0/0"}, ExitUsage, "0.0.0.0/0"},
		{"stdin scan without -f", []string{"--from", stdinScan}, ExitUsage, "-f"},
		{"positional", []string{"--from", sj, "extra"}, ExitUsage, "extra"},
		{"incomplete", []string{"--from", incomplete}, ExitIncomplete, "incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "bundle")
			args := append([]string{"remediate"}, tc.args...)
			if !slices.Contains(tc.args, "--out") {
				args = append(args, "--out", out)
			}
			code, stdout, errs := run(t, "", args...)
			if code != tc.want || stdout != "" || !strings.Contains(errs, tc.msg) {
				t.Fatalf("code=%d stdout=%q stderr=%q, want code %d and %q", code, stdout, errs, tc.want, tc.msg)
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatalf("exit %d wrote %s", code, out)
			}
		})
	}
	out := filepath.Join(t.TempDir(), "bundle")
	code, _, errs := run(t, rootVLLMDeployment, "remediate", "--from", stdinScan, "-f", "-", "--out", out)
	if code != ExitOK {
		t.Fatalf("stdin scan with -f -: code=%d stderr=%q", code, errs)
	}
}
