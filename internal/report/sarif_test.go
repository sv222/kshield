package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const toxicSARIF = "../../test/golden/toxic.sarif"

func renderSARIF(t *testing.T, r *Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					Properties struct {
						Tags []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []sarifDocInvocation `json:"invocations"`
		Results     []sarifDocResult     `json:"results"`
	} `json:"runs"`
}

type sarifDocInvocation struct {
	ExecutionSuccessful        *bool `json:"executionSuccessful"`
	ToolExecutionNotifications []struct {
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	} `json:"toolExecutionNotifications"`
}

type sarifDocResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation *struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
		LogicalLocations []struct {
			FullyQualifiedName string `json:"fullyQualifiedName"`
		} `json:"logicalLocations"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

func decodeSARIF(t *testing.T, b []byte) *sarifDoc {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d sarifDoc
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if len(d.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(d.Runs))
	}
	return &d
}

func TestSARIFGolden(t *testing.T) {
	got := renderSARIF(t, toxicReport(t))
	if again := renderSARIF(t, toxicReport(t)); !bytes.Equal(again, got) {
		t.Fatal("two renders of the same report differ")
	}
	if !bytes.HasSuffix(got, []byte("}\n")) {
		t.Fatal("SARIF does not end with a newline")
	}
	if *update {
		if err := os.WriteFile(toxicSARIF, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(toxicSARIF)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SARIF differs from %s (run with -update and review the diff)", toxicSARIF)
	}
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSARIFStructure(t *testing.T) {
	r := toxicReport(t)
	d := decodeSARIF(t, renderSARIF(t, r))
	if d.Version != "2.1.0" {
		t.Errorf("version = %q", d.Version)
	}
	if d.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("$schema = %q", d.Schema)
	}
	run := d.Runs[0]
	drv := run.Tool.Driver
	if drv.Name != "kshield" || drv.Version != r.Tool.Version {
		t.Errorf("driver = %q %q", drv.Name, drv.Version)
	}
	if len(drv.Rules) != len(r.Checks) {
		t.Fatalf("rules = %d, checks = %d", len(drv.Rules), len(r.Checks))
	}
	for i, c := range r.Checks {
		rule := drv.Rules[i]
		if rule.ID != c.ID || rule.Name != c.Display || rule.ShortDescription.Text != c.Title {
			t.Errorf("rule %d = %q %q %q, want check %q %q %q", i, rule.ID, rule.Name, rule.ShortDescription.Text, c.ID, c.Display, c.Title)
		}
		if !slices.Equal(rule.Properties.Tags, []string{c.Fix, c.Severity}) {
			t.Errorf("rule %s tags = %v", rule.ID, rule.Properties.Tags)
		}
	}
	want := 0
	for _, c := range r.Checks {
		if c.Verdict == VerdictFail || c.Verdict == VerdictWarn || c.Verdict == VerdictInfo {
			want += len(c.Findings)
		}
	}
	if want == 0 {
		t.Fatal("toxic report has no findings to map; the test cannot pass")
	}
	if len(run.Results) != want {
		t.Fatalf("results = %d, want %d", len(run.Results), want)
	}
	levels := map[string]bool{"error": true, "warning": true, "note": true}
	seen := map[string]bool{}
	for i, res := range run.Results {
		if res.RuleIndex == nil || *res.RuleIndex < 0 || *res.RuleIndex >= len(drv.Rules) {
			t.Fatalf("result %d ruleIndex out of range", i)
		}
		if drv.Rules[*res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d ruleIndex %d -> %q, ruleId %q", i, *res.RuleIndex, drv.Rules[*res.RuleIndex].ID, res.RuleID)
		}
		if !levels[res.Level] {
			t.Errorf("result %d level %q not in enum", i, res.Level)
		}
		if !strings.HasSuffix(res.Message.Text, ")") || !strings.Contains(res.Message.Text, " (") {
			t.Errorf("result %d message %q", i, res.Message.Text)
		}
		if len(res.Locations) != 1 {
			t.Fatalf("result %d locations = %d", i, len(res.Locations))
		}
		loc := res.Locations[0]
		if len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].FullyQualifiedName == "" {
			t.Errorf("result %d logical location missing", i)
		}
		if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %d physical location missing", i)
		} else if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine < 1 {
			t.Errorf("result %d region missing", i)
		}
		fp := res.PartialFingerprints["kshield/v1"]
		if len(res.PartialFingerprints) != 1 || !fingerprintRE.MatchString(fp) {
			t.Errorf("result %d fingerprints %v", i, res.PartialFingerprints)
		}
		if seen[fp] {
			t.Errorf("result %d fingerprint %s repeats", i, fp)
		}
		seen[fp] = true
	}
}

func TestSARIFFields(t *testing.T) {
	r := sampleReport()
	d := decodeSARIF(t, renderSARIF(t, r))
	res := d.Runs[0].Results
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
	got := res[0]
	if got.RuleID != "KS-WL-001" || *got.RuleIndex != 0 || got.Level != "error" {
		t.Errorf("rule/level = %q %d %q", got.RuleID, *got.RuleIndex, got.Level)
	}
	if got.Message.Text != "runAsNonRoot is not true and runAsUser is not set (Deployment/ai-inference/vllm)" {
		t.Errorf("message = %q", got.Message.Text)
	}
	loc := got.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "deploy/vllm.yaml" || loc.PhysicalLocation.Region.StartLine != 1 {
		t.Errorf("physical = %+v", loc.PhysicalLocation)
	}
	if loc.LogicalLocations[0].FullyQualifiedName != "Deployment/ai-inference/vllm" {
		t.Errorf("logical = %q", loc.LogicalLocations[0].FullyQualifiedName)
	}
	sum := sha256.Sum256([]byte("KS-WL-001|Deployment/ai-inference/vllm||vllm|/spec/template/spec/containers/0/securityContext/runAsNonRoot|runAsNonRoot is not true and runAsUser is not set"))
	if fp := got.PartialFingerprints["kshield/v1"]; fp != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint = %s", fp)
	}
}

func TestSARIFFingerprintIgnoresLivePodName(t *testing.T) {
	fingerprint := func(pod string) string {
		r := sampleReport()
		f := &r.Checks[0].Findings[0]
		f.Source = nil
		f.Message = LivePodPrefix + pod + ": " + f.Message
		return decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results[0].PartialFingerprints["kshield/v1"]
	}
	a, b := fingerprint("vllm-7d9f8-abcde"), fingerprint("vllm-7d9f8-zzzzz")
	if a == "" || a != b {
		t.Fatalf("fingerprints differ across pod names: %q %q", a, b)
	}
	sum := sha256.Sum256([]byte("KS-WL-001|Deployment/ai-inference/vllm||vllm|/spec/template/spec/containers/0/securityContext/runAsNonRoot|runAsNonRoot is not true and runAsUser is not set"))
	if a != hex.EncodeToString(sum[:]) {
		t.Errorf("live fingerprint %s differs from the template one", a)
	}
}

func TestSARIFStdin(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Source = &Source{File: "-", Line: 3}
	loc := decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results[0].Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("physical location missing for stdin")
	}
	if uri := loc.PhysicalLocation.ArtifactLocation.URI; uri != "stdin" {
		t.Fatalf("uri = %q, want stdin", uri)
	}
	if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("region = %+v", loc.PhysicalLocation.Region)
	}
}

func TestSARIFNoSource(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Source = nil
	loc := decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results[0].Locations[0]
	if loc.PhysicalLocation != nil {
		t.Fatalf("physical location %+v for a finding with no source", loc.PhysicalLocation)
	}
	if len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].FullyQualifiedName != "Deployment/ai-inference/vllm" {
		t.Fatalf("logical locations = %+v", loc.LogicalLocations)
	}
}

func TestSARIFURIEscapes(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Source = &Source{File: "dir a/漢.yaml", Line: 2}
	loc := decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results[0].Locations[0]
	if uri := loc.PhysicalLocation.ArtifactLocation.URI; uri != "dir%20a/%E6%BC%A2.yaml" {
		t.Fatalf("uri = %q", uri)
	}
}

func TestSARIFNoResultsForPass(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Verdict = VerdictPass
	r.Checks[0].Findings[0].Verdict = VerdictPass
	r.Checks[2].Findings = []Finding{r.Checks[0].Findings[0]}
	r.Checks[2].Findings[0].Verdict = VerdictNA
	b := renderSARIF(t, r)
	d := decodeSARIF(t, b)
	if len(d.Runs[0].Results) != 0 {
		t.Fatalf("results = %d, want 0", len(d.Runs[0].Results))
	}
	if !bytes.Contains(b, []byte(`"results": []`)) {
		t.Fatal("results is not an empty array")
	}
	if len(d.Runs[0].Tool.Driver.Rules) != len(r.Checks) {
		t.Fatalf("rules = %d, want %d", len(d.Runs[0].Tool.Driver.Rules), len(r.Checks))
	}
}

func TestSARIFLevelFromFinding(t *testing.T) {
	r := sampleReport()
	base := r.Checks[0].Findings[0]
	mk := func(verdict, path string) Finding {
		f := base
		f.Verdict = verdict
		f.Path = path
		return f
	}
	r.Checks[0].Findings = []Finding{
		mk(VerdictFail, "/a"),
		mk(VerdictWarn, "/b"),
		mk(VerdictInfo, "/c"),
		mk(VerdictPass, "/d"),
		mk(VerdictNA, "/e"),
		mk("", "/f"),
	}
	res := decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results
	var got []string
	for _, x := range res {
		got = append(got, x.Level)
	}
	if want := []string{"error", "warning", "note"}; !slices.Equal(got, want) {
		t.Fatalf("levels = %v, want %v", got, want)
	}
}

func jsonStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			jsonStrings(e, out)
		}
	case map[string]any:
		for k, e := range x {
			*out = append(*out, k)
			jsonStrings(e, out)
		}
	}
}

func TestSARIFNoComplianceClaim(t *testing.T) {
	r := toxicReport(t)
	var v any
	if err := json.Unmarshal(renderSARIF(t, r), &v); err != nil {
		t.Fatal(err)
	}
	var strs []string
	jsonStrings(v, &strs)
	slices.Sort(strs)
	if len(strs) < 100 {
		t.Fatalf("only %d strings in SARIF; the search has nothing to check", len(strs))
	}
	assertNoComplianceClaim(t, strings.Join(strs, "\n"), r)
}

func TestSARIFInvocations(t *testing.T) {
	b := renderSARIF(t, toxicReport(t))
	inv := decodeSARIF(t, b).Runs[0].Invocations
	if len(inv) != 1 || inv[0].ExecutionSuccessful == nil || !*inv[0].ExecutionSuccessful {
		t.Fatalf("toxic invocations = %+v, want one with executionSuccessful true", inv)
	}
	if inv[0].ToolExecutionNotifications != nil || bytes.Contains(b, []byte("toolExecutionNotifications")) {
		t.Fatal("complete scan must have no toolExecutionNotifications")
	}

	r := sampleReport()
	r.Errors = []string{"x", "networking.k8s.io/v1 networkpolicies: forbidden"}
	r.Summary.Incomplete = true
	inv = decodeSARIF(t, renderSARIF(t, r)).Runs[0].Invocations
	if len(inv) != 1 || inv[0].ExecutionSuccessful == nil || *inv[0].ExecutionSuccessful {
		t.Fatalf("incomplete invocations = %+v, want one with executionSuccessful false", inv)
	}
	n := inv[0].ToolExecutionNotifications
	if len(n) != 2 {
		t.Fatalf("notifications = %+v, want 2", n)
	}
	for i, want := range r.Errors {
		if n[i].Level != "error" || n[i].Message.Text != want {
			t.Errorf("notification %d = %+v, want level error, text %q", i, n[i], want)
		}
	}
}

func TestSARIFUnknownGivesNoResult(t *testing.T) {
	r := sampleReport()
	base := r.Checks[0].Findings[0]
	warn, unknown := base, base
	warn.Verdict, warn.Path = VerdictWarn, "/a"
	unknown.Verdict, unknown.Path = VerdictUnknown, "/b"
	r.Checks[0].Verdict = VerdictUnknown
	r.Checks[0].Findings = []Finding{warn, unknown}
	res := decodeSARIF(t, renderSARIF(t, r)).Runs[0].Results
	if len(res) != 1 || res[0].Level != "warning" {
		t.Fatalf("results = %+v, want one warning (UNKNOWN gives no result)", res)
	}
}
