package test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	clusterCorpusRoot = "cluster-corpus"
	factsFile         = "facts.yaml"
)

type nodeFactsFile struct {
	Node         string   `json:"node"`
	LSM          []string `json:"lsm"`
	BPFLSMConfig string   `json:"bpfLSMConfig"`
	Unknown      string   `json:"unknown"`
}

type clusterFactsFile struct {
	ProbeRan bool            `json:"probeRan"`
	Nodes    []nodeFactsFile `json:"nodes"`
}

func TestClusterCorpus(t *testing.T) {
	cases, err := corpus.Cases(clusterCorpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatalf("no cases under %s", clusterCorpusRoot)
	}
	for _, dir := range cases {
		name, err := filepath.Rel(clusterCorpusRoot, dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.ToSlash(name), func(t *testing.T) {
			runClusterCase(t, dir)
		})
	}
}

func runClusterCase(t *testing.T, dir string) {
	t.Helper()
	spec, err := corpus.LoadSpec(filepath.Join(dir, corpus.ExpectedFile))
	if err != nil {
		t.Fatalf("case %s: %v", dir, err)
	}
	namespace := spec.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}
	objs, err := load.Read([]string{filepath.Join(dir, corpus.InputFile)}, load.Options{DefaultNamespace: namespace})
	if err != nil {
		t.Fatalf("case %s: %v", dir, err)
	}
	facts, err := readFacts(filepath.Join(dir, factsFile))
	if err != nil {
		t.Fatalf("case %s: %v", dir, err)
	}
	r, err := scan.ClusterObjects(objs, facts, scan.ClusterOptions{ProfileID: profileID, Deterministic: true, Errors: probeErrors(facts)})
	if err != nil {
		t.Fatalf("case %s: scan failed: %v", dir, err)
	}
	compareCase(t, dir, spec, r)
	for _, msg := range unmatchedUnknown(r) {
		t.Errorf("case %s: %s", dir, msg)
	}
}

func probeErrors(facts *check.ClusterFacts) []string {
	if facts == nil {
		return nil
	}
	var out []string
	for _, n := range facts.Nodes {
		if n.Unknown != "" {
			out = append(out, cluster.ProbeErrorPrefix+n.Node.Name+": "+n.Unknown)
		}
	}
	return out
}

func unmatchedUnknown(r *report.Report) []string {
	var out []string
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Verdict != report.VerdictUnknown {
				continue
			}
			prefix := cluster.ProbeErrorPrefix + f.Object.Name + ":"
			if !slices.ContainsFunc(r.Errors, func(e string) bool { return strings.HasPrefix(e, prefix) }) {
				out = append(out, fmt.Sprintf("%s UNKNOWN on %s has no errors line naming it", c.ID, f.Object))
			}
		}
	}
	if r.Summary.Unknown > 0 && !r.Summary.Incomplete {
		out = append(out, "UNKNOWN verdict but the scan is not incomplete")
	}
	return out
}

func readFacts(path string) (*check.ClusterFacts, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f clusterFactsFile
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, err
	}
	out := &check.ClusterFacts{ProbeRan: f.ProbeRan}
	for _, n := range f.Nodes {
		out.Nodes = append(out.Nodes, check.NodeFacts{
			Node:         load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: n.Node},
			LSM:          n.LSM,
			BPFLSMConfig: n.BPFLSMConfig,
			Unknown:      n.Unknown,
		})
	}
	return out, nil
}

func TestReadFacts(t *testing.T) {
	dir := t.TempDir()
	if f, err := readFacts(filepath.Join(dir, factsFile)); err != nil || f != nil {
		t.Errorf("missing file: got %+v, %v", f, err)
	}
	path := filepath.Join(dir, factsFile)
	body := "probeRan: true\nnodes:\n  - {node: n1, lsm: [lockdown, bpf], bpfLSMConfig: \"y\", unknown: \"\"}\n  - {node: n2, unknown: probe pod failed}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := readFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.ProbeRan || len(f.Nodes) != 2 {
		t.Fatalf("facts %+v", f)
	}
	n1, n2 := f.Nodes[0], f.Nodes[1]
	if n1.Node != (load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: "n1"}) || len(n1.LSM) != 2 || n1.LSM[1] != "bpf" || n1.BPFLSMConfig != "y" || n1.Unknown != "" {
		t.Errorf("node 1 %+v", n1)
	}
	if n2.Node.Name != "n2" || n2.Unknown != "probe pod failed" || n2.BPFLSMConfig != "" {
		t.Errorf("node 2 %+v", n2)
	}
	if err := os.WriteFile(path, []byte("probeRan: true\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFacts(path); err == nil {
		t.Error("unknown field must fail")
	}
}

func TestUnmatchedUnknownExactNode(t *testing.T) {
	unknown := func(name string) *report.Report {
		return &report.Report{
			Checks: []report.CheckResult{{ID: "KS-PRE-004", Findings: []report.Finding{{
				Object:  load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: name},
				Verdict: report.VerdictUnknown,
			}}}},
			Summary: report.Summary{Unknown: 1, Incomplete: true},
		}
	}
	r := unknown("n1")
	r.Errors = []string{"node probe n10: probe pod Pending: ImagePullBackOff"}
	if got := unmatchedUnknown(r); len(got) != 1 {
		t.Errorf("n1 must not match the line of n10, got %v", got)
	}
	r.Errors = []string{"node probe n10: x", "node probe n1: probe pod Pending: ImagePullBackOff"}
	if got := unmatchedUnknown(r); len(got) != 0 {
		t.Errorf("n1 must match its own line, got %v", got)
	}
}
