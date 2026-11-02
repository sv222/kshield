package remediate

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/fixturegen"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	rescanCorpusRoot  = "../../test/corpus"
	rescanSeedDir     = "fixturegen"
	rescanDefaultNS   = "default"
	rescanProfile     = "dora"
	rescanBuiltFile   = "built.yaml"
	rescanPatchedFile = "patched.yaml"
	reorderedDir      = "../../test/corpus/remediate/raycluster-reordered"
)

var (
	rescanSeeds   = []int64{1001, 1002, 1003}
	enforceChecks = []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003"}
	verdictRank   = map[string]int{report.VerdictPass: 0, report.VerdictInfo: 1, report.VerdictWarn: 2, report.VerdictFail: 3}
)

type rescanFixture struct {
	name      string
	input     string
	namespace string
	residuals []corpus.Residual
}

type findingKey struct {
	check     string
	object    load.ObjectRef
	container string
}

func (k findingKey) String() string {
	s := k.check + " " + k.object.String()
	if k.container != "" {
		s += " container " + k.container
	}
	return s
}

func residualKey(r corpus.Residual) string {
	s := r.Check + " " + r.Object
	if r.Container != "" {
		s += " container " + r.Container
	}
	return s
}

func rescanFixtures(t *testing.T) []rescanFixture {
	t.Helper()
	cases, err := corpus.Cases(rescanCorpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	var out []rescanFixture
	for _, dir := range cases {
		spec, err := corpus.LoadSpec(filepath.Join(dir, corpus.ExpectedFile))
		if err != nil {
			t.Fatal(err)
		}
		input, err := corpus.InputPath(dir)
		if err != nil {
			t.Fatal(err)
		}
		res, err := corpus.LoadResiduals(dir)
		if err != nil {
			t.Fatal(err)
		}
		name, err := filepath.Rel(rescanCorpusRoot, dir)
		if err != nil {
			t.Fatal(err)
		}
		ns := spec.Namespace
		if ns == "" {
			ns = rescanDefaultNS
		}
		out = append(out, rescanFixture{name: filepath.ToSlash(name), input: input, namespace: ns, residuals: res})
	}
	seedRoot := t.TempDir()
	for _, seed := range rescanSeeds {
		input, spec, _, err := fixturegen.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		name := "seed-" + strconv.FormatInt(seed, 10)
		p := filepath.Join(seedRoot, name+".yaml")
		if err := os.WriteFile(p, input, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := corpus.LoadResiduals(filepath.Join(rescanCorpusRoot, rescanSeedDir, name))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rescanFixture{name: rescanSeedDir + "/" + name, input: p, namespace: spec.Namespace, residuals: res})
	}
	return out
}

func TestRescanCorpus(t *testing.T) {
	for _, fx := range rescanFixtures(t) {
		for _, mode := range []string{modeAudit, modeEnforce} {
			t.Run(fx.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				rescanLoop(t, fx, mode)
			})
		}
	}
}

func scanReport(t *testing.T, ns string, inputs ...string) (*report.Report, []byte) {
	t.Helper()
	r, err := scan.Manifest(scan.Options{Inputs: inputs, Namespace: ns, ProfileID: rescanProfile, Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	return r, buf.Bytes()
}

func rescanLoop(t *testing.T, fx rescanFixture, mode string) {
	before, scanJSON := scanReport(t, fx.namespace, fx.input)
	b, err := Run(Options{ScanJSON: scanJSON, Mode: mode})
	if err != nil {
		t.Fatalf("remediate: %v", err)
	}
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	if err := Write(bundleDir, b); err != nil {
		t.Fatal(err)
	}
	built, err := kustomizeBuild(bundleDir)
	if err != nil {
		t.Fatalf("kustomize build: %v", err)
	}
	builtPath := filepath.Join(dir, rescanBuiltFile)
	if err := os.WriteFile(builtPath, built, 0o644); err != nil {
		t.Fatal(err)
	}
	patchedPath := filepath.Join(dir, rescanPatchedFile)
	writePatched(t, fx, builtPath, filepath.Join(bundleDir, FilePolicies), patchedPath)
	after, afterJSON := scanReport(t, fx.namespace, patchedPath)
	assertResiduals(t, fx, mode, after)
	assertPatchesFixed(t, fx, mode, b, after)
	assertNoRegression(t, before, after)
	again, err := Run(Options{ScanJSON: afterJSON, Mode: mode})
	if err != nil {
		t.Fatalf("second remediate: %v", err)
	}
	switch p, ok := again.Files[FileWorkloadPatch]; {
	case !ok:
		t.Errorf("second remediate wrote no %s", FileWorkloadPatch)
	case len(p) > 0:
		t.Errorf("second remediate wrote %s:\n%s", FileWorkloadPatch, p)
	}
	for name, content := range again.Files {
		if strings.HasPrefix(name, Dir6902+"/") {
			t.Errorf("second remediate wrote %s:\n%s", name, content)
		}
	}
}

func kustomizeBuild(dir string) ([]byte, error) {
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), dir)
	if err != nil {
		return nil, err
	}
	return m.AsYaml()
}

func readObjects(t *testing.T, ns string, paths ...string) []load.Object {
	t.Helper()
	objs, err := load.Read(paths, load.Options{DefaultNamespace: ns})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func sameObject(a, b load.ObjectRef) bool {
	return apiGroupOf(a.APIVersion) == apiGroupOf(b.APIVersion) && a.Kind == b.Kind && a.Namespace == b.Namespace && a.Name == b.Name
}

func writePatched(t *testing.T, fx rescanFixture, builtPath, policiesPath, out string) {
	t.Helper()
	policies := readObjects(t, fx.namespace, policiesPath)
	var docs []any
	for _, o := range readObjects(t, fx.namespace, builtPath) {
		replaced := false
		for _, p := range policies {
			replaced = replaced || sameObject(o.Ref, p.Ref)
		}
		if !replaced {
			docs = append(docs, o.U.Object)
		}
	}
	for _, o := range readObjects(t, fx.namespace, fx.input) {
		if isSecret(o.Ref) && !owned(&o) {
			docs = append(docs, o.U.Object)
		}
	}
	for _, p := range policies {
		docs = append(docs, p.U.Object)
	}
	data, err := yamlDocs(docs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixKind(id string) check.Fix {
	c, ok := check.ByID(id)
	if !ok {
		return check.FixManual
	}
	return c.Fix
}

func assertResiduals(t *testing.T, fx rescanFixture, mode string, after *report.Report) {
	t.Helper()
	want := map[string]bool{}
	for _, r := range fx.residuals {
		if r.In(mode) {
			want[residualKey(r)] = true
		}
	}
	matched := map[string]bool{}
	for _, c := range after.Checks {
		fix := fixKind(c.ID)
		for _, f := range c.Findings {
			k := findingKey{c.ID, f.Object, f.Container}.String()
			switch {
			case f.Verdict == report.VerdictFail && fix != check.FixManual:
				if !want[k] {
					t.Errorf("FAIL after remediation with no residual: %s %s: %s", k, f.Path, f.Message)
				}
				matched[k] = true
			case f.Verdict == report.VerdictWarn && mode == modeEnforce && slices.Contains(enforceChecks, c.ID):
				if !want[k] {
					t.Errorf("WARN in enforce mode with no residual: %s %s: %s", k, f.Path, f.Message)
				}
				matched[k] = true
			}
		}
	}
	for k := range want {
		if !matched[k] {
			t.Errorf("stale residual (no FAIL, and no enforce-mode WARN, after remediation): %s", k)
		}
	}
}

func assertPatchesFixed(t *testing.T, fx rescanFixture, mode string, b *Bundle, after *report.Report) {
	t.Helper()
	residual := map[string]bool{}
	for _, r := range fx.residuals {
		if r.In(mode) {
			residual[residualKey(r)] = true
		}
	}
	left := map[string]report.Finding{}
	for _, c := range after.Checks {
		for _, f := range c.Findings {
			ref := load.ObjectRef{Kind: f.Object.Kind, Namespace: f.Object.Namespace, Name: f.Object.Name}
			left[findingKey{c.ID, ref, f.Container}.String()] = f
		}
	}
	for _, it := range remediation(t, b).Items {
		if it.Action != ActionPatch {
			continue
		}
		ref := load.ObjectRef{Kind: it.Object.Kind, Namespace: it.Object.Namespace, Name: it.Object.Name}
		k := findingKey{it.Check, ref, it.Container}.String()
		if f, ok := left[k]; ok && !residual[k] {
			t.Errorf("patch item still has a finding after remediation: %s %s %s: %s", k, f.Verdict, f.Path, f.Message)
		}
	}
}

func worstByKey(r *report.Report) map[findingKey]string {
	out := map[findingKey]string{}
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			k := findingKey{c.ID, f.Object, f.Container}
			if cur, ok := out[k]; !ok || verdictRank[f.Verdict] > verdictRank[cur] {
				out[k] = f.Verdict
			}
		}
	}
	return out
}

func assertNoRegression(t *testing.T, before, after *report.Report) {
	t.Helper()
	old := worstByKey(before)
	for k, v := range worstByKey(after) {
		prev, ok := old[k]
		switch {
		case !ok:
			t.Errorf("new finding after remediation: %s %s", k, v)
		case verdictRank[v] > verdictRank[prev]:
			t.Errorf("verdict got worse after remediation: %s %s -> %s", k, prev, v)
		}
	}
}

func TestRescanRayClusterReordered(t *testing.T) {
	input := filepath.Join(reorderedDir, "input.yaml")
	_, scanJSON := scanReport(t, "ai-inference", input)
	b, err := Run(Options{ScanJSON: scanJSON})
	if err != nil {
		t.Fatal(err)
	}
	patch := patchFileName(load.ObjectRef{APIVersion: "ray.io/v1", Kind: "RayCluster", Namespace: "ai-inference", Name: "rc"})
	ops := b.Files[patch]
	if len(ops) == 0 {
		t.Fatalf("no %s in the bundle", patch)
	}
	for _, path := range []string{"/spec/workerGroupSpecs/1/groupName", "/spec/workerGroupSpecs/1/template/spec/containers/0/name", "/spec/workerGroupSpecs/1/template/spec/containers/1/name"} {
		if !bytes.Contains(ops, []byte("path: "+path+"\n")) {
			t.Errorf("%s has no test op on %s:\n%s", patch, path, ops)
		}
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := Write(dir, b); err != nil {
		t.Fatal(err)
	}
	out, err := kustomizeBuild(dir)
	if err != nil {
		t.Fatalf("build on the original: %v", err)
	}
	var rc map[string]any
	if err := yaml.Unmarshal(out, &rc); err != nil {
		t.Fatal(err)
	}
	assertJSON(t, at(t, rc, "/spec/workerGroupSpecs/1/template/spec/containers/0/securityContext/runAsNonRoot"), "true")
	assertJSON(t, at(t, rc, "/spec/workerGroupSpecs/1/template/spec/containers/1/securityContext/runAsNonRoot"), "true")
	for _, name := range []string{"groups-swapped.yaml", "containers-swapped.yaml"} {
		t.Run(name, func(t *testing.T) {
			swapped, err := os.ReadFile(filepath.Join(reorderedDir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(FileBase)), swapped, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = kustomizeBuild(dir)
			assertTestFailure(t, err)
		})
	}
}
