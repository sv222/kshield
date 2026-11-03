package remediate

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	toxicInput = "test/corpus/baseline/toxic/input.yaml"

	helmVLLMYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  labels:
    app.kubernetes.io/managed-by: Helm
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
        image: vllm/vllm-openai:v0.31.0
        args: ["serve", "/models/m", "--trust-remote-code", "--port", "8000"]
`

	ownedYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai-inference
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
        image: vllm/vllm-openai:v0.31.0
---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: vllm-abc
  namespace: ai-inference
  ownerReferences:
  - apiVersion: apps/v1
    kind: Deployment
    name: vllm
    uid: 11111111-1111-1111-1111-111111111111
    controller: true
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
        image: vllm/vllm-openai:v0.31.0
---
apiVersion: v1
kind: Pod
metadata:
  name: vllm-abc-x1
  namespace: ai-inference
  ownerReferences:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: vllm-abc
    uid: 22222222-2222-2222-2222-222222222222
    controller: true
spec:
  containers:
  - name: vllm
    image: vllm/vllm-openai:v0.31.0
---
apiVersion: v1
kind: Pod
metadata:
  name: orphan
  namespace: ai-inference
  ownerReferences:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: gone
    uid: 33333333-3333-3333-3333-333333333333
    controller: true
spec:
  containers:
  - name: vllm
    image: vllm/vllm-openai:v0.31.0
    env:
    - name: HF_TOKEN
      value: "` + hfTokenValue + `"
`

	hfTokenValue  = "hf_kshield_test_token_value"
	apiKeyValue   = "sk-kshield-test-api-key-value"
	secretValue   = "kshield-secret-object-value"
	secretsInYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai-inference
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
        image: vllm/vllm-openai:v0.31.0
        args: ["serve", "/models/m", "--api-key", "` + apiKeyValue + `"]
        env:
        - name: HF_TOKEN
          value: "` + hfTokenValue + `"
      - name: shell
        image: vllm/vllm-openai:v0.31.0
        command: ["sh", "-c", "vllm serve /models/m --api-key '` + apiKeyValue + `' --port 8001"]
---
apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: rc
  namespace: ai-inference
spec:
  headGroupSpec:
    template:
      spec:
        containers:
        - name: ray-head
          image: rayproject/ray:2.50.0
          command: ["vllm", "serve", "/models/m", "--api-key", "` + apiKeyValue + `"]
  workerGroupSpecs:
  - groupName: gpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.50.0
          env:
          - name: HF_TOKEN
            value: "` + hfTokenValue + `"
---
apiVersion: v1
kind: Secret
metadata:
  name: extra
  namespace: ai-inference
stringData:
  token: ` + secretValue + `
`
)

type remediationDoc struct {
	SchemaVersion string `json:"schemaVersion"`
	Mode          string `json:"mode"`
	ScanSHA256    string `json:"scanSha256"`
	Items         []struct {
		Check  string `json:"check"`
		Object struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"object"`
		Container string `json:"container"`
		Path      string `json:"path"`
		Action    string `json:"action"`
		File      string `json:"file"`
		Reason    string `json:"reason"`
	} `json:"items"`
}

func scanJSON(t *testing.T, ns string, inputs ...string) []byte {
	t.Helper()
	r, err := scan.Manifest(scan.Options{Inputs: inputs, Namespace: ns, ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeInput(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func remediation(t *testing.T, b *Bundle) remediationDoc {
	t.Helper()
	var doc remediationDoc
	if err := json.Unmarshal(b.Files["remediation.json"], &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func buildBundle(t *testing.T, b *Bundle) []map[string]any {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "out")
	if err := Write(dir, b); err != nil {
		t.Fatal(err)
	}
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), dir)
	if err != nil {
		t.Fatalf("kustomize build: %v", err)
	}
	var out []map[string]any
	for _, r := range m.Resources() {
		y, err := r.AsYAML()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, parseObj(t, string(y)))
	}
	return out
}

func goldenBundle(t *testing.T, mode, dir string) {
	t.Chdir("../..")
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", toxicInput), Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := Write(dir, b); err != nil {
			t.Fatal(err)
		}
	}
	var want []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		want = append(want, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for name := range b.Files {
		got = append(got, name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("files %v, golden %v (run with -update and review the diff)", got, want)
	}
	for _, name := range want {
		golden, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Files[name], golden) {
			t.Errorf("%s differs from %s (run with -update and review the diff)", name, dir)
		}
	}
	buildBundle(t, b)
}

func TestToxicAudit(t *testing.T) {
	goldenBundle(t, "audit", "test/golden/remediate/toxic-audit")
}

func TestToxicEnforce(t *testing.T) {
	goldenBundle(t, "enforce", "test/golden/remediate/toxic-enforce")
}

func TestMismatchedScan(t *testing.T) {
	p := writeInput(t, helmVLLMYAML)
	sj := scanJSON(t, "ai-inference", p)
	if _, err := Run(Options{ScanJSON: sj, Namespace: "other"}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("other namespace: err=%v, want ErrMismatch", err)
	}
	pinned := strings.Replace(helmVLLMYAML, "vllm/vllm-openai:v0.31.0", "vllm/vllm-openai@sha256:"+strings.Repeat("ab", 32), 1)
	if err := os.WriteFile(p, []byte(pinned), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Run(Options{ScanJSON: sj})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err=%v, want ErrMismatch", err)
	}
	want := "scan.json does not match the inputs: KS-WL-012 Deployment/ai-inference/vllm /spec/template/spec/containers/0/image"
	if err.Error() != want {
		t.Fatalf("err=%q, want %q", err, want)
	}
}

func TestNamespaceFromScan(t *testing.T) {
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, helmVLLMYAML))})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b.Files["base/manifests.yaml"]), "  namespace: ai-inference\n") {
		t.Fatalf("base has no namespace:\n%s", b.Files["base/manifests.yaml"])
	}
	j := "workload-patch-6902/apps_Deployment_ai-inference_vllm.yaml"
	if _, ok := b.Files[j]; !ok {
		t.Fatalf("no %s in %v", j, fileNames(b))
	}
	k := string(b.Files["kustomization.yaml"])
	for _, want := range []string{"- path: " + j + "\n  target:\n", "    namespace: ai-inference\n", "- path: workload-patch.yaml\n"} {
		if !strings.Contains(k, want) {
			t.Fatalf("kustomization.yaml has no %q:\n%s", want, k)
		}
	}
	if strings.Index(k, j) > strings.Index(k, "path: workload-patch.yaml") {
		t.Fatalf("6902 patches must come before workload-patch.yaml:\n%s", k)
	}
	if !strings.Contains(string(b.Files["workload-patch.yaml"]), "  namespace: ai-inference\n") {
		t.Fatalf("SMP has no namespace:\n%s", b.Files["workload-patch.yaml"])
	}
	if !strings.Contains(string(b.Files["MANUAL.md"]), "## Helm-managed objects") {
		t.Fatalf("MANUAL.md has no Helm section")
	}
	for _, o := range buildBundle(t, b) {
		md := o["metadata"].(map[string]any)
		if md["namespace"] != "ai-inference" {
			t.Fatalf("built %v/%v has namespace %v", o["kind"], md["name"], md["namespace"])
		}
	}
}

func helmSection(t *testing.T, input string) string {
	t.Helper()
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, input))})
	if err != nil {
		t.Fatal(err)
	}
	manual := string(b.Files["MANUAL.md"])
	start := strings.Index(manual, "## Helm-managed objects\n")
	if start < 0 {
		return ""
	}
	end := strings.Index(manual[start:], "\n## Residual items\n")
	if end < 0 {
		t.Fatalf("no Residual items section after the Helm section:\n%s", manual)
	}
	return manual[start : start+end]
}

func TestHelmPostRenderer(t *testing.T) {
	sec := helmSection(t, helmVLLMYAML)
	for _, want := range []string{
		"- `Deployment/ai-inference/vllm`\n",
		"`kshield-postrender/plugin.yaml`:\n\n```yaml\napiVersion: v1\nname: kshield-postrender\nversion: 0.1.0\ntype: postrenderer/v1\nruntime: subprocess\nruntimeConfig:\n  platformCommand:\n  - command: ${HELM_PLUGIN_DIR}/postrender.sh\n```\n",
		"`kshield-postrender/postrender.sh`:\n\n```bash\n#!/usr/bin/env bash\nset -euo pipefail\n",
		"unsetOnly: true\\n",
		"kustomize build \"$work/ns\" >\"$work/bundle/base/manifests.yaml\"\nkustomize build \"$work/bundle\"\n```\n",
		"helm plugin install ./kshield-postrender",
		"--post-renderer kshield-postrender --post-renderer-args <absolute path of this bundle dir> --post-renderer-args <namespace>",
		"kustomize also sets that namespace on every cluster-scoped custom resource (for example `ClusterServingRuntime`). Only the `helm template` output of step 4 shows it",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("Helm section has no %q:\n%s", want, sec)
		}
	}
	if strings.Contains(sec, "literal secret values") {
		t.Errorf("Helm section warns about moved secrets with none moved:\n%s", sec)
	}
}

func TestHelmPostRendererMovedSecrets(t *testing.T) {
	args := "        args: [\"serve\", \"/models/m\", \"--trust-remote-code\", \"--port\", \"8000\"]\n"
	in := strings.Replace(helmVLLMYAML, args, args+"        env:\n        - name: HF_TOKEN\n          value: \""+hfTokenValue+"\"\n", 1)
	if in == helmVLLMYAML {
		t.Fatal("env did not apply")
	}
	sec := helmSection(t, in)
	want := "kshield moved literal secret values of these objects to Secrets in `base/manifests.yaml` only:\n\n- `Deployment/ai-inference/vllm`\n"
	if !strings.Contains(sec, want) {
		t.Fatalf("Helm section has no %q:\n%s", want, sec)
	}
	if i, j := strings.Index(sec, want), strings.Index(sec, "\n1. Scan each Helm release"); j < 0 || i > j {
		t.Fatalf("moved-secret paragraph at %d is not before step 1 at %d:\n%s", i, j, sec)
	}
	if sec := helmSection(t, secretsInYAML); sec != "" {
		t.Fatalf("Helm section without a Helm object:\n%s", sec)
	}
}

func TestIncompleteScan(t *testing.T) {
	var r report.Report
	if err := json.Unmarshal(scanJSON(t, "ai-inference", writeInput(t, helmVLLMYAML)), &r); err != nil {
		t.Fatal(err)
	}
	r.Summary.Incomplete = true
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, &r); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{ScanJSON: buf.Bytes()}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err=%v, want ErrIncomplete", err)
	}
}

func TestRunInputErrors(t *testing.T) {
	p := writeInput(t, helmVLLMYAML)
	good := scanJSON(t, "ai-inference", p)
	edit := func(f func(*report.Report)) []byte {
		var r report.Report
		if err := json.Unmarshal(good, &r); err != nil {
			t.Fatal(err)
		}
		f(&r)
		var buf bytes.Buffer
		if err := report.WriteJSON(&buf, &r); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	cases := []struct {
		name string
		opt  Options
		want string
	}{
		{"not json", Options{ScanJSON: []byte("{")}, "scan.json"},
		{"schema", Options{ScanJSON: edit(func(r *report.Report) { r.SchemaVersion = "x/v9" })}, "schemaVersion"},
		{"stdin", Options{ScanJSON: edit(func(r *report.Report) { r.Scan.Inputs = []string{"-"} })}, "-f"},
		{"profile hash", Options{ScanJSON: edit(func(r *report.Report) { r.Profile.SHA256 = strings.Repeat("0", 64) })}, "sha256"},
		{"mode", Options{ScanJSON: good, Mode: "strict"}, "strict"},
		{"cidr", Options{ScanJSON: good, AllowCIDR: []string{"0.0.0.0/0"}}, "0.0.0.0/0"},
		{"fqdn", Options{ScanJSON: good, AllowFQDN: []string{"api.svc"}}, "api.svc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(tc.opt)
			if err == nil || errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want an error with %q", err, tc.want)
			}
		})
	}
}

func TestOwnerReferencesManual(t *testing.T) {
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, ownedYAML))})
	if err != nil {
		t.Fatal(err)
	}
	doc := remediation(t, b)
	patched := false
	checks := map[string]bool{}
	for _, it := range doc.Items {
		switch it.Object.Name {
		case "vllm":
			patched = patched || it.Action == "patch"
		case "vllm-abc", "vllm-abc-x1", "orphan":
			if it.Action == "policy" {
				continue
			}
			if it.Object.Name == "orphan" {
				checks[it.Check] = true
			}
			owner := "Deployment/ai-inference/vllm"
			if it.Object.Name == "orphan" {
				owner = "ReplicaSet/ai-inference/gone"
			}
			if it.Action != "manual" || !strings.Contains(it.Reason, owner) || (it.Object.Name == "orphan") != strings.Contains(it.Reason, "not in the input") {
				t.Fatalf("%s %s/%s: action=%s reason=%q", it.Check, it.Object.Kind, it.Object.Name, it.Action, it.Reason)
			}
		}
	}
	if !patched {
		t.Fatal("the Deployment got no patch")
	}
	for _, id := range []string{"KS-WL-001", "KS-WL-011", "KS-WL-012", "KS-WL-013"} {
		if !checks[id] {
			t.Fatalf("no %s item on the orphan Pod", id)
		}
	}
	for name, content := range b.Files {
		if strings.HasPrefix(name, "workload-patch") && (strings.Contains(string(content), "vllm-abc") || strings.Contains(string(content), "orphan")) {
			t.Fatalf("%s patches an owned object:\n%s", name, content)
		}
		if strings.Contains(string(content), hfTokenValue) {
			t.Fatalf("%s holds the secret value of the owned Pod", name)
		}
	}
	base := string(b.Files["base/manifests.yaml"])
	if strings.Contains(base, "vllm-abc") || strings.Contains(base, "orphan") {
		t.Fatalf("base keeps an owned object:\n%s", base)
	}
	manual := string(b.Files["MANUAL.md"])
	for _, want := range []string{"### Generated objects left out of the bundle", "- `ReplicaSet/ai-inference/vllm-abc`", "- `Pod/ai-inference/vllm-abc-x1`", "- `Pod/ai-inference/orphan`"} {
		if !strings.Contains(manual, want) {
			t.Fatalf("MANUAL.md has no %q:\n%s", want, manual)
		}
	}
	for _, o := range buildBundle(t, b) {
		if o["kind"] != "Deployment" {
			t.Fatalf("built output holds %v", o["kind"])
		}
	}
}

func containersOf(v any, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["image"]; ok {
			*out = append(*out, x)
		}
		for _, e := range x {
			containersOf(e, out)
		}
	case []any:
		for _, e := range x {
			containersOf(e, out)
		}
	}
}

func envItem(c map[string]any, name string) map[string]any {
	env, _ := c["env"].([]any)
	for _, e := range env {
		if m, _ := e.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

func fromSecret(e map[string]any) bool {
	if e == nil || e["value"] != nil {
		return false
	}
	vf, _ := e["valueFrom"].(map[string]any)
	ref, _ := vf["secretKeyRef"].(map[string]any)
	return ref["name"] == "vllm-kshield-env" || ref["name"] == "rc-kshield-env"
}

func TestNoSecretValues(t *testing.T) {
	ref := "$(" + movedAPIKeyEnv + ")"
	for _, mode := range []string{"audit", "enforce"} {
		b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, secretsInYAML)), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		for name, content := range b.Files {
			for _, v := range []string{hfTokenValue, apiKeyValue, secretValue} {
				if strings.Contains(string(content), v) {
					t.Fatalf("%s: %s holds the secret value %q", mode, name, v)
				}
			}
		}
		manual := string(b.Files["MANUAL.md"])
		for _, want := range []string{"generic vllm-kshield-env -n ai-inference", "generic rc-kshield-env -n ai-inference"} {
			if !strings.Contains(manual, want) {
				t.Fatalf("MANUAL.md has no %q:\n%s", want, manual)
			}
		}
		for _, it := range remediation(t, b).Items {
			if strings.Contains(it.Reason, "literal --api-key") {
				t.Fatalf("%s: stale residual %s %s: %s", mode, it.Check, it.Container, it.Reason)
			}
		}
		var cs []map[string]any
		for _, o := range buildBundle(t, b) {
			if o["kind"] == "Secret" {
				t.Fatalf("base keeps the input Secret %v", o["metadata"])
			}
			containersOf(o, &cs)
		}
		refs, tokens, loads := 0, 0, 0
		for _, c := range cs {
			words := fmt.Sprint(c["command"], c["args"])
			if strings.Contains(words, ref) {
				refs++
				if !fromSecret(envItem(c, movedAPIKeyEnv)) {
					t.Fatalf("%s: container %v uses %s without its env item: env %v", mode, c["name"], ref, c["env"])
				}
			}
			if strings.Contains(words, "--load-format safetensors") {
				loads++
			}
			if e := envItem(c, "HF_TOKEN"); e != nil {
				tokens++
				if !fromSecret(e) {
					t.Fatalf("%s: container %v HF_TOKEN is not from the Secret: %v", mode, c["name"], e)
				}
			}
		}
		if refs != 3 || tokens != 2 || loads != 3 {
			t.Fatalf("%s: %d containers with %s (want 3), %d with HF_TOKEN (want 2), %d with --load-format safetensors (want 3)", mode, refs, ref, tokens, loads)
		}
	}
}

func TestSecretNamesUniquePerOwner(t *testing.T) {
	workload := func(kind string) string {
		return `apiVersion: apps/v1
kind: ` + kind + `
metadata:
  name: vllm
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: vllm-` + strings.ToLower(kind) + `
  template:
    metadata:
      labels:
        app: vllm-` + strings.ToLower(kind) + `
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        args: ["serve", "/models/m", "--port", "8000"]
        env:
        - name: HF_TOKEN
          value: "` + hfTokenValue + `"
`
	}
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, workload("Deployment")+"---\n"+workload("StatefulSet")))})
	if err != nil {
		t.Fatal(err)
	}
	manual := string(b.Files["MANUAL.md"])
	for _, want := range []string{
		"generic vllm-deployment-vllm-api-key -n ai-inference",
		"generic vllm-statefulset-vllm-api-key -n ai-inference",
		"generic vllm-deployment-kshield-env -n ai-inference",
		"generic vllm-statefulset-kshield-env -n ai-inference",
	} {
		if !strings.Contains(manual, want) {
			t.Errorf("MANUAL.md has no %q:\n%s", want, manual)
		}
	}
	got := map[string][]string{}
	for _, o := range buildBundle(t, b) {
		var cs []map[string]any
		containersOf(o, &cs)
		for _, c := range cs {
			for _, name := range []string{"HF_TOKEN", vllmAPIKeyEnv} {
				vf, _ := envItem(c, name)["valueFrom"].(map[string]any)
				ref, _ := vf["secretKeyRef"].(map[string]any)
				got[fmt.Sprint(o["kind"])] = append(got[fmt.Sprint(o["kind"])], fmt.Sprint(ref["name"]))
			}
		}
	}
	want := map[string][]string{
		"Deployment":  {"vllm-deployment-kshield-env", "vllm-deployment-vllm-api-key"},
		"StatefulSet": {"vllm-statefulset-kshield-env", "vllm-statefulset-vllm-api-key"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Secret names %v, want %v", got, want)
	}
}

func manualDeployment(name, args, extra string) string {
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ` + name + `
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: ` + name + `
  template:
    metadata:
      labels:
        app: ` + name + `
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        args: ` + args + `
` + extra
}

func TestManualEnforceWarnings(t *testing.T) {
	serve := `["serve", "/models/m", "--port", "8000"]`
	input := strings.Join([]string{
		manualDeployment("shm", serve, `        volumeMounts:
        - name: shm
          mountPath: /dev/shm
      volumes:
      - name: shm
        hostPath:
          path: /dev/shm
`),
		manualDeployment("models", serve, `        volumeMounts:
        - name: models
          mountPath: /models
      volumes:
      - name: models
        hostPath:
          path: /models
`),
		manualDeployment("rootmount", serve, `        volumeMounts:
        - name: cache
          mountPath: /root/.cache
      volumes:
      - name: cache
        emptyDir: {}
`),
		manualDeployment("clean", `["serve", "/models/m", "--trust-remote-code", "--port", "8000"]`, ""),
	}, "---\n")
	for _, mode := range []string{"audit", "enforce"} {
		b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, input)), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		manual := string(b.Files["MANUAL.md"])
		for _, want := range []string{
			"- The `kshield-pod-security` rule of the `kshield-admission` Policy enforces the Pod Security Standards `restricted` profile. ",
			"Workloads of this bundle: `Deployment/ai-inference/models`, `Deployment/ai-inference/rootmount`.\n",
			"build and apply the whole enforce bundle (`kustomize build . | kubectl apply -f -`), because its KS-NET-002 enforce patches are in `workload-patch-6902/`",
			"### Remote code (KS-AI-002)\n\nThe patch removes `--trust-remote-code`.",
			"\n\n- `Deployment/ai-inference/clean` container `vllm`\n\n### Model weights (KS-AI-003)",
		} {
			if !strings.Contains(manual, want) {
				t.Errorf("%s: MANUAL.md has no %q:\n%s", mode, want, manual)
			}
		}
	}
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, manualDeployment("clean", serve, "")))})
	if err != nil {
		t.Fatal(err)
	}
	if want := "No workload of this bundle has such a residual item or a hostPath volume.\n"; !strings.Contains(string(b.Files["MANUAL.md"]), want) {
		t.Errorf("MANUAL.md has no %q:\n%s", want, b.Files["MANUAL.md"])
	}
}

func TestManualOtherWorkloads(t *testing.T) {
	serve := `["serve", "/models/m", "--port", "8000"]`
	other := func(kind, ns, name, image string) string {
		return `apiVersion: apps/v1
kind: ` + kind + `
metadata:
  name: ` + name + `
  namespace: ` + ns + `
spec:
  selector:
    matchLabels:
      app: ` + name + `
  template:
    metadata:
      labels:
        app: ` + name + `
    spec:
      containers:
      - name: main
        image: ` + image + `
`
	}
	input := strings.Join([]string{
		manualDeployment("models", serve, ""),
		other("StatefulSet", "ai-inference", "etcd", "quay.io/coreos/etcd:v3.5.21"),
		other("Deployment", "ai-inference", "minio", "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"),
		other("Deployment", "tools", "busy", "busybox:1.38.0"),
	}, "---\n")
	want := "- kshield checks and patches AI workloads only, but the policies of a namespace apply to all its pods: " +
		"the egress policy, the shell-exec guard and the `kshield-pod-security` rule. " +
		"Other workloads in the namespaces with policies: `Deployment/ai-inference/minio`, `StatefulSet/ai-inference/etcd`. " +
		"kshield does not patch them: in enforce mode the `kshield-pod-security` rule rejects their new pods that break the `restricted` profile, " +
		"so set their security context to that profile first. " +
		"Run an operator or controller among them (for example the KubeRay operator) in a namespace without these policies, " +
		"or give only its pods an egress rule to the API server: a CiliumNetworkPolicy with an `endpointSelector` on its pod labels and `toEntities: [kube-apiserver]`. " +
		"This bundle adds an API server rule only for a RayCluster with the in-tree autoscaler, and that rule is the `kshield-egress-apiserver` policy, which selects only the Ray head pods (`ray.io/node-type: head`) of the namespace.\n"
	for _, mode := range []string{"audit", "enforce"} {
		b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, input)), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		manual := string(b.Files["MANUAL.md"])
		if !strings.Contains(manual, want) {
			t.Errorf("%s: MANUAL.md has no %q:\n%s", mode, want, manual)
		}
		if strings.Contains(manual, "tools/busy") {
			t.Errorf("%s: MANUAL.md names a workload outside the namespaces with policies:\n%s", mode, manual)
		}
	}
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, manualDeployment("models", serve, ""))), Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b.Files["MANUAL.md"]), "Other workloads in the namespaces with policies") {
		t.Errorf("MANUAL.md names other workloads, but the input has none:\n%s", b.Files["MANUAL.md"])
	}
}

func TestManualRayShellGuard(t *testing.T) {
	ray := func(ns, name string) string {
		return `apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: ` + name + `
  namespace: ` + ns + `
spec:
  headGroupSpec:
    template:
      spec:
        containers:
        - name: ray-head
          image: rayproject/ray:2.52.0
  workerGroupSpecs:
  - groupName: cpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.52.0
`
	}
	input := strings.Join([]string{ray("ai-inference", "rc"), ray("ai-inference", "batch")}, "---\n")
	want := "- Ray starts shells from its Python processes: the dashboard, the client server, the autoscaler v2 monitor, `multiprocessing` spawn children and a `ray start` fork. " +
		"In enforce mode the shell-exec guard kills them, and the Ray head does not start (measured with `rayproject/ray:2.52.0`). " +
		"kshield has no allow-list for Ray. Keep the namespaces of these workloads in audit: `RayCluster/ai-inference/batch`, `RayCluster/ai-inference/rc`.\n"
	for _, mode := range []string{"audit", "enforce"} {
		b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, input)), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		manual := string(b.Files["MANUAL.md"])
		if !strings.Contains(manual, want) {
			t.Errorf("%s: MANUAL.md has no %q:\n%s", mode, want, manual)
		}
		if n := strings.Count(manual, "Ray starts shells"); n != 1 {
			t.Errorf("%s: MANUAL.md has the Ray item %d times:\n%s", mode, n, manual)
		}
	}
	serve := `["serve", "/models/m", "--port", "8000"]`
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, manualDeployment("models", serve, ""))), Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b.Files["MANUAL.md"]), "Ray starts shells") {
		t.Errorf("MANUAL.md has the Ray item, but the input has no Ray workload:\n%s", b.Files["MANUAL.md"])
	}
}

func TestManualImageUID(t *testing.T) {
	milvus := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: milvus
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: milvus
  template:
    metadata:
      labels:
        app: milvus
    spec:
      containers:
      - name: standalone
        image: milvusdb/milvus:v3.0.3
        args: ["milvus", "run", "standalone"]
`
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, milvus)), Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	manual := string(b.Files["MANUAL.md"])
	for _, want := range []string{
		"### Image user IDs (KS-WL-001)\n\nThe patch runs these containers as the uid and gid of their image, not as 1000. ",
		"the files of `milvusdb/milvus:v3.0.3` are owned by uid 999 (`milvus`)",
		"- `Deployment/ai-inference/milvus` container `standalone`: uid 999\n",
	} {
		if !strings.Contains(manual, want) {
			t.Errorf("MANUAL.md has no %q:\n%s", want, manual)
		}
	}
	b, err = Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, manualDeployment("models", `["serve", "/models/m"]`, ""))), Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b.Files["MANUAL.md"]), "Image user IDs") {
		t.Errorf("MANUAL.md has the image uid section for a vLLM-only input:\n%s", b.Files["MANUAL.md"])
	}
}

func TestDeterministic(t *testing.T) {
	t.Chdir("../..")
	opt := Options{
		ScanJSON:  scanJSON(t, "ai-inference", toxicInput),
		Mode:      "enforce",
		AllowFQDN: []string{"huggingface.co", "api.example.com"},
		AllowCIDR: []string{"203.0.113.0/24", "169.254.20.10/32"},
	}
	a, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Files, b.Files) {
		t.Fatal("two runs differ")
	}
}

func TestWriteRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, &Bundle{Files: map[string][]byte{"a.yaml": nil}}); err == nil {
		t.Fatal("Write into a non-empty dir must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "a.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Write wrote into a non-empty dir: %v", err)
	}
}

func TestManualStepsForEveryManualCheck(t *testing.T) {
	for _, id := range manualCheckIDs() {
		if strings.TrimSpace(manualSteps[id]) == "" {
			t.Errorf("%s has no manual steps", id)
		}
	}
}

func fileNames(b *Bundle) []string {
	var out []string
	for k := range b.Files {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

const existingGuardYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai-inference
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
          image: vllm/vllm-openai:v0.31.0
          args: ["--model", "m", "--load-format", "safetensors"]
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: kshield-shell-exec
  namespace: ai-inference
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      selectors:
        - matchActions:
            - action: Post
`

func policyNames(t *testing.T, b *Bundle) []string {
	t.Helper()
	var out []string
	for _, doc := range strings.Split(string(b.Files[FilePolicies]), "---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		o := parseObj(t, doc)
		md := o["metadata"].(map[string]any)
		out = append(out, o["kind"].(string)+"/"+md["namespace"].(string)+"/"+md["name"].(string))
	}
	return out
}

func TestAuditKeepsExistingPolicies(t *testing.T) {
	sj := scanJSON(t, "ai-inference", writeInput(t, existingGuardYAML))
	shell := "TracingPolicyNamespaced/ai-inference/kshield-shell-exec"
	for mode, want := range map[string]bool{"audit": false, "enforce": true} {
		b, err := Run(Options{ScanJSON: sj, Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		names := policyNames(t, b)
		if got := slices.Contains(names, shell); got != want {
			t.Errorf("%s: %s in the policies is %v, want %v (%v)", mode, shell, got, want, names)
		}
		if !slices.Contains(names, "TracingPolicyNamespaced/ai-inference/kshield-egress-connect") {
			t.Errorf("%s: kshield-egress-connect missing: %v", mode, names)
		}
		kept := strings.Contains(string(b.Files[FileManual]), "leaves out `"+shell+"`")
		if kept == want {
			t.Errorf("%s: MANUAL.md names the kept kshield-shell-exec: %v, want %v", mode, kept, !want)
		}
		seen := map[string]bool{}
		for _, it := range remediation(t, b).Items {
			seen[it.Check] = true
			switch {
			case it.Check == "KS-RT-001" && !want:
				reason := "an existing TracingPolicyNamespaced/kshield-shell-exec already has this name; audit mode never changes it; switch it to enforce by hand or run with --mode enforce"
				if it.Action != ActionManual || it.File != "" || it.Reason != reason {
					t.Errorf("%s: KS-RT-001 item %s %q %q, want manual with the kept-policy reason", mode, it.Action, it.File, it.Reason)
				}
			case it.Check == "KS-RT-001" || it.Check == "KS-RT-002" || it.Check == "KS-RT-003" || it.Check == "KS-NET-001":
				if it.Action != ActionPolicy || it.File != FilePolicies {
					t.Errorf("%s: %s item %s %q, want policy in %s", mode, it.Check, it.Action, it.File, FilePolicies)
				}
			}
		}
		if !seen["KS-RT-001"] || !seen["KS-RT-002"] {
			t.Errorf("%s: items %v, want KS-RT-001 and KS-RT-002", mode, seen)
		}
	}
}

func TestAuditAllPoliciesKept(t *testing.T) {
	guards := policyDocs(t, mustPolicies(t, []string{"ai-inference"}, PolicyOptions{Mode: "audit"}))
	input := joinDocs(t, append([]string{vllmIn(t, "ai-inference")}, guards...)...)
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", writeInput(t, input))})
	if err != nil {
		t.Fatal(err)
	}
	if p := b.Files[FilePolicies]; len(p) > 0 {
		t.Fatalf("policies written although all are in the input:\n%s", p)
	}
	manual := string(b.Files[FileManual])
	if strings.Contains(manual, "Namespaces with policies in this bundle") || !strings.Contains(manual, "This bundle has no policies.\n") {
		t.Errorf("MANUAL.md lists namespaces with policies:\n%s", manual)
	}
	n := 0
	for _, it := range remediation(t, b).Items {
		if it.File == FilePolicies || it.Action == ActionPolicy {
			t.Errorf("%s item %s %q claims the policies file", it.Check, it.Action, it.File)
		}
		if strings.HasPrefix(it.Check, "KS-RT-") || it.Check == "KS-NET-001" {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no KS-NET-001 or KS-RT-* item; the audit guards gave no WARN")
	}
}
