package remediate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	clusterToxicInput = "../../test/corpus/baseline/toxic/input.yaml"
	clusterNS         = "ai-inference"
	liveSecretValue   = "c2VjcmV0LXZhbHVl"

	clusterExtrasYAML = `apiVersion: v1
kind: Secret
metadata:
  name: models-token
  namespace: ai-inference
  uid: uid-secret
  resourceVersion: "9"
type: Opaque
data:
  token: c2VjcmV0LXZhbHVl
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: models-config
  namespace: ai-inference
  uid: uid-configmap
data:
  model: Qwen2.5-7B-Instruct
---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: vllm-5d9
  namespace: ai-inference
  uid: uid-rs
  ownerReferences:
  - apiVersion: apps/v1
    kind: Deployment
    name: vllm
    uid: uid-Deployment-vllm
    controller: true
spec:
  replicas: 1
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
  name: vllm-5d9-abcde
  namespace: ai-inference
  uid: uid-pod
  labels:
    app: vllm
  ownerReferences:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: vllm-5d9
    uid: uid-rs
    controller: true
spec:
  containers:
  - name: vllm
    image: vllm/vllm-openai:v0.31.0
  - name: istio-proxy
    image: istio/proxyv2:1.30.0
    securityContext:
      privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: notebook
  namespace: ai-inference
  uid: uid-notebook
spec:
  containers:
  - name: lab
    image: vllm/vllm-openai:v0.31.0
    securityContext:
      privileged: true
`

	literalsYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm
  namespace: ai-inference
  uid: uid-llm
spec:
  selector:
    matchLabels:
      app: llm
  template:
    metadata:
      labels:
        app: llm
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        args: ["--model", "m", "--api-key", "sk-live-1234567890"]
        env:
        - name: HF_TOKEN
          value: hf_abcdefghijklmnop
`
	literalToken  = "hf_abcdefghijklmnop"
	literalAPIKey = "sk-live-1234567890"
)

var serverFields = []struct {
	name  string
	field []string
}{
	{"status", []string{"status"}},
	{"managedFields", []string{"metadata", "managedFields"}},
	{"resourceVersion", []string{"metadata", "resourceVersion"}},
	{"uid", []string{"metadata", "uid"}},
	{"creationTimestamp", []string{"metadata", "creationTimestamp"}},
	{"generation", []string{"metadata", "generation"}},
	{"last-applied-configuration", []string{"metadata", "annotations", lastAppliedAnnotation}},
	{"deployment revision", []string{"metadata", "annotations", revisionAnnotation}},
}

func liveObjects(t *testing.T) []load.Object {
	t.Helper()
	objs := readObjects(t, clusterNS, clusterToxicInput)
	for i := range objs {
		u := objs[i].U
		u.SetUID(types.UID("uid-" + u.GetKind() + "-" + u.GetName()))
		u.SetResourceVersion("4711")
		u.SetGeneration(3)
		u.SetCreationTimestamp(metav1.NewTime(time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)))
		u.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply}})
		annotations := map[string]string{lastAppliedAnnotation: `{"kind":"` + u.GetKind() + `"}`}
		if u.GetKind() == "Deployment" && u.GetName() == "vllm" {
			annotations["team"] = "ml-platform"
			annotations[revisionAnnotation] = "7"
		}
		u.SetAnnotations(annotations)
		u.Object["status"] = map[string]any{"observedGeneration": int64(3)}
	}
	return append(objs, readObjects(t, clusterNS, writeInput(t, clusterExtrasYAML))...)
}

func cloneObjects(objs []load.Object) []load.Object {
	out := make([]load.Object, len(objs))
	for i, o := range objs {
		out[i] = o
		out[i].U = o.U.DeepCopy()
	}
	return out
}

func clusterScanJSON(t *testing.T, objs []load.Object) []byte {
	t.Helper()
	r, err := scan.ClusterObjects(objs, nil, scan.ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Incomplete {
		t.Fatalf("test scan is incomplete: %v", r.Errors)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func baseDocs(t *testing.T, b *Bundle) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, doc := range strings.Split(string(b.Files[FileBase]), "---\n") {
		if strings.TrimSpace(doc) != "" {
			out = append(out, parseObj(t, doc))
		}
	}
	return out
}

func docID(m map[string]any) string {
	u := unstructured.Unstructured{Object: m}
	return u.GetKind() + "/" + u.GetNamespace() + "/" + u.GetName()
}

func TestClusterBaseStripped(t *testing.T) {
	objs := liveObjects(t)
	b, err := Run(Options{ScanJSON: clusterScanJSON(t, objs), Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{}
	for _, it := range remediation(t, b).Items {
		if it.Action == ActionPatch {
			targets[it.Object.Kind+"/"+it.Object.Namespace+"/"+it.Object.Name] = true
		}
	}
	for _, want := range []string{"Deployment/ai-inference/vllm", "Deployment/ai-inference/qdrant", "RayCluster/ai-inference/rc"} {
		if !targets[want] {
			t.Errorf("%s has no patch; targets %v", want, targets)
		}
	}
	docs := baseDocs(t, b)
	got := map[string]bool{}
	for _, d := range docs {
		id := docID(d)
		got[id] = true
		if !targets[id] {
			t.Errorf("base holds %s, which no patch targets", id)
		}
		for _, f := range serverFields {
			if _, found, _ := unstructured.NestedFieldNoCopy(d, f.field...); found {
				t.Errorf("%s still has %s", id, f.name)
			}
		}
	}
	for id := range targets {
		if !got[id] {
			t.Errorf("patch target %s is not in base", id)
		}
	}
	for _, d := range docs {
		if k := d["kind"]; k == "Secret" || k == "ConfigMap" || k == "ReplicaSet" || k == "Pod" {
			t.Errorf("base holds a %v", k)
		}
	}
	for _, d := range docs {
		if docID(d) == "Deployment/ai-inference/vllm" {
			if a, _, _ := unstructured.NestedStringMap(d, "metadata", "annotations"); a["team"] != "ml-platform" || len(a) != 1 {
				t.Errorf("annotations %v, want only team", a)
			}
		}
	}
	for name, content := range b.Files {
		if strings.Contains(string(content), liveSecretValue) {
			t.Errorf("%s holds the Secret value", name)
		}
	}
}

func TestClusterBundleBuilds(t *testing.T) {
	objs := liveObjects(t)
	b, err := Run(Options{ScanJSON: clusterScanJSON(t, objs), Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	built := buildBundle(t, b)
	if len(built) != len(baseDocs(t, b)) {
		t.Fatalf("built %d objects, base has %d", len(built), len(baseDocs(t, b)))
	}
	for _, m := range built {
		if docID(m) == "Deployment/ai-inference/vllm" {
			c, _, _ := unstructured.NestedSlice(m, "spec", "template", "spec", "containers")
			sc, _, _ := unstructured.NestedMap(c[0].(map[string]any), "securityContext")
			if sc["runAsNonRoot"] != true {
				t.Errorf("patched vllm securityContext %v", sc)
			}
		}
	}
}

func TestClusterLivePodFindingIsManual(t *testing.T) {
	objs := liveObjects(t)
	b, err := Run(Options{ScanJSON: clusterScanJSON(t, objs), Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, it := range remediation(t, b).Items {
		if it.Object.Kind != "Pod" || it.Action == ActionPolicy {
			continue
		}
		seen[it.Object.Name] = true
		want := "a running Pod cannot be changed in place; change its owner Deployment/ai-inference/vllm"
		if it.Object.Name == "notebook" {
			want = "a running Pod cannot be changed in place; change its source"
		}
		if it.Action != ActionManual || !strings.Contains(it.Reason, want) {
			t.Errorf("%s on %s: action %s reason %q, want %q", it.Check, it.Object.Name, it.Action, it.Reason, want)
		}
	}
	for _, name := range []string{"vllm-5d9-abcde", "notebook"} {
		if !seen[name] {
			t.Errorf("no finding on the live pod %s", name)
		}
	}
	for _, name := range []string{FileWorkloadPatch, FileBase} {
		for _, bad := range []string{"istio-proxy", "notebook"} {
			if strings.Contains(string(b.Files[name]), bad) {
				t.Errorf("%s names %s", name, bad)
			}
		}
	}
}

func rescanWithFindings(t *testing.T, objs []load.Object, edit func(*report.Report)) []byte {
	t.Helper()
	var sr report.Report
	if err := json.Unmarshal(clusterScanJSON(t, objs), &sr); err != nil {
		t.Fatal(err)
	}
	edit(&sr)
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, &sr); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addFinding(r *report.Report, id string, f report.Finding) {
	for i, c := range r.Checks {
		if c.ID == id {
			r.Checks[i].Findings = append(r.Checks[i].Findings, f)
		}
	}
}

func TestClusterPodRenamedIsNotMismatch(t *testing.T) {
	objs := liveObjects(t)
	scanned := clusterScanJSON(t, objs)
	renamed := cloneObjects(objs)
	for _, o := range renamed {
		if o.U.GetKind() == "Pod" && o.U.GetName() == "vllm-5d9-abcde" {
			o.U.SetName("vllm-5d9-zzzzz")
		}
	}
	for i := range renamed {
		if renamed[i].U.GetName() == "vllm-5d9-zzzzz" {
			renamed[i].Ref.Name = "vllm-5d9-zzzzz"
		}
	}
	b, err := Run(Options{ScanJSON: scanned, Objects: renamed})
	if err != nil {
		t.Fatal(err)
	}
	gone := false
	for _, it := range remediation(t, b).Items {
		if it.Object.Name == "vllm-5d9-abcde" {
			gone = true
			if it.Action != ActionManual || !strings.Contains(it.Reason, "is not in the cluster any more") {
				t.Errorf("%s on the old pod: action %s reason %q", it.Check, it.Action, it.Reason)
			}
		}
	}
	if !gone {
		t.Error("the findings of the old pod are not in remediation.json")
	}
}

func TestClusterManualChecksAreNotCompared(t *testing.T) {
	objs := liveObjects(t)
	ds := load.ObjectRef{APIVersion: "apps/v1", Kind: "DaemonSet", Namespace: "kube-system", Name: "tetragon"}
	scanned := rescanWithFindings(t, objs, func(r *report.Report) {
		addFinding(r, "KS-PRE-001", report.Finding{Object: ds, Message: "0 of 1 pods Ready", Verdict: report.VerdictFail})
	})
	b, err := Run(Options{ScanJSON: scanned, Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range remediation(t, b).Items {
		if it.Check == "KS-PRE-001" {
			found = true
			if it.Action != ActionManual {
				t.Errorf("KS-PRE-001 item %+v", it)
			}
		}
	}
	if !found {
		t.Error("the KS-PRE-001 finding of scan.json is not in remediation.json")
	}
}

func TestClusterLivePodDriftIsNotCompared(t *testing.T) {
	objs := liveObjects(t)
	vllm := load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: clusterNS, Name: "vllm"}
	scanned := rescanWithFindings(t, objs, func(r *report.Report) {
		addFinding(r, "KS-WL-001", report.Finding{
			Object: vllm, Container: "ghost", Path: "/spec/template/spec/containers/5/securityContext",
			Message: "live pod vllm-old: runs as root", Verdict: report.VerdictFail,
		})
	})
	b, err := Run(Options{ScanJSON: scanned, Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range remediation(t, b).Items {
		if it.Container == "ghost" {
			t.Errorf("an old drift finding became an item: %+v", it)
		}
	}
}

func TestClusterLiteralsAreRedacted(t *testing.T) {
	objs := readObjects(t, clusterNS, writeInput(t, literalsYAML))
	b, err := Run(Options{ScanJSON: clusterScanJSON(t, objs), Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range b.Files {
		for _, v := range []string{literalToken, literalAPIKey} {
			if strings.Contains(string(content), v) {
				t.Errorf("%s holds the literal %s", name, v)
			}
		}
	}
	docs := baseDocs(t, b)
	if len(docs) != 1 || docID(docs[0]) != "Deployment/ai-inference/llm" {
		t.Fatalf("base %v, want only the Deployment llm", docs)
	}
	if !strings.Contains(string(b.Files[FileBase]), "secretKeyRef") {
		t.Errorf("base does not read the values from a Secret:\n%s", b.Files[FileBase])
	}
	patched, moved := false, false
	for _, it := range remediation(t, b).Items {
		switch {
		case it.Action == ActionPatch:
			patched = true
		case it.Check == secretEnvCheck && strings.Contains(it.Reason, "the literal value is not in this bundle"):
			moved = true
		}
	}
	if !patched || !moved {
		t.Errorf("patched=%v, KS-WL-011 items with a reason=%v", patched, moved)
	}
	if !strings.Contains(string(b.Files[FileManual]), "kubectl create secret generic") {
		t.Error("MANUAL.md does not say how to create the Secret")
	}
}

func TestClusterRefusesFiles(t *testing.T) {
	objs := liveObjects(t)
	_, err := Run(Options{ScanJSON: clusterScanJSON(t, objs), Objects: objs, Inputs: []string{clusterToxicInput}})
	if !errors.Is(err, ErrClusterFiles) {
		t.Fatalf("err=%v, want ErrClusterFiles", err)
	}
	if err.Error() != "remediate: a cluster scan cannot be matched to files; scan the files with scan manifest" {
		t.Errorf("message %q", err)
	}
}

func TestClusterObjectsOnManifestScan(t *testing.T) {
	_, err := Run(Options{ScanJSON: scanJSON(t, clusterNS, clusterToxicInput), Objects: liveObjects(t)})
	if err == nil || !strings.Contains(err.Error(), "cluster scan") {
		t.Fatalf("err=%v", err)
	}
}

func TestClusterMismatch(t *testing.T) {
	objs := liveObjects(t)
	scanned := clusterScanJSON(t, objs)
	changed := cloneObjects(objs)
	for _, o := range changed {
		if o.U.GetKind() == "Deployment" && o.U.GetName() == "qdrant" {
			if err := unstructured.SetNestedField(o.U.Object, true, "spec", "template", "spec", "hostNetwork"); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err := Run(Options{ScanJSON: scanned, Objects: changed})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err=%v, want ErrMismatch", err)
	}
	_, err = Run(Options{ScanJSON: scanned, Objects: nil})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("no objects: err=%v, want ErrMismatch", err)
	}
}

func TestClusterSkipsProbeCheck(t *testing.T) {
	objs := liveObjects(t)
	var sr report.Report
	if err := json.Unmarshal(clusterScanJSON(t, objs), &sr); err != nil {
		t.Fatal(err)
	}
	for i, c := range sr.Checks {
		if c.ID != probeOnlyCheck {
			continue
		}
		sr.Checks[i].Verdict = report.VerdictWarn
		sr.Checks[i].Findings = []report.Finding{{
			Object:  load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: "n1"},
			Message: "BPF LSM is not active",
			Verdict: report.VerdictWarn,
		}}
	}
	sr.Scan.Cluster = &report.ClusterInfo{Context: "kind-test", NodeProbe: true, ProbeNamespace: "kube-system", Namespaces: []string{}}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, &sr); err != nil {
		t.Fatal(err)
	}
	b, err := Run(Options{ScanJSON: buf.Bytes(), Objects: objs})
	if err != nil {
		t.Fatal(err)
	}
	probe := false
	for _, it := range remediation(t, b).Items {
		if it.Check == probeOnlyCheck {
			probe = true
			if it.Object.Kind != "Node" || it.Action != ActionManual {
				t.Errorf("probe item %+v", it)
			}
		}
	}
	if !probe {
		t.Error("the probe finding of scan.json is not in remediation.json")
	}
}

func TestClusterIncompleteScanJSON(t *testing.T) {
	objs := liveObjects(t)
	var sr report.Report
	if err := json.Unmarshal(clusterScanJSON(t, objs), &sr); err != nil {
		t.Fatal(err)
	}
	sr.Summary.Incomplete = true
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, &sr); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{ScanJSON: buf.Bytes(), Objects: objs}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err=%v, want ErrIncomplete", err)
	}
}
