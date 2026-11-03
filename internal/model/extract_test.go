package model

import (
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sv222/kshield/internal/load"
)

type wantWorkload struct {
	owner      string
	specPath   string
	group      string
	containers []string
}

func readFiles(t *testing.T, names ...string) []load.Object {
	t.Helper()
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = "testdata/" + n
	}
	objs, err := load.Read(paths, load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func readInline(t *testing.T, doc string) []load.Object {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func summarize(ws []Workload) []wantWorkload {
	var out []wantWorkload
	for _, w := range ws {
		var cs []string
		for _, c := range w.Containers {
			cs = append(cs, c.Path)
		}
		out = append(out, wantWorkload{w.Owner.String(), w.SpecPath, w.Group, cs})
	}
	return out
}

func byPath(t *testing.T, ws []Workload, specPath string) Workload {
	t.Helper()
	for _, w := range ws {
		if w.SpecPath == specPath {
			return w
		}
	}
	t.Fatalf("no workload at %s", specPath)
	return Workload{}
}

func rayWant(owner, base string) []wantWorkload {
	head := base + "/headGroupSpec/template/spec"
	cpu := base + "/workerGroupSpecs/0/template/spec"
	gpu := base + "/workerGroupSpecs/1/template/spec"
	return []wantWorkload{
		{owner, head, "head", []string{head + "/containers/0"}},
		{owner, cpu, "cpu", []string{cpu + "/containers/0"}},
		{owner, gpu, "gpu", []string{gpu + "/containers/0"}},
	}
}

func TestExtractPaths(t *testing.T) {
	cases := []struct {
		file string
		want []wantWorkload
	}{
		{"deployment.yaml", []wantWorkload{{"Deployment/ai/vllm", "/spec/template/spec", "", []string{"/spec/template/spec/initContainers/0", "/spec/template/spec/containers/0"}}}},
		{"statefulset.yaml", []wantWorkload{{"StatefulSet/ai/qdrant", "/spec/template/spec", "", []string{"/spec/template/spec/containers/0"}}}},
		{"daemonset.yaml", []wantWorkload{{"DaemonSet/ai/agent", "/spec/template/spec", "", []string{"/spec/template/spec/containers/0"}}}},
		{"replicaset.yaml", []wantWorkload{{"ReplicaSet/ai/rs", "/spec/template/spec", "", []string{"/spec/template/spec/containers/0"}}}},
		{"job.yaml", []wantWorkload{{"Job/ai/train", "/spec/template/spec", "", []string{"/spec/template/spec/initContainers/0", "/spec/template/spec/containers/0"}}}},
		{"pod.yaml", []wantWorkload{{"Pod/ai/solo", "/spec", "", []string{"/spec/containers/0"}}}},
		{"cronjob.yaml", []wantWorkload{{"CronJob/ai/dl", "/spec/jobTemplate/spec/template/spec", "", []string{"/spec/jobTemplate/spec/template/spec/containers/0"}}}},
		{"raycluster-v1.yaml", rayWant("RayCluster/ai/rc", "/spec")},
		{"raycluster-v1alpha1.yaml", rayWant("RayCluster/ai/rc", "/spec")},
		{"rayservice.yaml", rayWant("RayService/ai/svc", "/spec/rayClusterConfig")},
		{"rayjob.yaml", []wantWorkload{
			{"RayJob/ai/job", "/spec/rayClusterSpec/headGroupSpec/template/spec", "head", []string{"/spec/rayClusterSpec/headGroupSpec/template/spec/containers/0"}},
			{"RayJob/ai/job", "/spec/rayClusterSpec/workerGroupSpecs/0/template/spec", "gpu", []string{"/spec/rayClusterSpec/workerGroupSpecs/0/template/spec/containers/0"}},
		}},
		{"rayjob-selector.yaml", nil},
		{"isvc-predictor.yaml", []wantWorkload{{"InferenceService/ai/llm", "/spec/predictor", "predictor", []string{"/spec/predictor/containers/0"}}}},
		{"isvc-model.yaml", []wantWorkload{{"InferenceService/ai/hf", "/spec/predictor", "predictor", nil}}},
		{"isvc-all.yaml", []wantWorkload{
			{"InferenceService/ai/full", "/spec/predictor", "predictor", []string{"/spec/predictor/containers/0"}},
			{"InferenceService/ai/full", "/spec/transformer", "transformer", []string{"/spec/transformer/containers/0"}},
			{"InferenceService/ai/full", "/spec/explainer", "explainer", []string{"/spec/explainer/containers/0"}},
		}},
		{"servingruntime.yaml", []wantWorkload{{"ServingRuntime/ai/hf", "/spec", "", []string{"/spec/containers/0"}}}},
		{"clusterservingruntime.yaml", []wantWorkload{{"ClusterServingRuntime/vllm-rt", "/spec", "", []string{"/spec/containers/0"}}}},
		{"service-configmap.yaml", nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			ws, err := Extract(readFiles(t, c.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := summarize(ws); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestOrderAndObjectPointer(t *testing.T) {
	objs := readFiles(t, "deployment.yaml", "service-configmap.yaml", "cronjob.yaml", "statefulset.yaml")
	ws, err := Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	var owners []string
	for _, w := range ws {
		owners = append(owners, w.Owner.String())
		idx := -1
		for i := range objs {
			if objs[i].Ref == w.Owner {
				idx = i
			}
		}
		if idx < 0 || w.Object != &objs[idx] {
			t.Errorf("%s: Object does not point at the input element", w.Owner)
		}
	}
	want := []string{"Deployment/ai/vllm", "CronJob/ai/dl", "StatefulSet/ai/qdrant"}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners = %v, want %v", owners, want)
	}
}

func TestContainerFields(t *testing.T) {
	ws, err := Extract(readFiles(t, "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("got %d workloads", len(ws))
	}
	w := ws[0]
	if len(w.Spec.InitContainers) != 1 || len(w.Spec.Containers) != 1 {
		t.Fatalf("spec containers: init=%d main=%d", len(w.Spec.InitContainers), len(w.Spec.Containers))
	}
	if len(w.Containers) != 2 {
		t.Fatalf("got %d containers", len(w.Containers))
	}
	init, main := w.Containers[0], w.Containers[1]
	if !init.Init || init.Index != 0 || init.Spec.Name != "fetch" || init.Path != "/spec/template/spec/initContainers/0" {
		t.Errorf("init container = %+v", init)
	}
	if main.Init || main.Index != 0 || main.Spec.Name != "server" || main.Path != "/spec/template/spec/containers/0" {
		t.Errorf("main container = %+v", main)
	}
	if main.Spec.Image != "vllm/vllm-openai:v0.6.0" || !reflect.DeepEqual(main.Spec.Args, []string{"--model", "facebook/opt-125m"}) {
		t.Errorf("main container spec = %+v", main.Spec)
	}
	if init.Stack != Generic || !reflect.DeepEqual(wordsOf(init.Commands), [][]string{{"echo", "fetch"}}) {
		t.Errorf("init container Stack=%q Commands=%v", init.Stack, init.Commands)
	}
	if main.Stack != VLLM || !reflect.DeepEqual(wordsOf(main.Commands), [][]string{{"--model", "facebook/opt-125m"}}) {
		t.Errorf("main container Stack=%q Commands=%v", main.Stack, main.Commands)
	}
	if !reflect.DeepEqual(w.Stacks, []Stack{VLLM}) || !w.IsAI() {
		t.Errorf("Stacks=%v IsAI=%v, want [vllm] and true", w.Stacks, w.IsAI())
	}
}

func TestExtraFieldsDecode(t *testing.T) {
	ws, err := Extract(readFiles(t, "isvc-predictor.yaml", "isvc-model.yaml", "servingruntime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 3 {
		t.Fatalf("got %d workloads", len(ws))
	}
	if ws[0].Spec.ServiceAccountName != "llm-sa" {
		t.Errorf("ServiceAccountName = %q", ws[0].Spec.ServiceAccountName)
	}
	if len(ws[2].Spec.Containers) != 1 || ws[2].Spec.Containers[0].Name != "kserve-container" {
		t.Errorf("servingruntime containers = %+v", ws[2].Spec.Containers)
	}
}

func TestLabelsAndAnnotations(t *testing.T) {
	cases := []struct {
		file        string
		specPath    string
		labels      map[string]string
		annotations map[string]string
	}{
		{"deployment.yaml", "/spec/template/spec", map[string]string{"app": "vllm"}, map[string]string{"team": "ml"}},
		{"pod.yaml", "/spec", map[string]string{"app": "solo"}, map[string]string{"note": "pod"}},
		{"cronjob.yaml", "/spec/jobTemplate/spec/template/spec", map[string]string{"app": "dl"}, map[string]string{}},
		{"servingruntime.yaml", "/spec", map[string]string{"runtime": "hf"}, map[string]string{}},
		{"isvc-predictor.yaml", "/spec/predictor", map[string]string{
			"team":                               "ml",
			"tier":                               "gold",
			"component":                          "predictor",
			"serving.kserve.io/inferenceservice": "llm",
		}, map[string]string{"note": "predictor"}},
		{"isvc-all.yaml", "/spec/explainer", map[string]string{
			"component":                          "explainer",
			"serving.kserve.io/inferenceservice": "full",
		}, map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.file+c.specPath, func(t *testing.T) {
			ws, err := Extract(readFiles(t, c.file))
			if err != nil {
				t.Fatal(err)
			}
			w := byPath(t, ws, c.specPath)
			if !reflect.DeepEqual(w.Labels, c.labels) {
				t.Errorf("labels = %v, want %v", w.Labels, c.labels)
			}
			if !reflect.DeepEqual(w.Annotations, c.annotations) {
				t.Errorf("annotations = %v, want %v", w.Annotations, c.annotations)
			}
		})
	}
}

func TestNullLabelAndAnnotationValuesAreEmpty(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai}
spec:
  template:
    metadata:
      labels: {app: vllm, tier: null, empty: ~}
      annotations: {note: null}
    spec:
      containers: [{name: main, image: vllm/vllm-openai:v0.31.0}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("got %d workloads", len(ws))
	}
	if want := map[string]string{"app": "vllm", "tier": "", "empty": ""}; !reflect.DeepEqual(ws[0].Labels, want) {
		t.Errorf("labels = %v, want %v", ws[0].Labels, want)
	}
	if want := map[string]string{"note": ""}; !reflect.DeepEqual(ws[0].Annotations, want) {
		t.Errorf("annotations = %v, want %v", ws[0].Annotations, want)
	}
}

func TestRayLabelsSynthesized(t *testing.T) {
	ws, err := Extract(readFiles(t, "raycluster-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"/spec/headGroupSpec/template/spec": {
			"app":              "ray",
			"role":             "head-extra",
			"ray.io/cluster":   "rc",
			"ray.io/node-type": "head",
			"ray.io/group":     "headgroup",
		},
		"/spec/workerGroupSpecs/0/template/spec": {
			"app":              "ray",
			"ray.io/cluster":   "rc",
			"ray.io/node-type": "worker",
			"ray.io/group":     "cpu",
		},
		"/spec/workerGroupSpecs/1/template/spec": {
			"app":              "ray",
			"ray.io/cluster":   "rc",
			"ray.io/node-type": "worker",
			"ray.io/group":     "gpu",
		},
	}
	for specPath, labels := range want {
		w := byPath(t, ws, specPath)
		if !reflect.DeepEqual(w.Labels, labels) {
			t.Errorf("%s: labels = %v, want %v", specPath, w.Labels, labels)
		}
	}
}

func TestRayGeneratedClusterName(t *testing.T) {
	for _, file := range []string{"rayservice.yaml", "rayjob.yaml"} {
		t.Run(file, func(t *testing.T) {
			ws, err := Extract(readFiles(t, file))
			if err != nil {
				t.Fatal(err)
			}
			if len(ws) == 0 {
				t.Fatal("no workloads")
			}
			for _, w := range ws {
				if v, ok := w.Labels["ray.io/cluster"]; ok {
					t.Errorf("%s: ray.io/cluster = %q, want unset", w.SpecPath, v)
				}
				wantType, wantGroup := "worker", w.Group
				if w.Group == "head" {
					wantType, wantGroup = "head", "headgroup"
				}
				if w.Labels["ray.io/node-type"] != wantType || w.Labels["ray.io/group"] != wantGroup {
					t.Errorf("%s: labels = %v", w.SpecPath, w.Labels)
				}
			}
		})
	}
}

func TestAbsentSpecsAreSkipped(t *testing.T) {
	cases := map[string]string{
		"deployment without pod spec": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai}
spec: {replicas: 1}
`,
		"pod without spec": `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ai}
`,
		"raycluster without groups": `
apiVersion: ray.io/v1
kind: RayCluster
metadata: {name: rc, namespace: ai}
spec: {workerGroupSpecs: []}
`,
		"isvc with null predictor": `
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: i, namespace: ai}
spec: {predictor: null}
`,
		"other group with workload kind name": `
apiVersion: example.com/v1
kind: Deployment
metadata: {name: x, namespace: ai}
spec: {template: {spec: {containers: [{name: c, image: i}]}}}
`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			ws, err := Extract(readInline(t, doc))
			if err != nil {
				t.Fatal(err)
			}
			if len(ws) != 0 {
				t.Fatalf("got %+v", summarize(ws))
			}
		})
	}
}

func TestEmptyIsvcComponent(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: i, namespace: ai}
spec: {predictor: null, transformer: {}}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []wantWorkload{{"InferenceService/ai/i", "/spec/transformer", "transformer", nil}}
	if got := summarize(ws); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTypeMismatch(t *testing.T) {
	cases := []struct {
		name string
		objs []load.Object
		want string
	}{
		{"containers", readFiles(t, "bad-containers.yaml"), "Deployment/ai/bad: /spec/template/spec"},
		{"labels", readFiles(t, "bad-labels.yaml"), "Deployment/ai/badlabels: /spec/template/metadata/labels"},
		{"worker groups", readFiles(t, "bad-workers.yaml"), "RayCluster/ai/badworkers: /spec/workerGroupSpecs"},
		{"spec not object", readInline(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai}
spec: {template: {spec: "x"}}
`), "Deployment/ai/d: /spec/template/spec"},
		{"worker group not object", readInline(t, `
apiVersion: ray.io/v1
kind: RayCluster
metadata: {name: rc, namespace: ai}
spec: {workerGroupSpecs: ["x"]}
`), "RayCluster/ai/rc: /spec/workerGroupSpecs/0"},
		{"group name not string", readInline(t, `
apiVersion: ray.io/v1
kind: RayCluster
metadata: {name: rc, namespace: ai}
spec: {workerGroupSpecs: [{groupName: 5, template: {spec: {}}}]}
`), "RayCluster/ai/rc: /spec/workerGroupSpecs/0/groupName"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws, err := Extract(c.objs)
			if err == nil {
				t.Fatalf("no error, workloads: %+v", summarize(ws))
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
			if ws != nil {
				t.Errorf("workloads returned with error: %+v", summarize(ws))
			}
		})
	}
}

func TestStacks(t *testing.T) {
	w := Workload{Stacks: []Stack{VLLM, Ray}}
	if !w.IsAI() || !w.HasStack(VLLM) || !w.HasStack(Ray) || w.HasStack(Ollama) {
		t.Errorf("IsAI/HasStack wrong for %v", w.Stacks)
	}
	var zero Workload
	if zero.IsAI() || zero.HasStack(Generic) {
		t.Error("zero workload must not be AI")
	}
	for s, want := range map[Stack]string{Generic: "", VLLM: "vllm", Ray: "ray", Ollama: "ollama", Qdrant: "qdrant", Milvus: "milvus", KServe: "kserve"} {
		if string(s) != want {
			t.Errorf("stack %q != %q", s, want)
		}
	}
}

func TestSelects(t *testing.T) {
	labels := map[string]string{"app": "vllm", "tier": "gold"}
	expr := func(key string, op metav1.LabelSelectorOperator, values ...string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: key, Operator: op, Values: values}}}
	}
	cases := []struct {
		name   string
		sel    *metav1.LabelSelector
		labels map[string]string
		want   bool
	}{
		{"nil", nil, labels, false},
		{"nil with nil labels", nil, nil, false},
		{"empty", &metav1.LabelSelector{}, labels, true},
		{"empty with nil labels", &metav1.LabelSelector{}, nil, true},
		{"matchLabels hit", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}}, labels, true},
		{"matchLabels miss", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}, labels, false},
		{"matchLabels missing key", &metav1.LabelSelector{MatchLabels: map[string]string{"zone": "a"}}, labels, false},
		{"matchLabels nil labels", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}}, nil, false},
		{"In hit", expr("app", metav1.LabelSelectorOpIn, "a", "vllm"), labels, true},
		{"In miss", expr("app", metav1.LabelSelectorOpIn, "a", "b"), labels, false},
		{"In missing key", expr("zone", metav1.LabelSelectorOpIn, "a"), labels, false},
		{"NotIn hit", expr("app", metav1.LabelSelectorOpNotIn, "a", "b"), labels, true},
		{"NotIn miss", expr("app", metav1.LabelSelectorOpNotIn, "vllm"), labels, false},
		{"NotIn missing key", expr("zone", metav1.LabelSelectorOpNotIn, "a"), labels, true},
		{"Exists hit", expr("app", metav1.LabelSelectorOpExists), labels, true},
		{"Exists miss", expr("zone", metav1.LabelSelectorOpExists), labels, false},
		{"DoesNotExist hit", expr("zone", metav1.LabelSelectorOpDoesNotExist), labels, true},
		{"DoesNotExist miss", expr("app", metav1.LabelSelectorOpDoesNotExist), labels, false},
		{"labels and expressions", &metav1.LabelSelector{
			MatchLabels:      map[string]string{"app": "vllm"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"silver"}}},
		}, labels, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Selects(c.sel, c.labels)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("Selects = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSelectsInvalid(t *testing.T) {
	sel := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Bogus"}}}
	got, err := Selects(sel, map[string]string{"app": "vllm"})
	if err == nil {
		t.Fatal("no error for invalid operator")
	}
	if got {
		t.Error("invalid selector must not select")
	}
}

func TestMapSelects(t *testing.T) {
	labels := map[string]string{"app": "vllm", "tier": "gold"}
	cases := []struct {
		name   string
		sel    map[string]string
		labels map[string]string
		want   bool
	}{
		{"nil selector", nil, labels, false},
		{"empty selector", map[string]string{}, labels, false},
		{"empty selector nil labels", map[string]string{}, nil, false},
		{"subset", map[string]string{"app": "vllm"}, labels, true},
		{"equal", map[string]string{"app": "vllm", "tier": "gold"}, labels, true},
		{"extra key", map[string]string{"app": "vllm", "zone": "a"}, labels, false},
		{"value differs", map[string]string{"app": "other"}, labels, false},
		{"nil labels", map[string]string{"app": "vllm"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MapSelects(c.sel, c.labels); got != c.want {
				t.Fatalf("MapSelects = %v, want %v", got, c.want)
			}
		})
	}
}
