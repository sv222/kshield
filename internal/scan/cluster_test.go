package scan

import (
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/report"
)

const (
	hardenedSC = `
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false`
	rootContainerMsg = "container may run as root: runAsNonRoot is not true and runAsUser is not set"
	tplPath          = "/spec/template/spec/containers/0/securityContext/"
)

func readObjects(t *testing.T, docs ...string) []load.Object {
	t.Helper()
	path := writeFile(t, t.TempDir(), "in.yaml", strings.Join(docs, "---\n"))
	objs, err := load.Read([]string{path}, load.Options{DefaultNamespace: "ai"})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func deployment(uid, sc string) string {
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai
  uid: ` + uid + `
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
          image: vllm/vllm-openai:v0.6.0` + sc + "\n"
}

func replicaSet(name, uid, ownerKind, ownerName, ownerUID string) string {
	return `apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: ` + name + `
  namespace: ai
  uid: ` + uid + `
  ownerReferences:
    - {apiVersion: apps/v1, kind: ` + ownerKind + `, name: ` + ownerName + `, uid: ` + ownerUID + `, controller: true}
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
}

func livePod(name, uid, ownerKind, ownerName, ownerUID, labels, phase string) string {
	return `apiVersion: v1
kind: Pod
metadata:
  name: ` + name + `
  namespace: ai
  uid: ` + uid + `
  labels: {` + labels + `}
  ownerReferences:
    - {apiVersion: v1, kind: ` + ownerKind + `, name: ` + ownerName + `, uid: ` + ownerUID + `, controller: true}
spec:
  containers:
    - name: vllm
      image: vllm/vllm-openai:v0.6.0
status:
  phase: ` + phase + "\n"
}

func checkByID(t *testing.T, r *report.Report, id string) report.CheckResult {
	t.Helper()
	i := slices.IndexFunc(r.Checks, func(c report.CheckResult) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("check %s not in report", id)
	}
	return r.Checks[i]
}

func TestClusterObjectsReport(t *testing.T) {
	objs := readObjects(t, vllmDeployment, configMap)
	info := report.ClusterInfo{Context: "kind-kshield-test", Server: "https://127.0.0.1:6443", NodeProbe: true, ProbeNamespace: "kshield-probe"}
	errs := []string{"list secrets: forbidden"}
	r, err := ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true, Info: info, Errors: errs})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan.Mode != report.ModeCluster {
		t.Errorf("mode %q", r.Scan.Mode)
	}
	if r.Scan.Inputs == nil || len(r.Scan.Inputs) != 0 || r.Scan.InputDigests == nil || len(r.Scan.InputDigests) != 0 {
		t.Errorf("inputs %#v digests %#v, want empty non-nil", r.Scan.Inputs, r.Scan.InputDigests)
	}
	if r.Scan.Namespace != "" || r.Scan.Objects != 2 || r.Scan.AIWorkloads != 1 {
		t.Errorf("scan info %+v", r.Scan)
	}
	if r.Scan.Cluster == nil {
		t.Fatal("scan.cluster must be set in cluster mode")
	}
	c := r.Scan.Cluster
	if c.Context != info.Context || c.Server != info.Server || !c.NodeProbe || c.ProbeNamespace != info.ProbeNamespace || c.Namespaces == nil || len(c.Namespaces) != 0 {
		t.Errorf("cluster %+v", *c)
	}
	if r.Tool.Version != deterministicVersion || r.Scan.StartedAt != deterministicStart {
		t.Errorf("tool %+v startedAt %s", r.Tool, r.Scan.StartedAt)
	}
	if !slices.Equal(r.Errors, errs) || !r.Summary.Incomplete {
		t.Errorf("errors %v incomplete %v", r.Errors, r.Summary.Incomplete)
	}
	if len(r.Checks) != len(check.All()) {
		t.Errorf("got %d checks, registry has %d", len(r.Checks), len(check.All()))
	}
	if v := checkByID(t, r, "KS-AI-002").Verdict; v != report.VerdictNA {
		t.Errorf("KS-AI-002 (Manifest tier) verdict %s, want N/A", v)
	}
	wl := checkByID(t, r, "KS-WL-001")
	if wl.Verdict != report.VerdictFail || len(wl.Findings) != 1 || wl.Findings[0].Object.String() != "Deployment/ai/vllm" {
		t.Errorf("KS-WL-001 %+v", wl)
	}
	for _, cr := range r.Checks {
		for _, f := range cr.Findings {
			if f.Source != nil {
				t.Errorf("%s: cluster finding has source %+v", cr.ID, *f.Source)
			}
		}
	}
}

func TestClusterObjectsErrors(t *testing.T) {
	objs := readObjects(t, vllmDeployment)
	in := []string{"list pods: timeout", "get cilium-config: forbidden", "list secrets: forbidden"}
	r, err := ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true, Errors: in})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"get cilium-config: forbidden", "list pods: timeout", "list secrets: forbidden"}
	if !slices.Equal(r.Errors, want) || !r.Summary.Incomplete {
		t.Errorf("errors %v incomplete %v", r.Errors, r.Summary.Incomplete)
	}
	if in[0] != "list pods: timeout" {
		t.Errorf("caller's errors were changed: %v", in)
	}

	r, err = ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Errors == nil || len(r.Errors) != 0 || r.Summary.Incomplete {
		t.Errorf("errors %#v incomplete %v", r.Errors, r.Summary.Incomplete)
	}
	if r.Scan.Cluster == nil || r.Scan.Cluster.Namespaces == nil {
		t.Errorf("cluster %+v", r.Scan.Cluster)
	}
}

func TestClusterObjectsUnknownProfile(t *testing.T) {
	if _, err := ClusterObjects(nil, nil, ClusterOptions{ProfileID: "nope"}); err == nil {
		t.Error("unknown profile must fail")
	}
}

func oneCheckProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Parse([]byte("id: one\nversion: 1\ntitle: One\nchecks:\n  KS-T-001: {display: T-1, severity: fail, refs: [dora-art9-2]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClusterObjectsFacts(t *testing.T) {
	var seen []*check.Input
	checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Both, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
		seen = append(seen, in)
		return check.Result{Applicable: true}
	}}}
	objs := readObjects(t, vllmDeployment)
	if _, err := clusterObjects(objs, nil, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Cluster == nil || len(seen[0].Workloads) != 1 {
		t.Fatalf("nil facts must become empty facts: %+v", seen)
	}
	facts := &check.ClusterFacts{ProbeRan: true, Nodes: []check.NodeFacts{{Node: load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: "n1"}, LSM: []string{"bpf"}, BPFLSMConfig: "y"}}}
	seen = nil
	if _, err := clusterObjects(objs, facts, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Cluster != facts {
		t.Errorf("facts not passed through: %+v", seen)
	}
}

func TestLivePassDedup(t *testing.T) {
	objs := readObjects(t,
		deployment("d1", hardenedSC),
		replicaSet("vllm-x", "rs1", "Deployment", "vllm", "d1"),
		livePod("vllm-x-c", "p3", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Running"),
		livePod("vllm-x-a", "p1", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Running"),
		livePod("vllm-x-b", "p2", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Pending"),
	)
	r, err := ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]report.Finding{
		"KS-WL-001": {Path: tplPath + "runAsNonRoot", Message: "live pod vllm-x-a: " + rootContainerMsg},
		"KS-WL-002": {Path: tplPath + "allowPrivilegeEscalation", Message: "live pod vllm-x-a: allowPrivilegeEscalation is not set to false"},
	}
	for id, w := range want {
		c := checkByID(t, r, id)
		if len(c.Findings) != 1 {
			t.Fatalf("%s: %d findings, want 1: %+v", id, len(c.Findings), c.Findings)
		}
		f := c.Findings[0]
		if f.Object.String() != "Deployment/ai/vllm" || f.Group != "" || f.Container != "vllm" || f.Path != w.Path || f.Message != w.Message || f.Verdict != report.VerdictFail || f.Source != nil {
			t.Errorf("%s: got %+v, want path %s message %q", id, f, w.Path, w.Message)
		}
		if c.Verdict != report.VerdictFail {
			t.Errorf("%s: verdict %s", id, c.Verdict)
		}
	}
}

func TestLivePassKeepsTemplateFinding(t *testing.T) {
	objs := readObjects(t,
		deployment("d1", ""),
		replicaSet("vllm-x", "rs1", "Deployment", "vllm", "d1"),
		livePod("vllm-x-a", "p1", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Running"),
		livePod("vllm-x-b", "p2", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Running"),
	)
	r, err := ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	c := checkByID(t, r, "KS-WL-001")
	if len(c.Findings) != 1 || c.Findings[0].Message != rootContainerMsg || c.Findings[0].Path != tplPath+"runAsNonRoot" {
		t.Errorf("want only the template finding, got %+v", c.Findings)
	}
}

func TestLivePassPathsAndObjects(t *testing.T) {
	svc := load.ObjectRef{APIVersion: "v1", Kind: "Service", Namespace: "ai", Name: "vllm"}
	checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Both, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
		res := check.Result{Applicable: true}
		for _, w := range in.Workloads {
			res.Findings = append(res.Findings,
				check.Finding{Object: w.Owner, Container: "vllm", Path: "/spec/containers/0/x", Message: "spec"},
				check.Finding{Object: w.Owner, Path: "/metadata/namespace", Message: "meta"},
				check.Finding{Object: w.Owner, Path: "/specx", Message: "near"},
				check.Finding{Object: svc, Path: "/spec/type", Message: "svc"},
			)
		}
		return res
	}}}
	objs := readObjects(t,
		deployment("d1", hardenedSC),
		replicaSet("vllm-x", "rs1", "Deployment", "vllm", "d1"),
		livePod("vllm-x-a", "p1", "ReplicaSet", "vllm-x", "rs1", "app: vllm", "Running"),
	)
	r, err := clusterObjects(objs, nil, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range r.Checks[0].Findings {
		got = append(got, f.Object.String()+" "+f.Path+" "+f.Message)
	}
	want := []string{
		"Deployment/ai/vllm /metadata/namespace meta",
		"Deployment/ai/vllm /spec/containers/0/x spec",
		"Deployment/ai/vllm /spec/template/spec/containers/0/x live pod vllm-x-a: spec",
		"Deployment/ai/vllm /specx near",
		"Service/ai/vllm /spec/type svc",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %q\nwant %q", got, want)
	}
}

func TestLivePassGroups(t *testing.T) {
	checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Both, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
		res := check.Result{Applicable: true}
		for _, w := range in.Workloads {
			if w.Owner.Kind == "Pod" {
				res.Findings = append(res.Findings, check.Finding{Object: w.Owner, Path: "/spec/containers/0/x", Message: "m"})
			}
		}
		return res
	}}}
	objs := readObjects(t,
		`apiVersion: ray.io/v1
kind: RayService
metadata: {name: llm, namespace: ai, uid: r1}
spec:
  rayClusterConfig:
    headGroupSpec:
      template:
        spec:
          containers: [{name: vllm, image: rayproject/ray:2.9.0}]
    workerGroupSpecs:
      - groupName: cpu
        template:
          spec:
            containers: [{name: vllm, image: rayproject/ray:2.9.0}]
      - groupName: gpu
        template:
          spec:
            containers: [{name: vllm, image: rayproject/ray:2.9.0}]
`,
		`apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: llm-rc
  namespace: ai
  uid: r2
  ownerReferences: [{apiVersion: ray.io/v1, kind: RayService, name: llm, uid: r1, controller: true}]
spec: {}
`,
		livePod("llm-rc-head", "p1", "RayCluster", "llm-rc", "r2", "ray.io/node-type: head, ray.io/group: headgroup", "Running"),
		livePod("llm-rc-gpu-a", "p2", "RayCluster", "llm-rc", "r2", "ray.io/node-type: worker, ray.io/group: gpu", "Running"),
		livePod("llm-rc-tpu-a", "p3", "RayCluster", "llm-rc", "r2", "ray.io/node-type: worker, ray.io/group: tpu", "Running"),
		`apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: isvc, namespace: ai, uid: i1}
spec:
  predictor:
    containers: [{name: vllm, image: vllm/vllm-openai:v0.6.0}]
`,
		`apiVersion: apps/v1
kind: Deployment
metadata:
  name: isvc-predictor
  namespace: ai
  uid: i2
  ownerReferences: [{apiVersion: serving.kserve.io/v1beta1, kind: InferenceService, name: isvc, uid: i1, controller: true}]
spec:
  template:
    spec:
      containers: [{name: vllm, image: vllm/vllm-openai:v0.6.0}]
`,
		livePod("isvc-predictor-a", "p4", "Deployment", "isvc-predictor", "i2", "component: predictor", "Running"),
	)
	r, err := clusterObjects(objs, nil, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range r.Checks[0].Findings {
		got = append(got, f.Object.String()+" ["+f.Group+"] "+f.Path+" "+f.Message)
	}
	want := []string{
		"InferenceService/ai/isvc [predictor] /spec/predictor/containers/0/x live pod isvc-predictor-a: m",
		"Pod/ai/llm-rc-tpu-a [] /spec/containers/0/x live pod llm-rc-tpu-a: m",
		"RayService/ai/llm [gpu] /spec/rayClusterConfig/workerGroupSpecs/1/template/spec/containers/0/x live pod llm-rc-gpu-a: m",
		"RayService/ai/llm [head] /spec/rayClusterConfig/headGroupSpec/template/spec/containers/0/x live pod llm-rc-head: m",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %q\nwant %q", got, want)
	}
}

func cycle(t *testing.T) []load.Object {
	t.Helper()
	return readObjects(t,
		replicaSet("vllm-a", "ca", "ReplicaSet", "vllm-b", "cb"),
		replicaSet("vllm-b", "cb", "ReplicaSet", "vllm-a", "ca"),
		livePod("vllm-a-x", "p1", "ReplicaSet", "vllm-a", "ca", "app: vllm", "Running"),
	)
}

func TestLivePassCycle(t *testing.T) {
	r, err := ClusterObjects(cycle(t), nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	c := checkByID(t, r, "KS-WL-001")
	var got []string
	for _, f := range c.Findings {
		got = append(got, f.Object.String()+" "+f.Message)
	}
	want := []string{"ReplicaSet/ai/vllm-a " + rootContainerMsg, "ReplicaSet/ai/vllm-b " + rootContainerMsg}
	if !slices.Equal(got, want) || c.Verdict != report.VerdictFail {
		t.Errorf("findings %q, want %q", got, want)
	}
	if r.Scan.AIWorkloads != 2 {
		t.Errorf("aiWorkloads %d: both cycle members are roots judged by template", r.Scan.AIWorkloads)
	}
}

func TestLivePassApplicable(t *testing.T) {
	svc := load.ObjectRef{APIVersion: "v1", Kind: "Service", Namespace: "ai", Name: "vllm"}
	run := func(onPod bool) report.CheckResult {
		checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Both, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
			if len(in.Workloads) == 0 {
				return check.Result{}
			}
			res := check.Result{Applicable: true}
			for _, w := range in.Workloads {
				obj := svc
				if onPod {
					obj = w.Owner
				}
				res.Findings = append(res.Findings, check.Finding{Object: obj, Path: "/spec/x", Message: "m"})
			}
			return res
		}}}
		objs := readObjects(t,
			`apiVersion: leaderworkerset.x-k8s.io/v1
kind: LeaderWorkerSet
metadata: {name: lws, namespace: ai, uid: l1}
`,
			livePod("lws-0", "p1", "LeaderWorkerSet", "lws", "l1", "app: vllm", "Running"),
		)
		r, err := clusterObjects(objs, nil, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks)
		if err != nil {
			t.Fatal(err)
		}
		return r.Checks[0]
	}
	if c := run(false); c.Verdict != report.VerdictNA || len(c.Findings) != 0 {
		t.Errorf("only dropped live findings: want N/A, got %+v", c)
	}
	if c := run(true); c.Verdict != report.VerdictFail || len(c.Findings) != 1 || c.Findings[0].Object.String() != "Pod/ai/lws-0" {
		t.Errorf("a live finding makes the check applicable: got %+v", c)
	}
}

func TestLivePassContainers(t *testing.T) {
	checks := []check.Check{{ID: "KS-T-001", Title: "t", Tier: check.Both, Fix: check.FixPatch, Run: func(in *check.Input) check.Result {
		res := check.Result{Applicable: true}
		for _, w := range in.Workloads {
			for _, c := range w.Containers {
				res.Findings = append(res.Findings, check.Finding{Object: w.Owner, Container: c.Spec.Name, Path: c.Path + "/x", Message: "m"})
				if w.Owner.Kind == "Pod" {
					res.Findings = append(res.Findings, check.Finding{Object: w.Owner, Container: c.Spec.Name, Path: c.Path + "/y", Message: "m"})
				}
			}
		}
		return res
	}}}
	tpl := `apiVersion: apps/v1
kind: Deployment
metadata: {name: vllm, namespace: ai, uid: d1}
spec:
  template:
    spec:
      initContainers: [{name: setup, image: busybox:1.36}]
      containers: [{name: vllm, image: vllm/vllm-openai:v0.6.0}]
`
	podDoc := func(name, uid string) string {
		return `apiVersion: v1
kind: Pod
metadata:
  name: ` + name + `
  namespace: ai
  uid: ` + uid + `
  ownerReferences: [{apiVersion: apps/v1, kind: Deployment, name: vllm, uid: d1, controller: true}]
spec:
  initContainers: [{name: setup, image: busybox:1.36}]
  containers:
    - {name: istio-proxy, image: docker.io/istio/proxyv2:1.24.0}
    - {name: vllm, image: vllm/vllm-openai:v0.6.0}
    - {name: setup, image: busybox:1.36}
status: {phase: Running}
`
	}
	objs := readObjects(t, tpl, podDoc("vllm-x-b", "p2"), podDoc("vllm-x-a", "p1"))
	r, err := clusterObjects(objs, nil, ClusterOptions{Deterministic: true}, oneCheckProfile(t), checks)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range r.Checks[0].Findings {
		got = append(got, f.Object.String()+" "+f.Path+" "+f.Container+" "+f.Message)
	}
	want := []string{
		"Deployment/ai/vllm /spec/template/spec/containers/0/x vllm m",
		"Deployment/ai/vllm /spec/template/spec/containers/0/y vllm live pod vllm-x-a: m",
		"Deployment/ai/vllm /spec/template/spec/initContainers/0/x setup m",
		"Deployment/ai/vllm /spec/template/spec/initContainers/0/y setup live pod vllm-x-a: m",
		"Pod/ai/vllm-x-a /spec/containers/0/x istio-proxy live pod vllm-x-a: m",
		"Pod/ai/vllm-x-a /spec/containers/0/y istio-proxy live pod vllm-x-a: m",
		"Pod/ai/vllm-x-a /spec/containers/2/x setup live pod vllm-x-a: m",
		"Pod/ai/vllm-x-a /spec/containers/2/y setup live pod vllm-x-a: m",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %q\nwant %q", got, want)
	}
}

func TestLivePassSidecarDoesNotRepeatAgreeingContainer(t *testing.T) {
	sidecarPod := func(name, uid string, prepend bool) string {
		vllm := "    - {name: vllm, image: vllm/vllm-openai:v0.6.0, securityContext: {runAsNonRoot: true, runAsUser: 1000, allowPrivilegeEscalation: false}}\n"
		proxy := "    - {name: istio-proxy, image: docker.io/istio/proxyv2:1.24.0}\n"
		containers := vllm + proxy
		if prepend {
			containers = proxy + vllm
		}
		return `apiVersion: v1
kind: Pod
metadata:
  name: ` + name + `
  namespace: ai
  uid: ` + uid + `
  ownerReferences: [{apiVersion: apps/v1, kind: Deployment, name: vllm, uid: d1, controller: true}]
spec:
  containers:
` + containers + `status: {phase: Running}
`
	}
	for _, prepend := range []bool{true, false} {
		objs := readObjects(t, deployment("d1", hardenedSC), sidecarPod("vllm-x-a", "p1", prepend), sidecarPod("vllm-x-b", "p2", prepend))
		r, err := ClusterObjects(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
		if err != nil {
			t.Fatal(err)
		}
		idx := "1"
		if prepend {
			idx = "0"
		}
		c := checkByID(t, r, "KS-WL-001")
		if len(c.Findings) != 1 {
			t.Fatalf("prepend %v: %d findings, want 1: %+v", prepend, len(c.Findings), c.Findings)
		}
		f := c.Findings[0]
		if f.Object.String() != "Pod/ai/vllm-x-a" || f.Container != "istio-proxy" || f.Path != "/spec/containers/"+idx+"/securityContext/runAsNonRoot" || f.Message != "live pod vllm-x-a: "+rootContainerMsg {
			t.Errorf("prepend %v: %+v", prepend, f)
		}
	}
}
