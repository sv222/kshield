package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	tetragonLabels = "app.kubernetes.io/name: tetragon\n    app.kubernetes.io/instance: tetragon\n    app.kubernetes.io/component: agent"
	ciliumLabels   = "k8s-app: cilium\n    app.kubernetes.io/name: cilium-agent\n    app.kubernetes.io/part-of: cilium"
	kyvernoLabels  = "app.kubernetes.io/component: admission-controller\n    app.kubernetes.io/part-of: kyverno"
)

var preVLLM = deployment(vllmPod(`"--model", "m"`))

func runPre(t *testing.T, id, doc string, facts *ClusterFacts) Result {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := ByID(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	if facts == nil {
		facts = &ClusterFacts{}
	}
	return Evaluate(c, &Input{Objects: objs, Workloads: ws, Cluster: facts})
}

func appsDoc(kind, ns, name, labels, body string) string {
	return "---\napiVersion: apps/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n  namespace: " + ns + "\n  labels:\n    " + labels + "\n" + body
}

func ciliumConfigDoc(ns string, data ...string) string {
	doc := "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\n  namespace: " + ns + "\ndata:\n  cluster-name: default\n"
	for _, d := range data {
		doc += "  " + d + "\n"
	}
	return doc
}

type preWant struct {
	object   string
	path     string
	message  string
	strength Strength
}

func checkPre(t *testing.T, r Result, want []preWant) {
	t.Helper()
	if !r.Applicable {
		t.Fatal("must be applicable")
	}
	if len(r.Findings) != len(want) {
		t.Fatalf("got %d findings %+v, want %+v", len(r.Findings), r.Findings, want)
	}
	for i, f := range r.Findings {
		w := want[i]
		if f.Object.String() != w.object || f.Path != w.path || f.Message != w.message || f.Strength != w.strength || f.Container != "" || f.Group != "" {
			t.Errorf("finding %d: got %+v, want %+v", i, f, w)
		}
	}
}

func TestPreDaemonSetHealth(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   []preWant
	}{
		{"all ready", "status:\n  desiredNumberScheduled: 2\n  numberReady: 2\n", nil},
		{"one not ready", "status:\n  desiredNumberScheduled: 2\n  numberReady: 1\n", []preWant{{"DaemonSet/kube-system/tetragon", "/status/numberReady", "Tetragon DaemonSet not ready: 1/2 pods ready", Violation}}},
		{"desired zero", "status:\n  desiredNumberScheduled: 0\n  numberReady: 0\n", []preWant{{"DaemonSet/kube-system/tetragon", "/status/numberReady", "Tetragon DaemonSet not ready: 0/0 pods ready", Violation}}},
		{"missing status", "", []preWant{{"DaemonSet/kube-system/tetragon", "/status/numberReady", "Tetragon DaemonSet not ready: 0/0 pods ready", Violation}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := preVLLM + appsDoc("DaemonSet", "kube-system", "tetragon", tetragonLabels, tc.status)
			checkPre(t, runPre(t, "KS-PRE-001", doc, nil), tc.want)
		})
	}
}

func TestPreSeveralDaemonSets(t *testing.T) {
	doc := preVLLM +
		appsDoc("DaemonSet", "kube-system", "tetragon", tetragonLabels, "status:\n  desiredNumberScheduled: 3\n  numberReady: 3\n") +
		appsDoc("DaemonSet", "tetragon", "tetragon", tetragonLabels, "status:\n  desiredNumberScheduled: 3\n  numberReady: 2\n")
	checkPre(t, runPre(t, "KS-PRE-001", doc, nil), []preWant{{"DaemonSet/tetragon/tetragon", "/status/numberReady", "Tetragon DaemonSet not ready: 2/3 pods ready", Violation}})
}

func TestPreCiliumNotReadyIsSuspect(t *testing.T) {
	doc := preVLLM + appsDoc("DaemonSet", "kube-system", "cilium", ciliumLabels, "status:\n  desiredNumberScheduled: 3\n  numberReady: 1\n")
	checkPre(t, runPre(t, "KS-PRE-002", doc, nil), []preWant{{"DaemonSet/kube-system/cilium", "/status/numberReady", "Cilium DaemonSet not ready: 1/3 pods ready", Suspect}})
}

func TestPreDeploymentHealth(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []preWant
	}{
		{"replicas unset ready 1", "spec: {}\nstatus:\n  readyReplicas: 1\n", nil},
		{"replicas null ready 1", "spec:\n  replicas:\nstatus:\n  readyReplicas: 1\n", nil},
		{"replicas 3 ready 3", "spec:\n  replicas: 3\nstatus:\n  readyReplicas: 3\n", nil},
		{"replicas unset no status", "spec: {}\n", []preWant{{"Deployment/kyverno/kyverno-admission-controller", "/status/readyReplicas", "Kyverno admission controller not ready: 0/1", Violation}}},
		{"replicas 3 ready 2", "spec:\n  replicas: 3\nstatus:\n  readyReplicas: 2\n", []preWant{{"Deployment/kyverno/kyverno-admission-controller", "/status/readyReplicas", "Kyverno admission controller not ready: 2/3", Violation}}},
		{"scaled to zero", "spec:\n  replicas: 0\n", []preWant{{"Deployment/kyverno/kyverno-admission-controller", "/status/readyReplicas", "Kyverno admission controller not ready: 0/0", Violation}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := preVLLM + appsDoc("Deployment", "kyverno", "kyverno-admission-controller", kyvernoLabels, tc.body)
			checkPre(t, runPre(t, "KS-PRE-003", doc, nil), tc.want)
		})
	}
}

func TestPreNotFound(t *testing.T) {
	second := strings.ReplaceAll(preVLLM, "namespace: ai", "namespace: ai-two")
	other := strings.ReplaceAll(strings.ReplaceAll(preVLLM, "name: vllm\n", "name: vllm-b\n"), "app: vllm", "app: vllm-b")
	doc := preVLLM + "---\n" + second + "---\n" + other +
		appsDoc("DaemonSet", "kube-system", "cilium-envoy", "k8s-app: cilium-envoy\n    app.kubernetes.io/name: cilium-envoy", "") +
		appsDoc("Deployment", "kyverno", "kyverno-background-controller", "app.kubernetes.io/component: background-controller\n    app.kubernetes.io/part-of: kyverno", "spec: {}\n") +
		appsDoc("Deployment", "kube-system", "vpa-admission-controller", "app.kubernetes.io/component: admission-controller", "spec: {}\n")
	cases := []struct{ id, msg string }{
		{"KS-PRE-001", "Tetragon not found in the cluster; no runtime guard can run"},
		{"KS-PRE-002", "CNI is not Cilium; L7 and FQDN egress policies cannot be enforced"},
		{"KS-PRE-003", "Kyverno not found in the cluster; no admission guard can run"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r := runPre(t, tc.id, doc, nil)
			checkPre(t, r, []preWant{{"Namespace/ai", "", tc.msg, Violation}, {"Namespace/ai-two", "", tc.msg, Violation}})
			for _, f := range r.Findings {
				if f.Object.APIVersion != "v1" {
					t.Errorf("namespace apiVersion %q", f.Object.APIVersion)
				}
			}
		})
	}
}

func TestPreKyvernoCustomRelease(t *testing.T) {
	doc := preVLLM + appsDoc("Deployment", "policy", "policy-kyverno-admission-controller", "app.kubernetes.io/component: admission-controller\n    app.kubernetes.io/part-of: policy-kyverno", "spec:\n  replicas: 2\nstatus:\n  readyReplicas: 2\n")
	checkPre(t, runPre(t, "KS-PRE-003", doc, nil), nil)
}

func nodeRef(name string) load.ObjectRef {
	return load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: name}
}

func TestPreBPFLSM(t *testing.T) {
	lsm := []string{"lockdown", "capability", "yama"}
	cases := []struct {
		name string
		node NodeFacts
		want []preWant
	}{
		{"bpf active", NodeFacts{Node: nodeRef("n1"), LSM: []string{"lockdown", "bpf"}, BPFLSMConfig: "y"}, nil},
		{"config y", NodeFacts{Node: nodeRef("n1"), LSM: lsm, BPFLSMConfig: "y"}, []preWant{{"Node/n1", "", "bpf is not in the active LSM list (lockdown,capability,yama); kernel has CONFIG_BPF_LSM=y, add bpf to the lsm= boot parameter", Violation}}},
		{"config n", NodeFacts{Node: nodeRef("n1"), LSM: lsm, BPFLSMConfig: "n"}, []preWant{{"Node/n1", "", "bpf is not in the active LSM list (lockdown,capability,yama); kernel was built without CONFIG_BPF_LSM", Violation}}},
		{"config unreadable", NodeFacts{Node: nodeRef("n1"), LSM: lsm}, []preWant{{"Node/n1", "", "bpf is not in the active LSM list (lockdown,capability,yama); kernel config unreadable", Violation}}},
		{"unknown", NodeFacts{Node: nodeRef("n1"), Unknown: "probe pod Pending: ImagePullBackOff"}, []preWant{{"Node/n1", "", "probe pod Pending: ImagePullBackOff", Unknown}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkPre(t, runPre(t, "KS-PRE-004", preVLLM, &ClusterFacts{ProbeRan: true, Nodes: []NodeFacts{tc.node}}), tc.want)
		})
	}
}

func TestPreBPFLSMProbeNotRun(t *testing.T) {
	facts := &ClusterFacts{Nodes: []NodeFacts{{Node: nodeRef("n1"), LSM: []string{"capability"}, BPFLSMConfig: "n"}}}
	if r := runPre(t, "KS-PRE-004", preVLLM, facts); r.Applicable || len(r.Findings) != 0 {
		t.Fatalf("probe not run must be N/A, got %+v", r)
	}
}

func TestPreBPFLSMProbeRanNoNodes(t *testing.T) {
	for name, nodes := range map[string][]NodeFacts{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			r := runPre(t, "KS-PRE-004", preVLLM, &ClusterFacts{ProbeRan: true, Nodes: nodes})
			if r.Applicable || len(r.Findings) != 0 {
				t.Fatalf("probe ran with no nodes must be N/A, got %+v", r)
			}
		})
	}
}

func TestNetEncryption(t *testing.T) {
	cilium := appsDoc("DaemonSet", "kube-system", "cilium", ciliumLabels, "status:\n  desiredNumberScheduled: 1\n  numberReady: 1\n")
	off := []preWant{{"ConfigMap/kube-system/cilium-config", "/data", "Cilium pod-to-pod encryption is off (enable-wireguard and enable-ipsec are not true)", Violation}}
	cases := []struct {
		name  string
		extra string
		want  []preWant
	}{
		{"wireguard", cilium + ciliumConfigDoc("kube-system", `enable-wireguard: "true"`), nil},
		{"ipsec", cilium + ciliumConfigDoc("kube-system", `enable-ipsec: "true"`, `enable-wireguard: "false"`), nil},
		{"keys absent", cilium + ciliumConfigDoc("kube-system"), off},
		{"keys false", cilium + ciliumConfigDoc("kube-system", `enable-wireguard: "false"`, `enable-ipsec: "false"`), off},
		{"config in other namespace", cilium + ciliumConfigDoc("cilium", `enable-wireguard: "true"`), []preWant{{"DaemonSet/kube-system/cilium", "", "cilium-config not found; encryption state unknown", Suspect}}},
		{"no cilium", ciliumConfigDoc("kube-system", `enable-wireguard: "true"`), []preWant{{"Namespace/ai", "", "CNI is not Cilium; kshield cannot read pod-to-pod encryption", Suspect}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkPre(t, runPre(t, "KS-NET-003", preVLLM+tc.extra, nil), tc.want)
		})
	}
}

func TestPreNotApplicableWithoutAI(t *testing.T) {
	web := strings.ReplaceAll(preVLLM, "vllm/vllm-openai:v0.6.0", "nginx:1.27.0")
	web = strings.ReplaceAll(web, `args: ["--model", "m"]`, "args: []")
	facts := &ClusterFacts{ProbeRan: true, Nodes: []NodeFacts{{Node: nodeRef("n1"), BPFLSMConfig: "n"}}}
	for _, id := range []string{"KS-PRE-001", "KS-PRE-002", "KS-PRE-003", "KS-PRE-004", "KS-NET-003"} {
		if r := runPre(t, id, web, facts); r.Applicable || len(r.Findings) != 0 {
			t.Errorf("%s without AI workloads: got %+v", id, r)
		}
	}
}

func TestPreChecksClusterTier(t *testing.T) {
	for _, id := range []string{"KS-PRE-001", "KS-PRE-002", "KS-PRE-003", "KS-PRE-004", "KS-NET-003"} {
		c, ok := ByID(id)
		if !ok || c.Tier != Cluster || c.Fix != FixManual {
			t.Errorf("%s: %+v", id, c)
		}
		if r := Evaluate(c, &Input{}); r.Applicable {
			t.Errorf("%s must be N/A in a manifest scan", id)
		}
	}
}

func TestIsCiliumAgent(t *testing.T) {
	doc := appsDoc("DaemonSet", "kube-system", "cilium", ciliumLabels, "") +
		appsDoc("DaemonSet", "kube-system", "cilium-envoy", "k8s-app: cilium-envoy\n    app.kubernetes.io/name: cilium-envoy", "") +
		appsDoc("Deployment", "kube-system", "cilium", ciliumLabels, "spec: {}\n")
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range objs {
		if IsCiliumAgent(o) {
			got = append(got, o.Ref.String())
		}
	}
	if len(got) != 1 || got[0] != "DaemonSet/kube-system/cilium" || CiliumConfigName != "cilium-config" {
		t.Fatalf("got %v, config %q", got, CiliumConfigName)
	}
}

func TestIsPrerequisite(t *testing.T) {
	doc := appsDoc("DaemonSet", "kube-system", "cilium", ciliumLabels, "") +
		appsDoc("DaemonSet", "kube-system", "tetragon", tetragonLabels, "") +
		appsDoc("Deployment", "kyverno", "kyverno-admission-controller", kyvernoLabels, "") +
		appsDoc("DaemonSet", "kube-system", "cilium-envoy", "k8s-app: cilium-envoy\n    app.kubernetes.io/name: cilium-envoy", "") +
		appsDoc("DaemonSet", "kyverno", "kyverno-admission-controller", kyvernoLabels, "") +
		appsDoc("Deployment", "kube-system", "tetragon", tetragonLabels, "") +
		appsDoc("Deployment", "kyverno", "kyverno-cleanup-controller", "app.kubernetes.io/component: cleanup-controller\n    app.kubernetes.io/part-of: kyverno", "") +
		appsDoc("Deployment", "vpa", "vpa-admission-controller", "app.kubernetes.io/component: admission-controller", "")
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range objs {
		if IsPrerequisite(o) {
			got = append(got, o.Ref.String())
		}
	}
	want := []string{"DaemonSet/kube-system/cilium", "DaemonSet/kube-system/tetragon", "Deployment/kyverno/kyverno-admission-controller"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
