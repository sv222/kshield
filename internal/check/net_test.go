package check

import (
	"testing"
)

func TestCiliumSelects(t *testing.T) {
	app := map[string]string{"app": "vllm"}
	cases := []struct {
		name   string
		sel    map[string]any
		ns     string
		labels map[string]string
		want   bool
	}{
		{"k8s prefix stripped", map[string]any{"matchLabels": map[string]any{"k8s:app": "vllm"}}, "ai", app, true},
		{"k8s prefix other value", map[string]any{"matchLabels": map[string]any{"k8s:app": "ollama"}}, "ai", app, false},
		{"namespace key matches", map[string]any{"matchLabels": map[string]any{"k8s:io.kubernetes.pod.namespace": "ai", "app": "vllm"}}, "ai", app, true},
		{"namespace key other ns", map[string]any{"matchLabels": map[string]any{"k8s:io.kubernetes.pod.namespace": "ai", "app": "vllm"}}, "other", app, false},
		{"namespace expression", map[string]any{"matchExpressions": []any{map[string]any{"key": "k8s:io.kubernetes.pod.namespace", "operator": "In", "values": []any{"ai"}}}}, "ai", app, true},
		{"empty selects all", map[string]any{}, "ai", app, true},
		{"empty selects unlabelled", map[string]any{}, "ai", nil, true},
		{"nil selects nothing", nil, "ai", app, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ciliumSelects(tc.sel, tc.ns, tc.labels); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestGuardConstants(t *testing.T) {
	if GuardLabel != "kshield.io/guard" || GuardShellExec != "shell-exec" || GuardEgressConnect != "egress-connect" || GuardAdmission != "admission" {
		t.Fatalf("%q %q %q %q", GuardLabel, GuardShellExec, GuardEgressConnect, GuardAdmission)
	}
}

var guardWorkload = deployment(vllmPod(`"--model", "m"`))

const (
	nsPath          = "/metadata/namespace"
	npHead          = "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n  namespace: ai\n"
	cnpHead         = "---\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: cnp\n  namespace: ai\n"
	ccnpHead        = "---\napiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: ccnp\n"
	npRef           = "NetworkPolicy/ai/np"
	cnpRef          = "CiliumNetworkPolicy/ai/cnp"
	ccnpRef         = "CiliumClusterwideNetworkPolicy/ccnp"
	appVLLM         = "    matchLabels:\n      app: vllm\n"
	cnpSelVLLM      = "  endpointSelector:\n    matchLabels:\n      k8s:app: vllm\n"
	cnpSpecsSelVLLM = "  - endpointSelector:\n      matchLabels:\n        k8s:app: vllm\n"
)

func wantNS(s Strength) []ai2Want {
	return []ai2Want{{object: deployRef, path: nsPath, strength: s}}
}

func TestNetEgressDefaultDeny(t *testing.T) {
	runAI2Cases(t, "KS-NET-001", []ai2Case{
		{"none", guardWorkload, wantNS(Violation)},
		{"netpol egress type", guardWorkload + npHead + "spec:\n  podSelector:\n" + appVLLM + "  policyTypes: [Egress]\n", nil},
		{"netpol select all", guardWorkload + npHead + "spec:\n  podSelector: {}\n  policyTypes: [Ingress, Egress]\n", nil},
		{"netpol implied egress", guardWorkload + npHead + "spec:\n  podSelector: {}\n  egress:\n    - to:\n        - podSelector: {}\n", nil},
		{"netpol empty egress list without types", guardWorkload + npHead + "spec:\n  podSelector: {}\n  egress: []\n", wantNS(Violation)},
		{"netpol ingress only", guardWorkload + npHead + "spec:\n  podSelector: {}\n  policyTypes: [Ingress]\n", wantNS(Violation)},
		{"netpol other selector", guardWorkload + npHead + "spec:\n  podSelector:\n    matchLabels:\n      app: other\n  policyTypes: [Egress]\n", wantNS(Violation)},
		{"netpol other namespace", guardWorkload + "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n  namespace: other\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n", wantNS(Violation)},
		{"cnp egress", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egress:\n    - toEndpoints:\n        - {}\n", nil},
		{"cnp egressDeny", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egressDeny:\n    - toEntities: [world]\n", nil},
		{"cnp audit form", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  enableDefaultDeny:\n    egress: false\n  egress:\n    - toEndpoints:\n        - {}\n", wantNS(Suspect)},
		{"cnp ingress only", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  ingress:\n    - fromEndpoints:\n        - {}\n", wantNS(Violation)},
		{"cnp specs entry", guardWorkload + cnpHead + "specs:\n" + cnpSpecsSelVLLM + "    egress:\n      - toEndpoints:\n          - {}\n", nil},
		{"cnp other namespace", guardWorkload + "---\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: cnp\n  namespace: other\nspec:\n  endpointSelector: {}\n  egress:\n    - toEndpoints:\n        - {}\n", wantNS(Violation)},
		{"ccnp namespace selector", guardWorkload + ccnpHead + "spec:\n  endpointSelector:\n    matchLabels:\n      k8s:io.kubernetes.pod.namespace: ai\n  egress:\n    - toEndpoints:\n        - {}\n", nil},
		{"ccnp other namespace selector", guardWorkload + ccnpHead + "spec:\n  endpointSelector:\n    matchLabels:\n      k8s:io.kubernetes.pod.namespace: other\n  egress:\n    - toEndpoints:\n        - {}\n", wantNS(Violation)},
		{"enforce beats audit", guardWorkload + cnpHead + "specs:\n" + cnpSpecsSelVLLM + "    enableDefaultDeny:\n      egress: false\n    egress:\n      - toEndpoints:\n          - {}\n" + cnpSpecsSelVLLM + "    egress:\n      - toEndpoints:\n          - {}\n", nil},
	})
}

func TestNetBroadEgress(t *testing.T) {
	w := func(ref, path string) ai2Want { return ai2Want{object: ref, path: path} }
	runAI2Cases(t, "KS-NET-002", []ai2Case{
		{"no policy", guardWorkload, nil},
		{"netpol empty to", guardWorkload + npHead + "spec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - to:\n        - podSelector: {}\n    - ports:\n        - port: 443\n", []ai2Want{w(npRef, "/spec/egress/1")}},
		{"netpol any cidr", guardWorkload + npHead + "spec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 10.0.0.0/8\n    - to:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n    - to:\n        - ipBlock:\n            cidr: \"::/0\"\n", []ai2Want{w(npRef, "/spec/egress/1"), w(npRef, "/spec/egress/2")}},
		{"netpol not covering", guardWorkload + npHead + "spec:\n  podSelector:\n    matchLabels:\n      app: other\n  policyTypes: [Egress]\n  egress:\n    - {}\n", nil},
		{"netpol ingress only ignores egress rules", guardWorkload + npHead + "spec:\n  podSelector: {}\n  policyTypes: [Ingress]\n  egress:\n    - {}\n", nil},
		{"cnp world", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egress:\n    - toEndpoints:\n        - {}\n    - toEntities: [world]\n", []ai2Want{w(cnpRef, "/spec/egress/1")}},
		{"cnp all and cidrs", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egress:\n    - toEntities: [all]\n    - toCIDR: [0.0.0.0/0]\n    - toCIDRSet:\n        - cidr: \"::/0\"\n    - toCIDR: [10.0.0.0/8]\n", []ai2Want{w(cnpRef, "/spec/egress/0"), w(cnpRef, "/spec/egress/1"), w(cnpRef, "/spec/egress/2")}},
		{"cnp specs path", guardWorkload + cnpHead + "specs:\n  - endpointSelector:\n      matchLabels:\n        app: other\n    egress:\n      - toEntities: [world]\n" + cnpSpecsSelVLLM + "    egress:\n      - toEntities: [world]\n", []ai2Want{w(cnpRef, "/specs/1/egress/0")}},
		{"ccnp world", guardWorkload + ccnpHead + "spec:\n  endpointSelector: {}\n  egress:\n    - toEntities: [world]\n", []ai2Want{w(ccnpRef, "/spec/egress/0")}},
		{"cnp world-ipv4 and world-ipv6", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egress:\n    - toEntities: [world-ipv4]\n    - toEntities: [cluster]\n    - toEntities: [World-IPv6]\n", []ai2Want{w(cnpRef, "/spec/egress/0"), w(cnpRef, "/spec/egress/2")}},
		{"ccnp in another namespace scope still selects by namespace key", guardWorkload + ccnpHead + "spec:\n  endpointSelector:\n    matchLabels:\n      k8s:io.kubernetes.pod.namespace: other\n  egress:\n    - toEntities: [world]\n", nil},
		{"cnp deny world is fine", guardWorkload + cnpHead + "spec:\n" + cnpSelVLLM + "  egressDeny:\n    - toEntities: [world]\n", nil},
	})
}

func tracing(kind, ns, guard, podSelector, hooks string) string {
	s := "---\napiVersion: cilium.io/v1alpha1\nkind: " + kind + "\nmetadata:\n  name: tp\n"
	if ns != "" {
		s += "  namespace: " + ns + "\n"
	}
	if guard != "" {
		s += "  labels:\n    kshield.io/guard: " + guard + "\n"
	}
	return s + "spec:\n" + podSelector + hooks
}

func kprobe(call, action string) string {
	return "  kprobes:\n    - call: " + call + "\n      syscall: true\n      selectors:\n        - matchActions:\n            - action: " + action + "\n"
}

func TestRuntimeShellExecGuard(t *testing.T) {
	runAI2Cases(t, "KS-RT-001", []ai2Case{
		{"none", guardWorkload, wantNS(Violation)},
		{"guard sigkill", guardWorkload + tracing("TracingPolicyNamespaced", "ai", "shell-exec", "", kprobe("sys_execve", "Sigkill")), nil},
		{"guard sigkill lowercase", guardWorkload + tracing("TracingPolicy", "", "shell-exec", "", kprobe("sys_execve", "sigkill")), nil},
		{"guard post", guardWorkload + tracing("TracingPolicyNamespaced", "ai", "shell-exec", "", kprobe("sys_execve", "Post")), wantNS(Suspect)},
		{"guard other namespace", guardWorkload + tracing("TracingPolicyNamespaced", "other", "shell-exec", "", kprobe("sys_execve", "Sigkill")), wantNS(Violation)},
		{"guard pod selector matches", guardWorkload + tracing("TracingPolicy", "", "shell-exec", "  podSelector:\n"+appVLLM, kprobe("sys_execve", "Sigkill")), nil},
		{"guard pod selector misses", guardWorkload + tracing("TracingPolicy", "", "shell-exec", "  podSelector:\n    matchLabels:\n      app: other\n", kprobe("sys_execve", "Sigkill")), wantNS(Violation)},
		{"wrong guard label", guardWorkload + tracing("TracingPolicy", "", "egress-connect", "", kprobe("tcp_connect", "Sigkill")), wantNS(Violation)},
		{"third party kprobe", guardWorkload + tracing("TracingPolicy", "", "", "", kprobe("sys_execve", "Post")), wantNS(Suspect)},
		{"third party lsm", guardWorkload + tracing("TracingPolicy", "", "", "", "  lsmhooks:\n    - hook: bprm_check_security\n"), wantNS(Suspect)},
		{"third party tracepoint", guardWorkload + tracing("TracingPolicy", "", "", "", "  tracepoints:\n    - subsystem: syscalls\n      event: sys_enter_execve\n"), wantNS(Suspect)},
		{"wrong group", guardWorkload + "---\napiVersion: example.io/v1\nkind: TracingPolicy\nmetadata:\n  name: tp\n  labels:\n    kshield.io/guard: shell-exec\nspec:\n" + kprobe("sys_execve", "Sigkill"), wantNS(Violation)},
	})
}

func TestRuntimeEgressConnectGuard(t *testing.T) {
	runAI2Cases(t, "KS-RT-002", []ai2Case{
		{"none", guardWorkload, wantNS(Violation)},
		{"guard override", guardWorkload + tracing("TracingPolicy", "", "egress-connect", "", kprobe("tcp_connect", "Override")), nil},
		{"guard sigkill", guardWorkload + tracing("TracingPolicyNamespaced", "ai", "egress-connect", "", kprobe("tcp_connect", "Sigkill")), nil},
		{"guard post", guardWorkload + tracing("TracingPolicy", "", "egress-connect", "", kprobe("tcp_connect", "Post")), wantNS(Suspect)},
		{"third party connect", guardWorkload + tracing("TracingPolicy", "", "", "", kprobe("__sys_connect", "Post")), wantNS(Suspect)},
		{"shell guard does not count", guardWorkload + tracing("TracingPolicy", "", "shell-exec", "", kprobe("sys_execve", "Sigkill")), wantNS(Violation)},
	})
}

func kyverno(kind, ns, guard, spec string) string {
	s := "---\napiVersion: kyverno.io/v1\nkind: " + kind + "\nmetadata:\n  name: kp\n"
	if ns != "" {
		s += "  namespace: " + ns + "\n"
	}
	if guard != "" {
		s += "  labels:\n    kshield.io/guard: " + guard + "\n"
	}
	return s + "spec:\n" + spec
}

func kyvernoRule(namespaces, failureAction string) string {
	s := "    - name: r\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n"
	if namespaces != "" {
		s += "              namespaces: [" + namespaces + "]\n"
	}
	s += "      validate:\n"
	if failureAction != "" {
		s += "        failureAction: " + failureAction + "\n"
	}
	return s + "        pattern:\n          spec: {}\n"
}

const ruleExclude = "      exclude:\n        any:\n          - resources:\n              names: [debug-*]\n"

const psaNamespace = "---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: ai\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n"

func TestRuntimeAdmissionGuard(t *testing.T) {
	runAI2Cases(t, "KS-RT-003", []ai2Case{
		{"none", guardWorkload, wantNS(Violation)},
		{"cluster enforce", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: enforce\n  rules:\n"+kyvernoRule("", "")), nil},
		{"cluster rule enforce", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("ai", "Enforce")), nil},
		{"failure action overrides", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Enforce\n  validationFailureActionOverrides:\n    - action: Audit\n      namespaces: [ai]\n  rules:\n"+kyvernoRule("", "")), wantNS(Suspect)},
		{"rule exclude", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")+"      exclude:\n        any:\n          - resources:\n              namespaces: [ai]\n"), wantNS(Suspect)},
		{"match namespace selector", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Enforce\n  rules:\n    - name: r\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n              namespaceSelector:\n                matchLabels:\n                  team: ml\n      validate:\n        pattern:\n          spec: {}\n"), wantNS(Suspect)},
		{"namespaced policy with rule failure action", guardWorkload + kyverno("Policy", "ai", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+kyvernoRule("", "Enforce")), nil},
		{"spec enforce rule audit", guardWorkload + kyverno("Policy", "ai", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")+kyvernoRule("", "Audit")), wantNS(Suspect)},
		{"spec audit rule enforce", guardWorkload + kyverno("Policy", "ai", "admission", "  validationFailureAction: Audit\n  rules:\n"+kyvernoRule("", "Enforce")), nil},
		{"rule enforce and rule without action", guardWorkload + kyverno("Policy", "ai", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+kyvernoRule("", "")), wantNS(Suspect)},
		{"spec enforce without validate rule", guardWorkload + kyverno("Policy", "ai", "admission", "  validationFailureAction: Enforce\n  rules:\n    - name: r\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n      mutate:\n        patchStrategicMerge:\n          spec: {}\n"), wantNS(Suspect)},
		{"rule failure action overrides", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+"        failureActionOverrides:\n          - action: Audit\n            namespaces: [ai]\n"), wantNS(Suspect)},
		{"plain enforce guard beats an approximated one", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+ruleExclude) +
			kyverno("Policy", "ai", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")), nil},
		{"cluster rule mixed", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+kyvernoRule("", "Audit")), wantNS(Suspect)},
		{"cluster audit", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Audit\n  rules:\n"+kyvernoRule("", "")), wantNS(Suspect)},
		{"cluster other namespace", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("other", "")), wantNS(Violation)},
		{"cluster wildcard namespace", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("a*", "")), nil},
		{"namespaced enforce", guardWorkload + kyverno("Policy", "ai", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")), nil},
		{"namespaced other ns", guardWorkload + kyverno("Policy", "other", "admission", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")), wantNS(Violation)},
		{"unlabelled", guardWorkload + kyverno("ClusterPolicy", "", "", "  validationFailureAction: Enforce\n  rules:\n"+kyvernoRule("", "")), wantNS(Violation)},
		{"psa restricted", guardWorkload + psaNamespace, wantNS(Suspect)},
		{"guard audit beats psa", guardWorkload + psaNamespace + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("", "Audit")), wantNS(Suspect)},
	})
}

func TestGuardChecksMessages(t *testing.T) {
	cases := []struct {
		id, doc, want string
	}{
		{"KS-RT-001", guardWorkload + tracing("TracingPolicy", "", "", "", kprobe("sys_execve", "Post")), "unverified third-party exec policy"},
		{"KS-RT-003", guardWorkload + psaNamespace, "partial: PSA does not cover shm hostPath or pickle loading"},
		{"KS-RT-003", guardWorkload + kyverno("ClusterPolicy", "", "admission", "  rules:\n"+kyvernoRule("", "Enforce")+ruleExclude), "guard scope or action not fully evaluated"},
	}
	for _, tc := range cases {
		r := runWL(t, tc.id, tc.doc)
		if len(r.Findings) != 1 || len(r.Findings[0].Message) < len(tc.want) || r.Findings[0].Message[:len(tc.want)] != tc.want {
			t.Errorf("%s: got %+v, want message starting %q", tc.id, r.Findings, tc.want)
		}
	}
}

func TestGuardChecksApplicability(t *testing.T) {
	generic := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: ai\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: nginx:1.27\n"
	for _, id := range []string{"KS-NET-001", "KS-NET-002", "KS-RT-001", "KS-RT-002", "KS-RT-003"} {
		if r := runWL(t, id, generic); r.Applicable || len(r.Findings) != 0 {
			t.Errorf("%s: must be N/A without AI workloads, got %+v", id, r)
		}
	}
	for _, id := range []string{"KS-NET-003", "KS-PRE-001", "KS-PRE-002", "KS-PRE-003", "KS-PRE-004"} {
		c, _ := ByID(id)
		if r := Evaluate(c, &Input{Cluster: &ClusterFacts{}}); r.Applicable {
			t.Errorf("%s: must be N/A without cluster facts", id)
		}
	}
}

const clusterServingRuntime = "---\napiVersion: serving.kserve.io/v1alpha1\nkind: ClusterServingRuntime\nmetadata:\n  name: csr\nspec:\n  containers:\n    - name: kserve-container\n      image: kserve/huggingfaceserver:v0.15.0\n"

func TestNamespaceChecksSkipClusterScopedTemplates(t *testing.T) {
	ids := []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003", "KS-WL-010"}
	for _, id := range ids {
		if r := runWL(t, id, clusterServingRuntime); r.Applicable || len(r.Findings) != 0 {
			t.Errorf("%s: only a cluster-scoped template must be N/A, got %+v", id, r)
		}
		r := runWL(t, id, guardWorkload+clusterServingRuntime)
		if !r.Applicable || len(r.Findings) != 1 || r.Findings[0].Object.String() != deployRef {
			t.Errorf("%s: want one finding on %s only, got %+v", id, deployRef, r)
		}
	}
	for _, id := range []string{"KS-WL-001", "KS-WL-009", "KS-WL-012"} {
		r := runWL(t, id, clusterServingRuntime)
		if !r.Applicable || len(r.Findings) != 1 || r.Findings[0].Object.String() != "ClusterServingRuntime/csr" {
			t.Errorf("%s: container checks still apply to the template, got %+v", id, r)
		}
	}
}

func TestGuardChecksRegistered(t *testing.T) {
	want := []struct {
		id    string
		title string
		tier  Tier
		fix   Fix
	}{
		{"KS-NET-001", "AI namespace has no default-deny egress (no CNP/NetworkPolicy in input or cluster)", Both, FixPolicy},
		{"KS-NET-002", "Egress allow-list too broad (world, 0.0.0.0/0)", Both, FixPolicy},
		{"KS-NET-003", "Pod-to-pod encryption off (Cilium WireGuard/IPsec)", Cluster, FixManual},
		{"KS-RT-001", "No runtime shell-exec guard on AI namespace (Tetragon)", Both, FixPolicy},
		{"KS-RT-002", "No runtime egress-connect guard on AI namespace (Tetragon)", Both, FixPolicy},
		{"KS-RT-003", "No admission guard for root, host namespaces, shm hostPath, pickle load (Kyverno)", Both, FixPolicy},
		{"KS-PRE-001", "Tetragon missing or unhealthy", Cluster, FixManual},
		{"KS-PRE-002", "CNI is not Cilium (L7/FQDN egress not possible)", Cluster, FixManual},
		{"KS-PRE-003", "Kyverno missing or unhealthy", Cluster, FixManual},
		{"KS-PRE-004", "Node kernel lacks BPF LSM (--node-probe)", Cluster, FixManual},
	}
	all := All()
	const first = 23
	if len(all) != 33 {
		t.Fatalf("catalog has %d checks, want 33", len(all))
	}
	for i, w := range want {
		c := all[first+i]
		if c.ID != w.id || c.Title != w.title || c.Fix != w.fix || c.Tier != w.tier {
			t.Errorf("catalog[%d] = %s %q fix=%s tier=%d, want %s %q fix=%s tier=%d", first+i, c.ID, c.Title, c.Fix, c.Tier, w.id, w.title, w.fix, w.tier)
		}
	}
}
