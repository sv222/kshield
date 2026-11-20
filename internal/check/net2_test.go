package check

import (
	"strings"
	"testing"
)

const ingressVLLM = "containers:\n  - {name: vllm, image: \"vllm/vllm-openai:v0.6.0\"}\n"

func netpolDoc(namespace, spec string) string {
	return "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n  namespace: " + namespace + "\n" + spec
}

func ciliumDoc(kind, namespace, spec string) string {
	ns := ""
	if namespace != "" {
		ns = "  namespace: " + namespace + "\n"
	}
	return "---\napiVersion: cilium.io/v2\nkind: " + kind + "\nmetadata:\n  name: cnp\n" + ns + spec
}

const (
	denyIngress   = "spec:\n  podSelector: {}\n  policyTypes: [Ingress]\n"
	ciliumGateway = "spec:\n  endpointSelector:\n    matchLabels: {app: vllm}\n  ingress:\n    - fromEndpoints:\n        - matchLabels: {role: gateway}\n"
)

func ingressRule(rule string) string {
	return denyIngress + "  ingress:\n" + rule
}

func TestIngressIsolation(t *testing.T) {
	cases := []struct {
		name     string
		extra    string
		strength []Strength
		contains string
	}{
		{"no policy", "", []Strength{Violation}, "no NetworkPolicy or Cilium policy restricts ingress"},
		{"deny all ingress", netpolDoc("ai", denyIngress), nil, ""},
		{"selector for the workload", netpolDoc("ai", "spec:\n  podSelector:\n    matchLabels: {app: vllm}\n  policyTypes: [Ingress]\n"), nil, ""},
		{"selector for another workload", netpolDoc("ai", "spec:\n  podSelector:\n    matchLabels: {app: other}\n  policyTypes: [Ingress]\n"), []Strength{Violation}, "no NetworkPolicy or Cilium policy"},
		{"policy in another namespace", netpolDoc("other", denyIngress), []Strength{Violation}, "no NetworkPolicy or Cilium policy"},
		{"ingress type absent from the types", netpolDoc("ai", "spec:\n  podSelector: {}\n  policyTypes: [Egress]\n"), []Strength{Violation}, "has no Ingress policyType"},
		{"policy types missing default to ingress", netpolDoc("ai", "spec:\n  podSelector: {}\n  egress:\n    - {}\n"), nil, ""},
		{"same namespace peer", netpolDoc("ai", ingressRule("    - from:\n        - podSelector: {}\n")), nil, ""},
		{"namespace selector with labels", netpolDoc("ai", ingressRule("    - from:\n        - namespaceSelector:\n            matchLabels: {team: ml}\n")), nil, ""},
		{"rule without from", netpolDoc("ai", ingressRule("    - ports:\n        - port: 8000\n")), []Strength{Violation}, "allows traffic from every source"},
		{"empty rule", netpolDoc("ai", ingressRule("    - {}\n")), []Strength{Violation}, "allows traffic from every source"},
		{"open ipv4 block", netpolDoc("ai", ingressRule("    - from:\n        - ipBlock: {cidr: 0.0.0.0/0}\n")), []Strength{Violation}, "every source"},
		{"open ipv6 block", netpolDoc("ai", ingressRule("    - from:\n        - ipBlock: {cidr: \"::/0\"}\n")), []Strength{Violation}, "every source"},
		{"open block with an exception", netpolDoc("ai", ingressRule("    - from:\n        - ipBlock: {cidr: 0.0.0.0/0, except: [10.0.0.0/8]}\n")), nil, ""},
		{"narrow block", netpolDoc("ai", ingressRule("    - from:\n        - ipBlock: {cidr: 10.0.0.0/8}\n")), nil, ""},
		{"every namespace", netpolDoc("ai", ingressRule("    - from:\n        - namespaceSelector: {}\n")), []Strength{Violation}, "every source"},
		{"every namespace and every pod", netpolDoc("ai", ingressRule("    - from:\n        - namespaceSelector: {}\n          podSelector: {}\n")), []Strength{Violation}, "every source"},
		{"every namespace but selected pods", netpolDoc("ai", ingressRule("    - from:\n        - namespaceSelector: {}\n          podSelector:\n            matchLabels: {role: gateway}\n")), nil, ""},
		{"one narrow and one open peer", netpolDoc("ai", ingressRule("    - from:\n        - podSelector: {}\n        - ipBlock: {cidr: 0.0.0.0/0}\n")), []Strength{Violation}, "every source"},
		{"cilium ingress rule", ciliumDoc("CiliumNetworkPolicy", "ai", ciliumGateway), nil, ""},
		{"cilium cluster wide ingress rule", ciliumDoc("CiliumClusterwideNetworkPolicy", "", ciliumGateway), nil, ""},
		{"cilium rule for another workload", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector:\n    matchLabels: {app: other}\n  ingress:\n    - fromEndpoints:\n        - {}\n"), []Strength{Violation}, "no NetworkPolicy or Cilium policy"},
		{"cilium egress rules only", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  egress:\n    - toEntities: [cluster]\n"), []Strength{Violation}, "no NetworkPolicy or Cilium policy"},
		{"cilium world entity", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [world]\n"), []Strength{Violation}, "Cilium policy cnp has an ingress rule that allows traffic from every source"},
		{"cilium open cidr", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  ingress:\n    - fromCIDR: [0.0.0.0/0]\n"), []Strength{Violation}, "every source"},
		{"cilium open cidr set", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  ingress:\n    - fromCIDRSet:\n        - cidr: \"::/0\"\n"), []Strength{Violation}, "every source"},
		{"cilium audit form", ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  enableDefaultDeny:\n    ingress: false\n  ingress:\n    - fromEndpoints:\n        - matchLabels: {role: gateway}\n"), []Strength{Suspect}, "audit form"},
		{"cilium isolates and a network policy is open", ciliumDoc("CiliumNetworkPolicy", "ai", ciliumGateway) + netpolDoc("ai", ingressRule("    - {}\n")), []Strength{Violation}, "NetworkPolicy np has an ingress rule"},
		{"network policy isolates and cilium is open", netpolDoc("ai", denyIngress) + ciliumDoc("CiliumNetworkPolicy", "ai", "spec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [all]\n"), []Strength{Violation}, "Cilium policy cnp has an ingress rule"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-NET-004", deployment(ingressVLLM)+c.extra)
			if !r.Applicable || len(r.Findings) != len(c.strength) {
				t.Fatalf("findings = %+v", r.Findings)
			}
			for i, f := range r.Findings {
				if f.Strength != c.strength[i] || f.Path != namespacePath || !strings.Contains(f.Message, c.contains) {
					t.Errorf("finding = %+v, want strength %d containing %q", f, c.strength[i], c.contains)
				}
			}
		})
	}
}

func TestIngressIsolationNotApplicable(t *testing.T) {
	c, _ := ByID("KS-NET-004")
	if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("empty input: %+v", r)
	}
	if r := runWL(t, "KS-NET-004", deployment("containers:\n  - {name: web, image: nginx}\n")); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("generic workload: %+v", r)
	}
}
