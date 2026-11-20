package check

import (
	"strings"
	"testing"
)

func kongIngressDoc(annotations string) string {
	return deployment(vllmContainerSpec) + svcDoc("ai", "svc", "", "app: vllm", "port: 80") + ingressDoc(ingressAPIVersion, "ai", "web", annotations, ruleSpec("svc"))
}

func TestKongProtectedIngressIsInfo(t *testing.T) {
	auth := kongDoc(kindKongPlugin, "ai", "key-auth", "plugin: key-auth\n")
	rate := kongDoc(kindKongPlugin, "ai", "rate", "plugin: rate-limiting\n")
	anon := kongDoc(kindKongPlugin, "ai", "anon", "plugin: key-auth\nconfig:\n  anonymous: consumer\n")
	cases := []struct {
		name string
		doc  string
		want Strength
		text string
	}{
		{"auth plugin on the ingress", kongIngressDoc("    konghq.com/plugins: key-auth\n") + auth, Declared, "KongPlugin ai/key-auth"},
		{"rate limit plugin", kongIngressDoc("    konghq.com/plugins: rate\n") + rate, Violation, ""},
		{"anonymous consumer", kongIngressDoc("    konghq.com/plugins: anon\n") + anon, Violation, ""},
		{"no plugin", kongIngressDoc(""), Violation, ""},
		{"plugin object missing", kongIngressDoc("    konghq.com/plugins: key-auth\n"), Violation, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", c.doc)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want || r.Findings[0].Object.String() != "Ingress/ai/web" {
				t.Fatalf("findings %+v", r.Findings)
			}
			if c.text != "" && !strings.Contains(r.Findings[0].Message, c.text) {
				t.Errorf("message %q lacks %q", r.Findings[0].Message, c.text)
			}
		})
	}
}

func TestKongPluginOnTheServiceProtectsTheIngress(t *testing.T) {
	doc := deployment(vllmContainerSpec) +
		"---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  namespace: ai\n  annotations:\n    konghq.com/plugins: jwt-all\nspec:\n  selector:\n    app: vllm\n  ports:\n    - port: 80\n" +
		ingressDoc(ingressAPIVersion, "ai", "web", "", ruleSpec("svc")) +
		kongDoc(kindKongClusterPlugin, "", "jwt-all", "plugin: jwt\n")
	r := runWL(t, "KS-AI-004", doc)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Declared || !strings.Contains(r.Findings[0].Message, "KongClusterPlugin jwt-all") {
		t.Fatalf("findings %+v", r.Findings)
	}
}

func TestKongPluginDoesNotProtectALoadBalancerService(t *testing.T) {
	doc := deployment(vllmContainerSpec) +
		"---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  namespace: ai\n  annotations:\n    konghq.com/plugins: key-auth\nspec:\n  type: LoadBalancer\n  selector:\n    app: vllm\n  ports:\n    - port: 80\n" +
		kongDoc(kindKongPlugin, "ai", "key-auth", "plugin: key-auth\n")
	r := runWL(t, "KS-AI-004", doc)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Violation {
		t.Fatalf("findings %+v", r.Findings)
	}
}
