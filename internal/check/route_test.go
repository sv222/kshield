package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/model"
)

const (
	routeBackends = "  rules:\n    - backendRefs:\n        - name: svc\n          port: 80\n"
	publicParent  = "  parentRefs:\n    - name: public\n      namespace: infra\n"
	routeService  = "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  namespace: ai\nspec:\n  selector:\n    app: vllm\n  ports:\n    - port: 80\n"
)

func routeDoc(annotations, spec string) string {
	doc := "---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata:\n  name: chat\n  namespace: ai\n"
	if annotations != "" {
		doc += "  annotations:\n" + annotations
	}
	return doc + "spec:\n" + spec
}

func envoyDoc(namespace, spec string) string {
	return "---\napiVersion: gateway.envoyproxy.io/v1alpha1\nkind: SecurityPolicy\nmetadata:\n  name: jwt\n  namespace: " + namespace + "\nspec:\n" + spec
}

func routeCheck(t *testing.T, doc string, cluster *ClusterFacts) Result {
	t.Helper()
	objs := readDocs(t, doc)
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	c := Check{ID: "KS-AI-013", Tier: Both, Run: aiRouteExposed}
	return Evaluate(c, &Input{Objects: objs, Workloads: ws, Cluster: cluster})
}

func TestRouteExposureIsApplicableOnlyWithAIWorkloads(t *testing.T) {
	if r := routeCheck(t, routeService, nil); r.Applicable {
		t.Errorf("no workload: %+v", r)
	}
	r := routeCheck(t, deployment(meshOllamaSpec)+routeService, nil)
	if !r.Applicable || len(r.Findings) != 0 {
		t.Errorf("no route: %+v", r)
	}
}

func TestRouteExposureFindings(t *testing.T) {
	ollama := deployment(meshOllamaSpec) + routeService
	keyed := deployment("containers:\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n    args: [\"--api-key\", \"k\"]\n") + routeService
	open := deployment(vllmContainerSpec) + routeService
	cases := []struct {
		name string
		doc  string
		want []Strength
	}{
		{"ollama behind a gateway", ollama + routeDoc("", publicParent+routeBackends), []Strength{Violation}},
		{"vllm without a key behind a gateway", open + routeDoc("", publicParent+routeBackends), []Strength{Violation}},
		{"vllm with an api key", keyed + routeDoc("", publicParent+routeBackends), nil},
		{"route to another service", ollama + routeDoc("", publicParent+"  rules:\n    - backendRefs:\n        - name: other\n"), nil},
		{"route in a mesh only", ollama + routeDoc("", "  parentRefs:\n    - name: mesh\n      kind: Service\n      group: \"\"\n"+routeBackends), nil},
		{"inference pool backend", ollama + routeDoc("", publicParent+"  rules:\n    - backendRefs:\n        - name: svc\n          group: inference.networking.k8s.io\n          kind: InferencePool\n"), nil},
		{"two backends of the same workload give one finding", ollama + routeDoc("", publicParent+"  rules:\n    - backendRefs:\n        - name: svc\n          port: 80\n        - name: svc\n          port: 81\n"), []Strength{Violation}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeCheck(t, c.doc, nil)
			var got []Strength
			for _, f := range r.Findings {
				got = append(got, f.Strength)
				if f.Object.String() != "HTTPRoute/ai/chat" || f.Path != "/spec/rules" || !strings.Contains(f.Message, "Deployment/ai/vllm") {
					t.Errorf("finding %+v", f)
				}
			}
			if len(got) != len(c.want) || (len(got) == 1 && got[0] != c.want[0]) {
				t.Errorf("strengths %v, want %v", got, c.want)
			}
		})
	}
}

func TestRouteAuthEvidence(t *testing.T) {
	ollama := deployment(meshOllamaSpec) + routeService
	cases := []struct {
		name string
		doc  string
		want Strength
		text string
	}{
		{"auth annotation on the route", routeDoc("    nginx.ingress.kubernetes.io/auth-url: https://auth/check\n", publicParent+routeBackends), Declared, "auth-url"},
		{"gateway-auth annotation on the route", routeDoc("    kshield.io/gateway-auth: \"true\"\n", publicParent+routeBackends), Declared, GatewayAuthKey},
		{"gateway-auth false", routeDoc("    kshield.io/gateway-auth: \"false\"\n", publicParent+routeBackends), Violation, ""},
		{"envoy policy on the route", routeDoc("", publicParent+routeBackends) + envoyDoc("ai", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  jwt: {}\n"), Declared, "SecurityPolicy ai/jwt enforces jwt"},
		{"envoy policy on the gateway", routeDoc("", publicParent+routeBackends) + envoyDoc("infra", "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: public}]\n  jwt:\n    providers: []\n"), Declared, "SecurityPolicy infra/jwt enforces jwt"},
		{"envoy policy on another gateway", routeDoc("", publicParent+routeBackends) + envoyDoc("infra", "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: private}]\n  jwt: {}\n"), Violation, ""},
		{"envoy policy without an auth mechanism", routeDoc("", publicParent+routeBackends) + envoyDoc("infra", "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: public}]\n  cors: {}\n"), Violation, ""},
		{"kong plugin annotation", routeDoc("    konghq.com/plugins: key-auth, rate\n", publicParent+routeBackends) + kongDoc(kindKongPlugin, "ai", "key-auth", "plugin: key-auth\n") + kongDoc(kindKongPlugin, "ai", "rate", "plugin: rate-limiting\n"), Declared, "KongPlugin ai/key-auth"},
		{"kong rate limit only", routeDoc("    konghq.com/plugins: rate\n", publicParent+routeBackends) + kongDoc(kindKongPlugin, "ai", "rate", "plugin: rate-limiting\n"), Violation, ""},
		{"kong extension ref", routeDoc("", publicParent+"  rules:\n    - filters:\n        - type: ExtensionRef\n          extensionRef: {group: configuration.konghq.com, kind: KongPlugin, name: apikey}\n      backendRefs:\n        - name: svc\n") + kongDoc(kindKongPlugin, "ai", "apikey", "plugin: key-auth\n"), Declared, "KongPlugin ai/apikey"},
		{"unbound kong cluster plugin", routeDoc("", publicParent+routeBackends) + kongDoc(kindKongClusterPlugin, "", "jwt-all", "plugin: jwt\n"), Violation, ""},
		{"non kong auth filter", routeDoc("", publicParent+"  rules:\n    - filters:\n        - type: ExtensionRef\n          extensionRef: {group: traefik.io, kind: Middleware, name: oidc-login}\n      backendRefs:\n        - name: svc\n"), Declared, "Middleware/oidc-login"},
		{"istio policy on the gateway", routeDoc("", publicParent+routeBackends) + strings.Replace(meshDoc(kindAuthorizationPolicy, "gw", gatewayTarget+principalRule), "namespace: ai", "namespace: infra", 1), Declared, "AuthorizationPolicy infra/gw"},
		{"istio policy on the workload", routeDoc("", publicParent+routeBackends) + meshDoc(kindAuthorizationPolicy, "mtls", appSelector+principalRule), Declared, "AuthorizationPolicy ai/mtls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeCheck(t, ollama+c.doc, nil)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want {
				t.Fatalf("findings %+v, want strength %v", r.Findings, c.want)
			}
			if c.text != "" && !strings.Contains(r.Findings[0].Message, c.text) {
				t.Errorf("message %q lacks %q", r.Findings[0].Message, c.text)
			}
		})
	}
}

func TestRouteDeclaredWorkloadIsInfo(t *testing.T) {
	doc := strings.Replace(deployment(meshOllamaSpec), "  namespace: ai\n", "  namespace: ai\n  annotations:\n    kshield.io/gateway-auth: \"true\"\n", 1) + routeService + routeDoc("", publicParent+routeBackends)
	r := routeCheck(t, doc, nil)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Declared || !strings.Contains(r.Findings[0].Message, GatewayAuthKey) {
		t.Fatalf("findings %+v", r.Findings)
	}
}

func TestRouteDoubt(t *testing.T) {
	ollama := deployment(meshOllamaSpec) + routeService
	route := routeDoc("", publicParent+routeBackends)
	cases := []struct {
		name    string
		doc     string
		cluster *ClusterFacts
		want    Strength
		text    string
	}{
		{"kong plugin that is not in the input", ollama + routeDoc("    konghq.com/plugins: key-auth\n", publicParent+routeBackends), nil, Suspect, "Kong plugin key-auth is not in the input"},
		{"kong extension ref that is not in the input", ollama + routeDoc("", publicParent+"  rules:\n    - filters:\n        - type: ExtensionRef\n          extensionRef: {group: configuration.konghq.com, kind: KongPlugin, name: apikey}\n      backendRefs:\n        - name: svc\n"), nil, Suspect, "Kong plugin apikey is not in the input"},
		{"parent gateway outside the scanned namespaces", ollama + route, &ClusterFacts{Namespaces: []string{"ai"}}, Suspect, "parent Gateway infra/public is outside the scanned namespaces"},
		{"parent gateway namespace is scanned", ollama + route, &ClusterFacts{Namespaces: []string{"ai", "infra"}}, Violation, ""},
		{"all namespaces scanned", ollama + route, &ClusterFacts{}, Violation, ""},
		{"parent gateway is in the input", ollama + route + "---\napiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata:\n  name: public\n  namespace: infra\nspec:\n  gatewayClassName: eg\n", &ClusterFacts{Namespaces: []string{"ai"}}, Violation, ""},
		{"manifest scan with the gateway elsewhere", ollama + route, nil, Violation, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeCheck(t, c.doc, c.cluster)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want {
				t.Fatalf("findings %+v, want strength %v", r.Findings, c.want)
			}
			if c.text != "" && !strings.Contains(r.Findings[0].Message, c.text) {
				t.Errorf("message %q lacks %q", r.Findings[0].Message, c.text)
			}
		})
	}
}
