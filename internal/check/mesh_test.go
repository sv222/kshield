package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

func meshDoc(kind, name, spec string) string {
	return "---\napiVersion: security.istio.io/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n  namespace: ai\nspec:\n" + spec
}

func parseMeshDoc(t *testing.T, doc string) (meshPolicy, bool) {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	return parseMeshPolicy(objs[0])
}

const (
	principalRule  = "  rules: [{from: [{source: {principals: [\"a\"]}}]}]\n"
	requestAllow   = "  rules: [{from: [{source: {requestPrincipals: [\"*\"]}}]}]\n"
	appSelector    = "  selector: {matchLabels: {app: vllm}}\n"
	jwtRule        = "  jwtRules: [{issuer: \"https://i.example.com\"}]\n"
	gatewayTarget  = "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: public}]\n"
	serviceTarget  = "  targetRefs: [{kind: Service, name: svc}]\n"
	meshOllamaSpec = "containers:\n  - name: ollama\n    image: ollama/ollama:0.40.3\n"
)

func TestParseMeshPolicy(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		spec    string
		ok      bool
		jwt     bool
		targets string
	}{
		{"request authentication with a rule", kindRequestAuthentication, appSelector + jwtRule, true, false, ""},
		{"request authentication without rules", kindRequestAuthentication, "  {}\n", false, false, ""},
		{"allow request principals on a gateway and a service", kindAuthorizationPolicy, "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: public}, {kind: Service, name: vllm}]\n" + requestAllow, true, true, "Gateway/ai/public,Service/ai/vllm"},
		{"allow principals", kindAuthorizationPolicy, appSelector + principalRule, true, false, ""},
		{"allow with no rules denies everything", kindAuthorizationPolicy, "  action: ALLOW\n", false, false, ""},
		{"allow where one rule has no identity", kindAuthorizationPolicy, "  rules: [{from: [{source: {principals: [\"a\"]}}]}, {to: [{operation: {methods: [GET]}}]}]\n", false, false, ""},
		{"allow with only an operation", kindAuthorizationPolicy, "  rules: [{to: [{operation: {methods: [GET, POST]}}]}]\n", false, false, ""},
		{"deny not request principals", kindAuthorizationPolicy, "  action: DENY\n  rules: [{from: [{source: {notRequestPrincipals: [\"*\"]}}]}]\n", true, true, ""},
		{"deny not principals", kindAuthorizationPolicy, "  action: DENY\n  rules: [{from: [{source: {notPrincipals: [\"*\"]}}]}]\n", true, false, ""},
		{"deny scoped to a path", kindAuthorizationPolicy, "  action: DENY\n  rules: [{from: [{source: {notRequestPrincipals: [\"*\"]}}], to: [{operation: {paths: [\"/admin\"]}}]}]\n", false, false, ""},
		{"custom provider", kindAuthorizationPolicy, "  action: CUSTOM\n  provider: {name: oauth2-proxy}\n", true, false, ""},
		{"custom without a provider", kindAuthorizationPolicy, "  action: CUSTOM\n", false, false, ""},
		{"a Gateway ref needs the gateway group", kindAuthorizationPolicy, "  targetRefs: [{kind: Gateway, name: public}]\n" + principalRule, true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := parseMeshDoc(t, meshDoc(c.kind, "p", c.spec))
			if ok != c.ok {
				t.Fatalf("authenticates = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if p.jwt != c.jwt || strings.Join(p.targets, ",") != c.targets {
				t.Errorf("jwt=%v targets=%q, want jwt=%v targets=%q", p.jwt, strings.Join(p.targets, ","), c.jwt, c.targets)
			}
		})
	}
}

func meshInput(t *testing.T, extra string) (*Input, model.Workload) {
	t.Helper()
	return exposureInput(t, meshOllamaSpec, svcDoc("ai", "svc", "LoadBalancer", "app: vllm", "port: 11434")+extra)
}

func TestMeshAuthApplies(t *testing.T) {
	cases := []struct {
		name     string
		extra    string
		svc      string
		gateways []string
		want     bool
		wantText string
	}{
		{"no policy", "", "svc", nil, false, ""},
		{"selector policy with principals", meshDoc(kindAuthorizationPolicy, "mtls", appSelector+principalRule), "svc", nil, true, "AuthorizationPolicy ai/mtls"},
		{"namespace wide policy", meshDoc(kindAuthorizationPolicy, "wide", principalRule), "svc", nil, true, "AuthorizationPolicy ai/wide"},
		{"selector does not match", meshDoc(kindAuthorizationPolicy, "other", "  selector: {matchLabels: {app: other}}\n"+principalRule), "svc", nil, false, ""},
		{"policy in another namespace", strings.Replace(meshDoc(kindAuthorizationPolicy, "x", principalRule), "namespace: ai", "namespace: other", 1), "svc", nil, false, ""},
		{"request principals need a request authentication", meshDoc(kindAuthorizationPolicy, "jwt", appSelector+requestAllow), "svc", nil, false, ""},
		{"request principals with a request authentication", meshDoc(kindAuthorizationPolicy, "jwt", appSelector+requestAllow) + meshDoc(kindRequestAuthentication, "jwt", appSelector+jwtRule), "svc", nil, true, "(JWT, with RequestAuthentication ai/jwt)"},
		{"authorization policy that allows any caller", meshDoc(kindAuthorizationPolicy, "any", appSelector+"  rules: [{to: [{operation: {methods: [GET]}}]}]\n"), "svc", nil, false, ""},
		{"service target", meshDoc(kindAuthorizationPolicy, "svc", serviceTarget+principalRule), "svc", nil, true, "AuthorizationPolicy ai/svc"},
		{"service target of another service", meshDoc(kindAuthorizationPolicy, "svc", serviceTarget+principalRule), "other", nil, false, ""},
		{"gateway target", meshDoc(kindAuthorizationPolicy, "gw", gatewayTarget+principalRule), "svc", []string{"ai/public"}, true, "AuthorizationPolicy ai/gw"},
		{"gateway target of another gateway", meshDoc(kindAuthorizationPolicy, "gw", gatewayTarget+principalRule), "svc", []string{"ai/private"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, w := meshInput(t, c.extra)
			a, ok := meshAuth(in, w, c.svc, c.gateways)
			if ok != c.want {
				t.Fatalf("meshAuth = %v (%+v), want %v", ok, a, c.want)
			}
			if ok && (a.Source != AuthIstio || !strings.Contains(a.Text(), c.wantText)) {
				t.Errorf("evidence %+v lacks %q", a, c.wantText)
			}
		})
	}
}

func TestWorkloadAuthUsesMeshSelectorPolicies(t *testing.T) {
	in, w := meshInput(t, meshDoc(kindAuthorizationPolicy, "mtls", appSelector+principalRule))
	if a, ok := workloadAuth(in, w); !ok || a.Source != AuthIstio {
		t.Fatalf("workloadAuth = %+v %v", a, ok)
	}
	in, w = meshInput(t, meshDoc(kindAuthorizationPolicy, "svc", serviceTarget+principalRule))
	if a, ok := workloadAuth(in, w); ok {
		t.Fatalf("a Service target must not protect the workload itself: %+v", a)
	}
}

func TestMeshSelectorPolicyMakesEngineKeyFindingsInfo(t *testing.T) {
	policy := meshDoc(kindAuthorizationPolicy, "mtls", appSelector+principalRule)
	for id, spec := range map[string]string{"KS-AI-001": vllmContainerSpec, "KS-AI-010": meshOllamaSpec} {
		open := runWL(t, id, deployment(spec))
		if len(open.Findings) != 1 || open.Findings[0].Strength == Declared {
			t.Fatalf("%s unprotected: %+v", id, open.Findings)
		}
		prot := runWL(t, id, deployment(spec)+policy)
		if len(prot.Findings) != 1 || prot.Findings[0].Strength != Declared || !strings.Contains(prot.Findings[0].Message, "AuthorizationPolicy ai/mtls") {
			t.Errorf("%s protected: %+v", id, prot.Findings)
		}
	}
}
