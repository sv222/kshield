package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

func TestAuthEvidencePresent(t *testing.T) {
	if (AuthEvidence{}).Present() {
		t.Error("zero evidence is present")
	}
	if !(AuthEvidence{Source: AuthIngressAnnotation}).Present() {
		t.Error("evidence with a source is not present")
	}
}

func TestAuthEvidenceSuffix(t *testing.T) {
	declared := AuthEvidence{Source: AuthGatewayDeclared, Detail: GatewayAuthKey}
	if declared.Suffix() != declaredSuffix {
		t.Errorf("declared suffix %q, want %q", declared.Suffix(), declaredSuffix)
	}
	policy := AuthEvidence{Source: AuthIngressAnnotation, Ref: load.ObjectRef{Kind: "AuthorizationPolicy", Namespace: "llm", Name: "jwt"}, Detail: "allows only authenticated principals"}
	got := policy.Suffix()
	for _, want := range []string{"AuthorizationPolicy llm/jwt", "allows only authenticated principals", "cannot check"} {
		if !strings.Contains(got, want) {
			t.Errorf("suffix %q lacks %q", got, want)
		}
	}
}

func authWorkload(t *testing.T, podSpec, extra string) (*Input, model.Workload) {
	t.Helper()
	return exposureInput(t, podSpec, extra)
}

func TestDeclaredAuth(t *testing.T) {
	cases := []struct {
		name string
		meta string
		want bool
	}{
		{"annotation true", "  annotations:\n    kshield.io/gateway-auth: \"true\"\n", true},
		{"label true", "  labels:\n    kshield.io/gateway-auth: \"true\"\n", true},
		{"annotation false", "  annotations:\n    kshield.io/gateway-auth: \"false\"\n", false},
		{"none", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := strings.Replace(deployment(vllmContainerSpec), "  namespace: ai\n", "  namespace: ai\n"+c.meta, 1)
			objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
			if err != nil {
				t.Fatal(err)
			}
			ws, err := model.Extract(objs)
			if err != nil {
				t.Fatal(err)
			}
			a, ok := declaredAuth(ws[0])
			if ok != c.want || a.Present() != c.want {
				t.Fatalf("declaredAuth ok=%v evidence=%+v, want %v", ok, a, c.want)
			}
			if ok && a.Source != AuthGatewayDeclared {
				t.Errorf("source %q", a.Source)
			}
		})
	}
}

func TestIngressAuthEvidence(t *testing.T) {
	cases := []struct {
		name        string
		annotations string
		want        AuthSource
	}{
		{"auth-url", "    nginx.ingress.kubernetes.io/auth-url: https://auth/check\n", AuthIngressAnnotation},
		{"auth-signin", "    nginx.ingress.kubernetes.io/auth-signin: https://auth/start\n", AuthIngressAnnotation},
		{"gateway-auth", "    kshield.io/gateway-auth: \"true\"\n", AuthIngressAnnotation},
		{"gateway-auth false", "    kshield.io/gateway-auth: \"false\"\n", ""},
		{"unrelated", "    nginx.ingress.kubernetes.io/rewrite-target: /\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, w := exposureInput(t, vllmContainerSpec, svcDoc("ai", "svc", "", "app: vllm", "port: 80")+ingressDoc(ingressAPIVersion, "ai", "web", c.annotations, ruleSpec("svc")))
			es := Exposures(in, w, nil)
			if len(es) != 1 {
				t.Fatalf("exposures %+v", es)
			}
			if es[0].Auth.Source != c.want {
				t.Errorf("source %q, want %q (%+v)", es[0].Auth.Source, c.want, es[0].Auth)
			}
			if c.want != "" && es[0].Auth.Ref.Name != "web" {
				t.Errorf("ref %+v does not name the Ingress", es[0].Auth.Ref)
			}
		})
	}
}

func TestEngineKeyAuth(t *testing.T) {
	const keyed = `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", "k"]
`
	in, w := authWorkload(t, keyed, "")
	v := serverAuth(in, w)
	if v.open || !v.keyed.Present() || v.keyed.Source != AuthEngineKey {
		t.Fatalf("keyed server %+v", v)
	}
	in, w = authWorkload(t, vllmContainerSpec, "")
	v = serverAuth(in, w)
	if !v.open || v.keyed.Present() {
		t.Fatalf("open server %+v", v)
	}
}
