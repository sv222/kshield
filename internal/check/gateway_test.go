package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
)

func readDocs(t *testing.T, doc string) []load.Object {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{DefaultNamespace: "llm", Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func TestParseHTTPRoute(t *testing.T) {
	objs := readDocs(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chat
spec:
  parentRefs:
    - name: public
      namespace: infra
    - name: mesh
      kind: Service
      group: ""
  rules:
    - backendRefs:
        - name: vllm
          port: 8000
        - name: vllm
          port: 8001
        - name: remote
          namespace: other
        - name: pool
          group: inference.networking.k8s.io
          kind: InferencePool
    - filters:
        - type: ExtensionRef
          extensionRef:
            group: traefik.io
            kind: Middleware
            name: oidc-login
        - type: ExtensionRef
          extensionRef:
            group: configuration.konghq.com
            kind: KongPlugin
            name: key-auth
        - type: RequestHeaderModifier
      backendRefs:
        - name: ollama
          filters:
            - type: ExtensionRef
              extensionRef:
                group: configuration.konghq.com
                kind: KongPlugin
                name: jwt
`)
	r := parseHTTPRoute(objs[0])
	if got := strings.Join(r.gateways, ","); got != "infra/public" {
		t.Errorf("gateways %q", got)
	}
	var services []string
	for _, s := range r.services {
		services = append(services, s.namespace+"/"+s.name)
	}
	if got := strings.Join(services, ","); got != "llm/vllm,other/remote,llm/ollama" {
		t.Errorf("services %q", got)
	}
	if got := strings.Join(r.plugins, ","); got != "key-auth,jwt" {
		t.Errorf("plugins %q", got)
	}
	if r.authFilter != "Middleware/oidc-login" {
		t.Errorf("authFilter %q", r.authFilter)
	}
}

func TestParseHTTPRouteFilterNamesAreNotAuth(t *testing.T) {
	objs := readDocs(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: plain
spec:
  rules:
    - filters:
        - type: ExtensionRef
          extensionRef: {group: traefik.io, kind: Middleware, name: rate-limit}
      backendRefs:
        - name: vllm
`)
	r := parseHTTPRoute(objs[0])
	if r.authFilter != "" || len(r.gateways) != 0 {
		t.Errorf("route %+v", r)
	}
}

func TestParseEnvoyPolicy(t *testing.T) {
	cases := []struct {
		name      string
		spec      string
		ok        bool
		mechanism string
		targets   string
	}{
		{"jwt on a gateway", "  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: public}]\n  jwt:\n    providers: []\n", true, "jwt", "Gateway/llm/public"},
		{"oidc on a route", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  oidc: {provider: {issuer: https://i.example.com}}\n", true, "oidc", "HTTPRoute/llm/chat"},
		{"basic auth", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  basicAuth: {users: {name: users}}\n", true, "basicAuth", "HTTPRoute/llm/chat"},
		{"api key auth", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  apiKeyAuth: {}\n", true, "apiKeyAuth", "HTTPRoute/llm/chat"},
		{"ext auth", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  extAuth: {http: {}}\n", true, "extAuth", "HTTPRoute/llm/chat"},
		{"cors only", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  cors:\n    allowOrigins: [\"*\"]\n", false, "", ""},
		{"a null mechanism", "  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: chat}\n  jwt: null\n", false, "", ""},
		{"a ref without a kind targets both", "  targetRef: {group: gateway.networking.k8s.io, name: x}\n  jwt: {}\n", true, "jwt", "Gateway/llm/x,HTTPRoute/llm/x"},
		{"a ref of another group", "  targetRef: {group: example.com, kind: Gateway, name: x}\n  jwt: {}\n", true, "jwt", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := readDocs(t, "apiVersion: gateway.envoyproxy.io/v1alpha1\nkind: SecurityPolicy\nmetadata:\n  name: p\nspec:\n"+c.spec)
			p, ok := parseEnvoyPolicy(objs[0])
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && (p.mechanism != c.mechanism || strings.Join(p.targets, ",") != c.targets) {
				t.Errorf("mechanism %q targets %q, want %q %q", p.mechanism, strings.Join(p.targets, ","), c.mechanism, c.targets)
			}
		})
	}
}

func TestIndexKeepsGatewayKinds(t *testing.T) {
	objs := readDocs(t, `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: infra
spec:
  gatewayClassName: eg
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chat
spec:
  parentRefs: [{name: public, namespace: infra}]
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: jwt
  namespace: infra
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: Gateway, name: public}
  jwt: {}
---
apiVersion: example.com/v1
kind: HTTPRoute
metadata:
  name: not-gateway-api
`)
	x := buildIndex(objs)
	if len(x.routes) != 1 || !x.gateways["infra/public"] || len(x.envoy) != 1 {
		t.Fatalf("routes=%d gateways=%v envoy=%d", len(x.routes), x.gateways, len(x.envoy))
	}
}
