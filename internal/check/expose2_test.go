package check

import (
	"strings"
	"testing"
)

func TestIngressAuthAnnotations(t *testing.T) {
	const sel = "app: vllm"
	cluster := svcDoc("ai", "svc", "ClusterIP", sel, "port: 80")
	spec := vllmPod(`"--model", "m"`)
	cases := []struct {
		name        string
		annotations string
		strength    Strength
		findings    int
	}{
		{"none", "", Violation, 1},
		{"auth-url", "    nginx.ingress.kubernetes.io/auth-url: https://auth\n", Violation, 0},
		{"auth-type", "    nginx.ingress.kubernetes.io/auth-type: basic\n", Violation, 0},
		{"auth-signin", "    nginx.ingress.kubernetes.io/auth-signin: https://auth/start\n", Violation, 0},
		{"auth-secret", "    nginx.ingress.kubernetes.io/auth-secret: users\n", Violation, 0},
		{"oauth2 annotation", "    example.com/oauth2-proxy: enabled\n", Violation, 0},
		{"upper case key", "    Nginx.Ingress.Kubernetes.io/Auth-URL: https://auth\n", Violation, 0},
		{"empty value", "    nginx.ingress.kubernetes.io/auth-signin: \"\"\n", Violation, 1},
		{"unrelated auth word", "    nginx.ingress.kubernetes.io/auth-tls-verify-client: \"on\"\n", Violation, 1},
		{"gateway auth declared", "    kshield.io/gateway-auth: \"true\"\n", Violation, 0},
		{"gateway auth false", "    kshield.io/gateway-auth: \"false\"\n", Violation, 1},
		{"ai-guard annotation is not ours", "    ai.infra.guard/gateway-auth: \"true\"\n", Violation, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", deployment(spec)+cluster+ingressDoc("networking.k8s.io/v1", "ai", "web", c.annotations, ruleSpec("svc")))
			if len(r.Findings) != c.findings {
				t.Fatalf("findings = %+v, want %d", r.Findings, c.findings)
			}
			for _, f := range r.Findings {
				if f.Strength != c.strength || !strings.Contains(f.Message, "auth annotation") {
					t.Errorf("finding = %+v", f)
				}
			}
		})
	}
}

func TestGatewayAuthDeclaredOnExposure(t *testing.T) {
	const sel = "app: vllm"
	vllm := deployment(vllmPod(`"--model", "m"`))
	svc := svcDoc("ai", "svc", "NodePort", sel, "port: 8000")
	cases := []struct {
		name string
		doc  string
		want Strength
	}{
		{"without the annotation", vllm + svc, Violation},
		{"object label", labelled(vllm, "    kshield.io/gateway-auth: \"true\"\n") + svc, Declared},
		{"template annotation", annotatedTemplate(vllm, "        kshield.io/gateway-auth: \"true\"\n") + svc, Declared},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", c.doc)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want {
				t.Fatalf("findings = %+v", r.Findings)
			}
			if c.want == Declared && !strings.Contains(r.Findings[0].Message, "gateway authentication is declared by kshield.io/gateway-auth") {
				t.Errorf("message = %q", r.Findings[0].Message)
			}
		})
	}
}

func TestEngineExposure(t *testing.T) {
	const sel = "app: vllm"
	svc := svcDoc("ai", "svc", "LoadBalancer", sel, "port: 80")
	cases := []struct {
		name     string
		spec     string
		extra    string
		strength []Strength
	}{
		{"tgi without auth", "containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n", svc, []Strength{Violation}},
		{"triton without auth", "containers:\n  - name: triton\n    image: nvcr.io/nvidia/tritonserver:24.05-py3\n", svc, []Strength{Violation}},
		{"tei with a key flag", "containers:\n  - name: tei\n    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8\n    args: [\"--api-key\", \"$(K)\"]\n", svc, nil},
		{"tei with a key env", "containers:\n  - name: tei\n    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8\n    env:\n      - name: API_KEY\n        valueFrom: {secretKeyRef: {name: s, key: k}}\n", svc, nil},
		{"tei with envFrom outside the input", "containers:\n  - name: tei\n    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8\n    envFrom:\n      - secretRef: {name: tei-key}\n", svc, []Strength{Suspect}},
		{"tgi behind clusterip", "containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80"), nil},
		{"tgi behind an authenticated ingress", "containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "    nginx.ingress.kubernetes.io/auth-signin: https://auth\n", ruleSpec("svc")), nil},
		{"tgi behind an open ingress", "containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), []Strength{Violation}},
		{"ollama is KS-AI-007", "containers:\n  - name: ollama\n    image: ollama/ollama:0.5.0\n", svc, nil},
		{"tgi with a vllm sidecar that has a key", "containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n    args: [\"--api-key\", \"$(K)\"]\n", svc, []Strength{Violation}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", deployment(c.spec)+c.extra)
			if !r.Applicable || len(r.Findings) != len(c.strength) {
				t.Fatalf("findings = %+v", r.Findings)
			}
			for i, f := range r.Findings {
				if f.Strength != c.strength[i] {
					t.Errorf("strength = %d, want %d: %s", f.Strength, c.strength[i], f.Message)
				}
			}
		})
	}
}

func TestGatewayAuthDeclaredOnOllamaExposure(t *testing.T) {
	ollama := deployment("containers:\n  - name: ollama\n    image: ollama/ollama:0.5.0\n")
	svc := svcDoc("ai", "svc", "LoadBalancer", "app: vllm", "port: 11434")
	cases := []struct {
		name string
		doc  string
		want Strength
	}{
		{"without the annotation", ollama + svc, Violation},
		{"object label", labelled(ollama, "    kshield.io/gateway-auth: \"true\"\n") + svc, Declared},
		{"template annotation", annotatedTemplate(ollama, "        kshield.io/gateway-auth: \"true\"\n") + svc, Declared},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-007", c.doc)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want {
				t.Fatalf("findings = %+v", r.Findings)
			}
		})
	}
}
