package check

import (
	"strings"
	"testing"
)

type engineCase struct {
	name     string
	spec     string
	findings []wantFinding
	strength []Strength
}

func runEngineCases(t *testing.T, id string, cases []engineCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, id, deployment(c.spec))
			if !r.Applicable {
				t.Fatalf("not applicable: %+v", r)
			}
			got := sortedFindings(r.Findings)
			if len(got) != len(c.findings) {
				t.Fatalf("findings = %+v (%v), want %+v", got, r.Findings, c.findings)
			}
			for i, w := range c.findings {
				if got[i] != w {
					t.Errorf("finding %d = %+v, want %+v", i, got[i], w)
				}
			}
			for i, f := range r.Findings {
				want := Violation
				if i < len(c.strength) {
					want = c.strength[i]
				}
				if f.Strength != want {
					t.Errorf("finding %d strength = %d, want %d: %s", i, f.Strength, want, f.Message)
				}
			}
		})
	}
}

func TestDebugFlags(t *testing.T) {
	const ctr0 = podSpecPath + "/containers/0"
	runEngineCases(t, "KS-AI-011", []engineCase{
		{"vllm debug arg", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--debug"]
`, []wantFinding{{"vllm", ctr0 + "/args"}}, nil},
		{"allow-http in a command", `
containers:
  - name: tgi
    image: ghcr.io/huggingface/text-generation-inference:3
    command: ["text-generation-launcher", "--allow-http"]
`, []wantFinding{{"tgi", ctr0 + "/command"}}, nil},
		{"debug with equals true", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--debug=true"]
`, []wantFinding{{"vllm", ctr0 + "/args"}}, nil},
		{"debug with equals false", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--debug=false"]
`, nil, nil},
		{"debug in the engine command of a script", `
containers:
  - name: triton
    image: registry.example.com/serving/runtime:1
    command: ["sh", "-c", "exec tritonserver --model-repository=/m --debug"]
`, []wantFinding{{"triton", ctr0 + "/command"}}, nil},
		{"debug in a sibling command is a guess", `
containers:
  - name: sglang
    image: lmsysorg/sglang:v0.4.6
    command: ["sh", "-c", "pip install x --debug && prepare.sh"]
`, []wantFinding{{"sglang", ctr0 + "/command"}}, []Strength{Suspect}},
		{"ollama debug env", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_DEBUG, value: "true"}
`, []wantFinding{{"ollama", ctr0 + "/env/0"}}, nil},
		{"ollama debug env one", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_DEBUG, value: "1"}
`, []wantFinding{{"ollama", ctr0 + "/env/0"}}, nil},
		{"ollama debug env off", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_DEBUG, value: "false"}
`, nil, nil},
		{"ollama debug env from secret", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - name: OLLAMA_DEBUG
        valueFrom: {secretKeyRef: {name: s, key: k}}
`, nil, nil},
		{"ollama origins wildcard", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_ORIGINS, value: "https://a.example.com, *"}
`, []wantFinding{{"ollama", ctr0 + "/env/0"}}, nil},
		{"ollama origins narrow", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_ORIGINS, value: "https://a.example.com,https://*.example.com"}
`, nil, nil},
		{"last env value wins", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
    env:
      - {name: OLLAMA_DEBUG, value: "true"}
      - {name: OLLAMA_DEBUG, value: "false"}
`, nil, nil},
		{"non engine container is not checked", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
  - name: sidecar
    image: registry.example.com/platform/proxy:1
    args: ["--debug"]
`, nil, nil},
		{"init container is not checked", `
initContainers:
  - name: init
    image: vllm/vllm-openai:v0.6.0
    args: ["--debug"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, nil, nil},
	})
}

func TestDebugFlagsOptedInCustomEngine(t *testing.T) {
	doc := strings.Replace(deployment(`
containers:
  - name: app
    image: registry.example.com/platform/genai-service:1.2
    args: ["--debug"]
`), "  name: vllm\n  namespace: ai\n", "  name: vllm\n  namespace: ai\n  labels:\n    kshield.io/ai: \"true\"\n", 1)
	r := runWL(t, "KS-AI-011", doc)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Suspect || !strings.Contains(r.Findings[0].Message, "guess") {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestDebugFlagsNotApplicable(t *testing.T) {
	c, _ := ByID("KS-AI-011")
	if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("empty input: %+v", r)
	}
	if r := runWL(t, "KS-AI-011", deployment("containers:\n  - {name: web, image: nginx, args: [\"--debug\"]}\n")); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("generic workload: %+v", r)
	}
}

func labelled(doc, labels string) string {
	return strings.Replace(doc, "  name: vllm\n  namespace: ai\n", "  name: vllm\n  namespace: ai\n  labels:\n"+labels, 1)
}

func annotatedTemplate(doc, annotations string) string {
	return strings.Replace(doc, "      labels:\n        app: vllm\n", "      labels:\n        app: vllm\n      annotations:\n"+annotations, 1)
}

func TestEngineAuthFindings(t *testing.T) {
	const ctr0 = podSpecPath + "/containers/0"
	runEngineCases(t, "KS-AI-010", []engineCase{
		{"tgi without auth", `
containers:
  - name: tgi
    image: ghcr.io/huggingface/text-generation-inference:3.3.4
    args: ["--model-id", "m"]
`, []wantFinding{{"tgi", ctr0 + "/args"}}, nil},
		{"triton without auth", `
containers:
  - name: triton
    image: nvcr.io/nvidia/tritonserver:24.05-py3
`, []wantFinding{{"triton", ctr0 + "/args"}}, nil},
		{"ollama without auth", `
containers:
  - name: ollama
    image: ollama/ollama:0.5.0
`, []wantFinding{{"ollama", ctr0 + "/args"}}, nil},
		{"tei with api key flag", `
containers:
  - name: tei
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8
    args: ["--model-id", "m", "--api-key", "$(KEY)"]
`, nil, nil},
		{"tei with api key flag and equals", `
containers:
  - name: tei
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8
    args: ["--model-id", "m", "--api-key=$(KEY)"]
`, nil, nil},
		{"api key flag without a value", `
containers:
  - name: tei
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8
    args: ["--api-key"]
`, []wantFinding{{"tei", ctr0 + "/args"}}, nil},
		{"tei with API_KEY from a secret", `
containers:
  - name: tei
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8
    env:
      - name: API_KEY
        valueFrom: {secretKeyRef: {name: s, key: k}}
`, nil, nil},
		{"tei with an empty API_KEY", `
containers:
  - name: tei
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8
    env:
      - {name: API_KEY, value: ""}
`, []wantFinding{{"tei", ctr0 + "/args"}}, nil},
		{"llama.cpp with LLAMA_API_KEY", `
containers:
  - name: llama
    image: ghcr.io/ggml-org/llama.cpp:server
    env:
      - {name: LLAMA_API_KEY, value: "x"}
`, nil, nil},
		{"llama.cpp with the vllm key name is not evidence", `
containers:
  - name: llama
    image: ghcr.io/ggml-org/llama.cpp:server
    env:
      - {name: VLLM_API_KEY, value: "x"}
`, []wantFinding{{"llama", ctr0 + "/args"}}, nil},
		{"localai with LOCALAI_API_KEY", `
containers:
  - name: localai
    image: quay.io/go-skynet/local-ai:latest
    env:
      - {name: LOCALAI_API_KEY, value: "x"}
`, nil, nil},
		{"vllm container is KS-AI-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, nil, nil},
		{"qdrant and ray are other checks", `
containers:
  - name: qdrant
    image: qdrant/qdrant:v1.12.0
  - name: ray
    image: rayproject/ray:2.9.0
`, nil, nil},
		{"init container is not checked", `
initContainers:
  - name: init
    image: ghcr.io/huggingface/text-generation-inference:3.3.4
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", "x"]
`, nil, nil},
		{"sglang uncertain engine command", `
containers:
  - name: sglang
    image: lmsysorg/sglang:v0.4.6
    command: ["sh", "-c", "a && b"]
`, []wantFinding{{"sglang", ctr0 + "/args"}}, []Strength{Suspect}},
	})
}

const engineSecretDoc = `---
apiVersion: v1
kind: Secret
metadata:
  name: tei-key
  namespace: ai
data:
  API_KEY: c2VjcmV0
`

func TestEngineAuthEnvFrom(t *testing.T) {
	tei := func(secret string) string {
		return deployment("containers:\n  - name: tei\n    image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.8\n    envFrom:\n      - secretRef: {name: " + secret + "}\n")
	}
	cases := []struct {
		name     string
		doc      string
		strength []Strength
	}{
		{"secret in the input holds the key", tei("tei-key") + engineSecretDoc, nil},
		{"secret in the input lacks the key", tei("other") + strings.Replace(strings.Replace(engineSecretDoc, "tei-key", "other", 1), "API_KEY", "OTHER", 1), []Strength{Violation}},
		{"secret not in the input", tei("tei-key"), []Strength{Suspect}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-010", c.doc)
			if len(r.Findings) != len(c.strength) {
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

func TestGatewayAuthDeclared(t *testing.T) {
	tgi := deployment("containers:\n  - name: tgi\n    image: ghcr.io/huggingface/text-generation-inference:3.3.4\n")
	vllm := deployment("containers:\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n    args: [\"--model\", \"m\"]\n")
	cases := []struct {
		name string
		id   string
		doc  string
		want Strength
	}{
		{"tgi without the annotation", "KS-AI-010", tgi, Violation},
		{"tgi object label", "KS-AI-010", labelled(tgi, "    kshield.io/gateway-auth: \"true\"\n"), Declared},
		{"tgi template annotation", "KS-AI-010", annotatedTemplate(tgi, "        kshield.io/gateway-auth: \"true\"\n"), Declared},
		{"tgi annotation with another value", "KS-AI-010", labelled(tgi, "    kshield.io/gateway-auth: \"false\"\n"), Violation},
		{"vllm without the annotation", "KS-AI-001", vllm, Violation},
		{"vllm object label", "KS-AI-001", labelled(vllm, "    kshield.io/gateway-auth: \"true\"\n"), Declared},
		{"vllm template annotation", "KS-AI-001", annotatedTemplate(vllm, "        kshield.io/gateway-auth: \"true\"\n"), Declared},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runWL(t, c.id, c.doc)
			if len(r.Findings) != 1 || r.Findings[0].Strength != c.want {
				t.Fatalf("findings = %+v, want one with strength %d", r.Findings, c.want)
			}
			if c.want == Declared && !strings.Contains(r.Findings[0].Message, "gateway authentication is declared by kshield.io/gateway-auth") {
				t.Errorf("message = %q", r.Findings[0].Message)
			}
		})
	}
}

func TestEngineAuthOptedInCustomImage(t *testing.T) {
	doc := labelled(deployment("containers:\n  - name: app\n    image: registry.example.com/platform/genai-service:1.2\n"), "    kshield.io/ai: \"true\"\n")
	r := runWL(t, "KS-AI-010", doc)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Suspect || !strings.Contains(r.Findings[0].Message, "guess") {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestEngineAuthNotApplicable(t *testing.T) {
	c, _ := ByID("KS-AI-010")
	if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("empty input: %+v", r)
	}
	if r := runWL(t, "KS-AI-010", deployment("containers:\n  - {name: web, image: nginx}\n")); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("generic workload: %+v", r)
	}
}
