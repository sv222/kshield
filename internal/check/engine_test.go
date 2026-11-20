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
