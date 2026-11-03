package check

import (
	"cmp"
	"slices"
	"strings"
	"testing"
)

type aiWant struct {
	container string
	path      string
	strength  Strength
}

type aiCase struct {
	name  string
	id    string
	spec  string
	extra string
	want  []aiWant
}

func vllmPod(args string) string {
	return "containers:\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n    args: [" + args + "]\n"
}

func runAICases(t *testing.T, cases []aiCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, tc.id, deployment(tc.spec)+tc.extra)
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			var got []aiWant
			for _, f := range r.Findings {
				got = append(got, aiWant{f.Container, f.Path, f.Strength})
				if f.Object.String() != deployRef || f.Group != "" || f.Message == "" {
					t.Errorf("bad finding %+v", f)
				}
			}
			want := slices.Clone(tc.want)
			byPath := func(a, b aiWant) int {
				return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.container, b.container))
			}
			slices.SortFunc(got, byPath)
			slices.SortFunc(want, byPath)
			if !slices.Equal(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
		})
	}
}

func TestVLLMAPIKey(t *testing.T) {
	const args = ctr0Path + "/args"
	finding := []aiWant{{"vllm", args, Violation}}
	runAICases(t, []aiCase{
		{name: "no key", id: "KS-AI-001", spec: vllmPod(`"--model", "m"`), want: finding},
		{name: "no args at all", id: "KS-AI-001", spec: "containers:\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n", want: finding},
		{name: "literal flag", id: "KS-AI-001", spec: vllmPod(`"--model", "m", "--api-key", "dummy"`)},
		{name: "flag from a variable", id: "KS-AI-001", spec: vllmPod(`"--model", "m", "--api-key", "$(KEY)"`) + `    env:
      - name: KEY
        valueFrom:
          secretKeyRef:
            name: vllm
            key: key
`},
		{name: "equals flag", id: "KS-AI-001", spec: vllmPod(`"--model", "m", "--api-key=$(KEY)"`)},
		{name: "empty flag", id: "KS-AI-001", spec: vllmPod(`"--model", "m", "--api-key", ""`), want: finding},
		{name: "env from a secret", id: "KS-AI-001", spec: vllmPod(`"--model", "m"`) + `    env:
      - name: VLLM_API_KEY
        valueFrom:
          secretKeyRef:
            name: vllm
            key: key
`},
		{name: "env literal", id: "KS-AI-001", spec: vllmPod(`"--model", "m"`) + `    env:
      - name: VLLM_API_KEY
        value: dummy
`},
		{name: "other secret env", id: "KS-AI-001", spec: vllmPod(`"--model", "m"`) + `    env:
      - name: OPENAI_API_KEY
        valueFrom:
          secretKeyRef:
            name: vllm
            key: key
`, want: finding},
		{name: "key inside sh -c", id: "KS-AI-001", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve m --api-key $KEY"]
`},
		{name: "no key inside sh -c", id: "KS-AI-001", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve m"]
`, want: finding},
		{name: "module without key", id: "KS-AI-001", spec: `
containers:
  - name: server
    image: registry.local/python:3.12
    command: ["python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "m"]
`, want: []aiWant{{"server", ctr0Path + "/args", Violation}}},
		{name: "init container without key is skipped", id: "KS-AI-001", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
`},
		{name: "init container without key and container without key", id: "KS-AI-001", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, want: finding},
		{name: "vllm only in an init container", id: "KS-AI-001", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
containers:
  - name: sidecar
    image: busybox:1.36
`},
		{name: "underscore flag counts as the key", id: "KS-AI-001", spec: vllmPod(`"--model", "m", "--api_key", "$(KEY)"`)},
		{name: "no key inside sh -c in command", id: "KS-AI-001", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m"]
`, want: finding},
		{name: "two vllm containers", id: "KS-AI-001", spec: `
containers:
  - name: a
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
  - name: b
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
`, want: []aiWant{{"a", ctr0Path + "/args", Violation}}},
		{name: "non vllm container is ignored", id: "KS-AI-001", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
  - name: sidecar
    image: busybox:1.36
`},
	})
}

func TestVLLMTrustRemoteCode(t *testing.T) {
	const args = ctr0Path + "/args"
	finding := []aiWant{{"vllm", args, Violation}}
	runAICases(t, []aiCase{
		{name: "flag", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust-remote-code"`), want: finding},
		{name: "equals true", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust-remote-code=true"`), want: finding},
		{name: "equals false", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust-remote-code=false"`)},
		{name: "no flag", id: "KS-AI-002", spec: vllmPod(`"--model", "m"`)},
		{name: "no-trust after trust", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust-remote-code", "--no-trust-remote-code"`)},
		{name: "trust after no-trust", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--no-trust-remote-code", "--trust-remote-code"`), want: finding},
		{name: "with safetensors", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--load-format", "safetensors", "--trust-remote-code"`), want: finding},
		{name: "underscore flag", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust_remote_code"`), want: finding},
		{name: "underscore flag equals true", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust_remote_code=true"`), want: finding},
		{name: "underscore no-trust after trust", id: "KS-AI-002", spec: vllmPod(`"--model", "m", "--trust-remote-code", "--no_trust_remote_code"`)},
		{name: "inside sh -c in command", id: "KS-AI-002", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --trust-remote-code"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Violation}}},
		{name: "inside sh -c in args", id: "KS-AI-002", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve m --trust-remote-code"]
`, want: finding},
		{name: "underscore inside sh -c in command", id: "KS-AI-002", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --trust_remote_code"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Violation}}},
		{name: "flag in command", id: "KS-AI-002", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["vllm", "serve", "m", "--trust-remote-code"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Violation}}},
		{name: "init container is skipped", id: "KS-AI-002", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--trust-remote-code"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`},
	})
}

func TestVLLMPickleLoad(t *testing.T) {
	const args = ctr0Path + "/args"
	fail := []aiWant{{"vllm", args, Violation}}
	warn := []aiWant{{"vllm", args, Suspect}}
	var cases []aiCase
	add := func(name, argList string, want []aiWant) {
		cases = append(cases, aiCase{name: name, id: "KS-AI-003", spec: vllmPod(argList), want: want})
	}
	add("safetensors", `"--model", "meta-llama/Llama-3.1-8B-Instruct", "--load-format", "safetensors"`, nil)
	add("safetensors equals form", `"--model", "m", "--load-format=safetensors"`, nil)
	add("safetensors upper case", `"--model", "m", "--load-format", "SafeTensors"`, nil)
	add("safetensors wins over a bin path", `"--model", "/models/pytorch_model.bin", "--load-format", "safetensors"`, nil)
	add("pt", `"--model", "m", "--load-format", "pt"`, fail)
	add("pt equals form", `"--model", "m", "--load-format=pt"`, fail)
	add("pt upper case", `"--model", "m", "--load-format", "PT"`, fail)
	add("npcache", `"--model", "m", "--load-format", "npcache"`, fail)
	add("pt wins over a safe looking model", `"--model", "m.safetensors", "--load-format", "pt"`, fail)
	add("last flag wins to pt", `"--model", "m", "--load-format", "safetensors", "--load-format", "pt"`, fail)
	add("last flag wins to safetensors", `"--model", "m", "--load-format", "pt", "--load-format", "safetensors"`, nil)
	add("auto with bin path", `"--model", "/models/llama/pytorch_model.bin", "--load-format", "auto"`, fail)
	add("unset with bin path", `"--model", "/models/llama/pytorch_model.bin"`, fail)
	add("unset with pt path", `"--model", "/models/llama.pt"`, fail)
	add("unset with pth path", `"--model", "/models/llama.pth"`, fail)
	add("unset with pkl path", `"--model", "/models/llama.pkl"`, fail)
	add("unset with ckpt path", `"--model", "/models/llama.ckpt"`, fail)
	add("unset with upper case extension", `"--model", "/models/Llama.BIN"`, fail)
	add("unset with mixed case extension", `"--model", "/models/llama.Pt"`, fail)
	add("unset with trailing slash", `"--model", "/models/llama.bin/"`, fail)
	add("positional bin path", `"/models/llama.bin"`, fail)
	add("hf with bin path", `"--model", "/models/llama.bin", "--load-format", "hf"`, fail)
	add("hf with directory", `"--model", "/models/llama", "--load-format", "hf"`, warn)
	add("auto with directory", `"--model", "/models/llama-3.1-8b", "--load-format", "auto"`, warn)
	add("auto upper case with directory", `"--model", "/models/llama", "--load-format", "AUTO"`, warn)
	add("unset with hub id", `"--model", "meta-llama/Llama-3.1-8B-Instruct"`, warn)
	add("positional hub id", `"meta-llama/Llama-3.1-8B-Instruct"`, warn)
	add("unset without a model", ``, warn)
	add("safetensors path with unset format", `"--model", "/models/llama.safetensors"`, warn)
	add("path that only contains bin", `"--model", "/models/bin/llama"`, warn)
	add("gguf", `"--model", "/models/llama.gguf", "--load-format", "gguf"`, warn)
	add("gguf with a bin path", `"--model", "/models/llama.bin", "--load-format", "gguf"`, warn)
	add("bitsandbytes", `"--model", "m", "--load-format", "bitsandbytes"`, warn)
	add("tensorizer", `"--model", "m", "--load-format", "tensorizer"`, warn)
	add("runai streamer", `"--model", "m", "--load-format", "runai_streamer"`, warn)
	add("dummy", `"--model", "m", "--load-format", "dummy"`, warn)
	add("fastsafetensors", `"--model", "m", "--load-format", "fastsafetensors"`, nil)
	add("instanttensor", `"--model", "m", "--load-format", "instanttensor"`, nil)
	add("mistral", `"--model", "m", "--load-format", "mistral"`, nil)
	add("mistral upper case with a bin path", `"--model", "/models/llama.bin", "--load-format", "MISTRAL"`, nil)
	add("sharded state", `"--model", "m", "--load-format", "sharded_state"`, warn)
	add("underscore flag pt", `"--model", "m", "--load_format", "pt"`, fail)
	add("underscore flag pt equals form", `"--model", "m", "--load_format=pt"`, fail)
	add("underscore flag safetensors", `"--model", "m", "--load_format", "safetensors"`, nil)
	add("underscore flag dynamic", `"--model", "m", "--load_format", "$FMT"`, warn)
	add("dynamic variable", `"--model", "m", "--load-format", "$FMT"`, warn)
	add("dynamic with a bin path", `"--model", "/models/llama.bin", "--load-format", "$FMT"`, warn)
	add("unresolved kubernetes variable", `"--model", "m", "--load-format", "$(LOAD_FMT)"`, warn)
	add("config file only", `"--config", "/etc/vllm/config.yaml"`, warn)
	add("config file equals form", `"--config=/etc/vllm/config.yaml"`, warn)
	add("config file with a bin path", `"--config", "/etc/vllm/config.yaml", "--model", "/models/llama.bin"`, fail)
	add("config file with safetensors", `"--config", "/etc/vllm/config.yaml", "--load-format", "safetensors"`, nil)
	cases = append(cases,
		aiCase{name: "inside sh -c", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve meta-llama/Llama-3.1-8B-Instruct --load-format pt"]
`, want: fail},
		aiCase{name: "inside sh -c with exec and quotes", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["bash", "-c", "set -e; exec vllm serve m --load-format 'pt'"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Violation}}},
		aiCase{name: "inside sh -c in command with a dynamic format", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --load-format $FMT"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Suspect}}},
		aiCase{name: "inside sh -c in command with the format unset", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve /models/llama.bin"]
`, want: fail},
		aiCase{name: "inside sh -c in command with underscore flag", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --load_format pt"]
`, want: []aiWant{{"vllm", ctr0Path + "/command", Violation}}},
		aiCase{name: "inside sh -c with safetensors", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve m --load-format safetensors"]
`},
		aiCase{name: "through a kubernetes variable", id: "KS-AI-003", spec: vllmPod(`"--model", "m", "--load-format", "$(LOAD_FMT)"`) + `    env:
      - name: LOAD_FMT
        value: pt
`, want: fail},
		aiCase{name: "through a kubernetes variable that is safe", id: "KS-AI-003", spec: vllmPod(`"--model", "m", "--load-format", "$(LOAD_FMT)"`) + `    env:
      - name: LOAD_FMT
        value: safetensors
`},
		aiCase{name: "through a kubernetes variable from a config map", id: "KS-AI-003", spec: vllmPod(`"--model", "m", "--load-format", "$(LOAD_FMT)"`) + `    env:
      - name: LOAD_FMT
        valueFrom:
          configMapKeyRef:
            name: cfg
            key: fmt
`, want: warn},
		aiCase{name: "model through a kubernetes variable", id: "KS-AI-003", spec: vllmPod(`"--model", "$(MODEL)"`) + `    env:
      - name: MODEL
        value: /models/llama.bin
`, want: fail},
		aiCase{name: "module on a generic image", id: "KS-AI-003", spec: `
containers:
  - name: server
    image: registry.local/python:3.12
    command: ["python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "m", "--load-format", "pt"]
`, want: []aiWant{{"server", ctr0Path + "/command", Violation}}},
		aiCase{name: "module on a generic image with the format in args", id: "KS-AI-003", spec: `
containers:
  - name: server
    image: registry.local/python:3.12
    command: ["python3", "-m", "vllm.entrypoints.openai.api_server"]
    args: ["--model", "m", "--load-format", "pt"]
`, want: []aiWant{{"server", ctr0Path + "/args", Violation}}},
		aiCase{name: "serve command with positional model", id: "KS-AI-003", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["vllm", "serve", "/models/llama.bin"]
`, want: fail},
		aiCase{name: "two containers", id: "KS-AI-003", spec: `
containers:
  - name: a
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "pt"]
  - name: b
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "safetensors"]
  - name: c
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, want: []aiWant{{"a", ctr0Path + "/args", Violation}, {"c", podSpecPath + "/containers/2/args", Suspect}}},
		aiCase{name: "init container is skipped", id: "KS-AI-003", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "pt"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "safetensors"]
`},
	)
	runAICases(t, cases)
}

func TestVLLMChecksDoNotLeakFlagValues(t *testing.T) {
	for _, id := range []string{"KS-AI-001", "KS-AI-002", "KS-AI-003"} {
		r := runWL(t, id, deployment(vllmPod(`"--model", "m", "--api-key", "super_secret_key", "--trust-remote-code", "--load-format", "pt"`)))
		for _, f := range r.Findings {
			if strings.Contains(f.Message, "super_secret_key") {
				t.Errorf("%s: message %q", id, f.Message)
			}
		}
	}
}

func TestVLLMExposure(t *testing.T) {
	const sel = "app: vllm"
	noKey := vllmPod(`"--model", "m"`)
	withFlag := vllmPod(`"--model", "m", "--api-key", "$(KEY)"`)
	withEnv := noKey + `    env:
      - name: VLLM_API_KEY
        valueFrom:
          secretKeyRef:
            name: vllm
            key: key
`
	auth := "    nginx.ingress.kubernetes.io/auth-url: https://auth.example.com/check\n"
	cases := []struct {
		name  string
		spec  string
		extra string
		want  []exposedFinding
	}{
		{"nodeport without key", noKey, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"loadbalancer without key", noKey, svcDoc("ai", "svc", "LoadBalancer", sel, "port: 8000"), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"nodeport with flag key", withFlag, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
		{"nodeport with env key", withEnv, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
		{"clusterip without key", noKey, svcDoc("ai", "svc", "ClusterIP", sel, "port: 8000"), nil},
		{"no service", noKey, "", nil},
		{"service for another workload", noKey, svcDoc("ai", "svc", "NodePort", "app: other", "port: 8000"), nil},
		{"service in another namespace", noKey, svcDoc("other", "svc", "NodePort", sel, "port: 8000"), nil},
		{"ingress without auth", noKey, svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")),
			[]exposedFinding{{"Ingress/ai/web", "/spec/rules"}}},
		{"ingress default backend without auth", noKey, svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", defaultBackendSpec("svc")),
			[]exposedFinding{{"Ingress/ai/web", "/spec/defaultBackend"}}},
		{"ingress with auth url", noKey, svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", auth, ruleSpec("svc")), nil},
		{"ingress with auth type", noKey, svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", "    nginx.ingress.kubernetes.io/auth-type: basic\n", ruleSpec("svc")), nil},
		{"ingress and vllm key", withFlag, svcDoc("ai", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), nil},
		{"nodeport and unauthenticated ingress", noKey, svcDoc("ai", "svc", "NodePort", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")),
			[]exposedFinding{{"Ingress/ai/web", "/spec/rules"}, {"Service/ai/svc", "/spec/type"}}},
		{"nodeport and authenticated ingress", noKey, svcDoc("ai", "svc", "NodePort", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", auth, ruleSpec("svc")),
			[]exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"two services", noKey, svcDoc("ai", "a", "NodePort", sel, "port: 80") + svcDoc("ai", "b", "LoadBalancer", sel, "port: 80"),
			[]exposedFinding{{"Service/ai/a", "/spec/type"}, {"Service/ai/b", "/spec/type"}}},
		{"one ingress naming two services", noKey, svcDoc("ai", "a", "ClusterIP", sel, "port: 80") + svcDoc("ai", "b", "ClusterIP", sel, "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("a", "b")), []exposedFinding{{"Ingress/ai/web", "/spec/rules"}}},
		{"one vllm container with key and one without", `
containers:
  - name: a
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
  - name: b
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"all vllm containers with key", `
containers:
  - name: a
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
  - name: b
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
`, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
		{"quoted service port", noKey, svcDoc("ai", "svc", "NodePort", sel, `port: "8000"`), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"quoted service port and target port", noKey, svcDoc("ai", "svc", "LoadBalancer", sel, "port: \"80\"\ntargetPort: \"8000\""), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"quoted service port with a key", withFlag, svcDoc("ai", "svc", "NodePort", sel, `port: "8000"`), nil},
		{"init container without key is skipped", `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
containers:
  - name: sidecar
    image: busybox:1.36
`, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
		{"init container without key and container with key", `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
`, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
		{"init container with key and container without key", `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), []exposedFinding{{"Service/ai/svc", "/spec/type"}}},
		{"underscore key flag", vllmPod(`"--model", "m", "--api_key", "$(KEY)"`), svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", deployment(tc.spec)+tc.extra)
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			var got []exposedFinding
			for _, f := range r.Findings {
				got = append(got, exposedFinding{f.Object.String(), f.Path})
				if f.Container != "" || f.Group != "" || f.Strength != Violation || f.Message == "" {
					t.Errorf("bad finding %+v", f)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

type exposedFinding struct {
	object string
	path   string
}

func TestVLLMExposureOneFindingPerIngress(t *testing.T) {
	second := strings.NewReplacer("name: vllm", "name: vllm-b", "app: vllm", "app: vllm-b").Replace(deployment(vllmPod(`"--model", "m"`)))
	both := ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc-b")+strings.TrimPrefix(defaultBackendSpec("svc-a"), "spec:\n"))
	services := svcDoc("ai", "svc-a", "ClusterIP", "app: vllm", "port: 80") + svcDoc("ai", "svc-b", "ClusterIP", "app: vllm-b", "port: 80")
	cases := map[string]string{
		"default backend workload first": deployment(vllmPod(`"--model", "m"`)) + "---\n" + second + services + both,
		"rules workload first":           second + "---\n" + deployment(vllmPod(`"--model", "m"`)) + services + both,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", doc)
			if len(r.Findings) != 1 || r.Findings[0].Object.String() != "Ingress/ai/web" || r.Findings[0].Path != "/spec/rules" {
				t.Fatalf("got %+v", r.Findings)
			}
		})
	}
}

func TestVLLMExposureTwoWorkloadsOneService(t *testing.T) {
	second := strings.NewReplacer("name: vllm", "name: vllm-b").Replace(deployment(vllmPod(`"--model", "m"`)))
	doc := deployment(vllmPod(`"--model", "m"`)) + "---\n" + second + svcDoc("ai", "svc", "NodePort", "app: vllm", "port: 8000")
	r := runWL(t, "KS-AI-004", doc)
	if len(r.Findings) != 1 || r.Findings[0].Object.String() != "Service/ai/svc" {
		t.Fatalf("got %+v", r.Findings)
	}
}

const kserveDoc = `apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: sklearn
  namespace: ai
spec:
  predictor:
    containers:
      - name: kserve-container
        image: kserve/sklearnserver:v0.15.0
`

const kserveSelector = "serving.kserve.io/inferenceservice: sklearn\n    component: predictor"

func TestVLLMExposureKServe(t *testing.T) {
	const kserveVLLM = `apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: sklearn
  namespace: ai
spec:
  predictor:
    containers:
      - name: kserve-container
        image: vllm/vllm-openai:v0.6.0
        args: ["--model", "m", "--api-key", "$(KEY)"]
`
	auth := "    nginx.ingress.kubernetes.io/auth-url: https://auth.example.com/check\n"
	cases := []struct {
		name string
		doc  string
		want []exposedFinding
	}{
		{"loadbalancer", kserveDoc + svcDoc("ai", "sklearn-lb", "LoadBalancer", kserveSelector, "port: 80"), []exposedFinding{{"Service/ai/sklearn-lb", "/spec/type"}}},
		{"nodeport", kserveDoc + svcDoc("ai", "sklearn-np", "NodePort", kserveSelector, "port: 80"), []exposedFinding{{"Service/ai/sklearn-np", "/spec/type"}}},
		{"clusterip", kserveDoc + svcDoc("ai", "sklearn", "ClusterIP", kserveSelector, "port: 80"), nil},
		{"other component", kserveDoc + svcDoc("ai", "sklearn-lb", "LoadBalancer", "serving.kserve.io/inferenceservice: sklearn\n    component: transformer", "port: 80"), nil},
		{"ingress without auth", kserveDoc + svcDoc("ai", "sklearn", "ClusterIP", kserveSelector, "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("sklearn")), []exposedFinding{{"Ingress/ai/web", "/spec/rules"}}},
		{"ingress with auth", kserveDoc + svcDoc("ai", "sklearn", "ClusterIP", kserveSelector, "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", auth, ruleSpec("sklearn")), nil},
		{"vllm container with key", kserveVLLM + svcDoc("ai", "sklearn-lb", "LoadBalancer", kserveSelector, "port: 80"), nil},
		{"vllm container without key", strings.Replace(kserveVLLM, `, "--api-key", "$(KEY)"`, "", 1) + svcDoc("ai", "sklearn-lb", "LoadBalancer", kserveSelector, "port: 80"),
			[]exposedFinding{{"Service/ai/sklearn-lb", "/spec/type"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, "KS-AI-004", tc.doc)
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			var got []exposedFinding
			for _, f := range r.Findings {
				got = append(got, exposedFinding{f.Object.String(), f.Path})
				if f.Container != "" || f.Group != "" || f.Strength != Violation {
					t.Errorf("bad finding %+v", f)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestVLLMExposureIgnoresOtherStacks(t *testing.T) {
	doc := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama
  namespace: ai
spec:
  selector:
    matchLabels:
      app: ollama
  template:
    metadata:
      labels:
        app: ollama
    spec:
      containers:
        - name: ollama
          image: ollama/ollama:0.5.0
` + svcDoc("ai", "svc", "LoadBalancer", "app: ollama", "port: 11434")
	r := runWL(t, "KS-AI-004", doc)
	if !r.Applicable || len(r.Findings) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestVLLMChecksApplicability(t *testing.T) {
	generic := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: ai
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
          args: ["--trust-remote-code", "--load-format", "pt"]
` + svcDoc("ai", "svc", "NodePort", "app: web", "port: 80")
	hardened := deployment(vllmPod(`"--model", "m", "--load-format", "safetensors", "--api-key", "$(KEY)"`)) + svcDoc("ai", "svc", "NodePort", "app: vllm", "port: 8000")
	for _, id := range []string{"KS-AI-001", "KS-AI-002", "KS-AI-003", "KS-AI-004"} {
		t.Run(id, func(t *testing.T) {
			c, ok := ByID(id)
			if !ok {
				t.Fatalf("%s is not registered", id)
			}
			if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
				t.Errorf("empty input: %+v", r)
			}
			if r := runWL(t, id, generic); r.Applicable || len(r.Findings) != 0 {
				t.Errorf("generic workload only: %+v", r)
			}
			if r := runWL(t, id, hardened); !r.Applicable || len(r.Findings) != 0 {
				t.Errorf("hardened vLLM workload: %+v", r)
			}
		})
	}
}

func TestVLLMChecksRegistered(t *testing.T) {
	want := []struct {
		id    string
		title string
		fix   Fix
		tier  Tier
	}{
		{"KS-AI-001", "vLLM API without auth (--api-key / VLLM_API_KEY unset)", FixManual, Manifest},
		{"KS-AI-002", "vLLM --trust-remote-code set", FixPatch, Manifest},
		{"KS-AI-003", "Model load may use pickle", FixPatch, Manifest},
		{"KS-AI-004", "Inference API exposed outside cluster (Service LoadBalancer/NodePort, Ingress) without auth", FixManual, Both},
	}
	all := All()
	const first = 14
	if len(all) < first+len(want) {
		t.Fatalf("catalog has %d checks", len(all))
	}
	for i, w := range want {
		c := all[first+i]
		if c.ID != w.id || c.Title != w.title || c.Fix != w.fix || c.Tier != w.tier {
			t.Errorf("catalog[%d] = %s %q fix=%s tier=%d, want %s %q fix=%s tier=%d", first+i, c.ID, c.Title, c.Fix, c.Tier, w.id, w.title, w.fix, w.tier)
		}
	}
}
