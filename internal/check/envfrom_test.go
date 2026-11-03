package check

import (
	"strings"
	"testing"
)

const (
	secretB64Value = "c3VwZXJzZWNyZXQ="
	secretPlain    = "supersecret"
	nodePortVLLM   = "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: vllm\n  namespace: ai\nspec:\n  type: NodePort\n  selector:\n    app: vllm\n  ports:\n    - port: 8000\n"
	svcRef         = "Service/ai/vllm"
)

func envFromPod(image, envFrom string) string {
	return "containers:\n  - name: vllm\n    image: " + image + "\n    args: [\"--model\", \"m\"]\n    envFrom:\n" + envFrom
}

func envSecretDoc(name, field, key string) string {
	value := secretB64Value
	if field == "stringData" {
		value = secretPlain
	}
	return "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: " + name + "\n  namespace: ai\n" + field + ":\n  " + key + ": " + value + "\n"
}

func envConfigMapDoc(name, key string) string {
	return "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n  namespace: ai\ndata:\n  " + key + ": x\n"
}

const (
	secretRefKeys    = "      - secretRef:\n          name: keys\n"
	configMapRefKeys = "      - configMapRef:\n          name: keys\n"
	prefixedRefKeys  = "      - prefix: VLLM_\n        secretRef:\n          name: keys\n"
)

func TestVLLMAPIKeyFromEnvFrom(t *testing.T) {
	const image = "vllm/vllm-openai:v0.6.0"
	args := ctr0Path + "/args"
	fail := []ai2Want{{deployRef, "", "vllm", args, Violation}}
	warn := []ai2Want{{deployRef, "", "vllm", args, Suspect}}
	runAI2Cases(t, "KS-AI-001", []ai2Case{
		{"secret data key in input", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "VLLM_API_KEY"), nil},
		{"secret stringData key in input", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "stringData", "VLLM_API_KEY"), nil},
		{"configmap key in input", deployment(envFromPod(image, configMapRefKeys)) + envConfigMapDoc("keys", "VLLM_API_KEY"), nil},
		{"prefix plus key", deployment(envFromPod(image, prefixedRefKeys)) + envSecretDoc("keys", "data", "API_KEY"), nil},
		{"secret in input without the key", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "OTHER"), fail},
		{"secret in another namespace", deployment(envFromPod(image, secretRefKeys)) + strings.Replace(envSecretDoc("keys", "data", "VLLM_API_KEY"), "namespace: ai", "namespace: other", 1), warn},
		{"secret not in input", deployment(envFromPod(image, secretRefKeys)), warn},
		{"configmap not in input", deployment(envFromPod(image, configMapRefKeys)), warn},
		{"explicit empty env wins over envFrom", deployment(envFromPod(image, secretRefKeys) + "    env:\n      - name: VLLM_API_KEY\n        value: \"\"\n"), fail},
	})
}

func TestEnvFromMessagesHaveNoValues(t *testing.T) {
	for _, doc := range []string{
		deployment(envFromPod("vllm/vllm-openai:v0.6.0", secretRefKeys)) + envSecretDoc("keys", "data", "OTHER"),
		deployment(envFromPod("vllm/vllm-openai:v0.6.0", secretRefKeys)) + envSecretDoc("keys", "stringData", "OTHER"),
		deployment(envFromPod("vllm/vllm-openai:v0.6.0", secretRefKeys)),
	} {
		r := runWL(t, "KS-AI-001", doc)
		for _, f := range r.Findings {
			if strings.Contains(f.Message, secretB64Value) || strings.Contains(f.Message, secretPlain) {
				t.Errorf("message leaks a value: %q", f.Message)
			}
		}
	}
	r := runWL(t, "KS-AI-001", deployment(envFromPod("vllm/vllm-openai:v0.6.0", secretRefKeys)))
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Message, "Secret keys") {
		t.Errorf("want the missing Secret named, got %+v", r.Findings)
	}
}

func TestExposedVLLMKeyFromEnvFrom(t *testing.T) {
	const image = "vllm/vllm-openai:v0.6.0"
	runAI2Cases(t, "KS-AI-004", []ai2Case{
		{"key from envFrom in input", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "VLLM_API_KEY") + nodePortVLLM, nil},
		{"envFrom not in input", deployment(envFromPod(image, secretRefKeys)) + nodePortVLLM, []ai2Want{{svcRef, "", "", serviceTypePath, Suspect}}},
		{"envFrom in input without the key", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "OTHER") + nodePortVLLM, []ai2Want{{svcRef, "", "", serviceTypePath, Violation}}},
	})
}

func TestQdrantKeyFromEnvFrom(t *testing.T) {
	const image = "qdrant/qdrant:v1.19.2"
	env := ctr0Path + "/env"
	tls := ai2Want{deployRef, "", "vllm", env, Violation}
	runAI2Cases(t, "KS-AI-008", []ai2Case{
		{"key from envFrom in input", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "QDRANT__SERVICE__API_KEY"), []ai2Want{tls}},
		{"envFrom not in input", deployment(envFromPod(image, secretRefKeys)), []ai2Want{{deployRef, "", "vllm", env, Suspect}, tls}},
		{"envFrom in input without the key", deployment(envFromPod(image, secretRefKeys)) + envSecretDoc("keys", "data", "OTHER"), []ai2Want{{deployRef, "", "vllm", env, Violation}, tls}},
		{"explicit env wins over a missing envFrom", deployment(envFromPod(image, secretRefKeys) + "    env:\n      - name: QDRANT__SERVICE__API_KEY\n        value: \"\"\n"), []ai2Want{{deployRef, "", "vllm", env, Violation}, tls}},
	})
}

func opaquePod(args string) string {
	return "containers:\n  - name: vllm\n    image: vllm/vllm-openai:v0.6.0\n    command: [\"/start.sh\"]\n    args: [" + args + "]\n"
}

func TestOpaqueVLLMCommandIsSuspect(t *testing.T) {
	args := ctr0Path + "/args"
	cases := []struct {
		id, spec, extra string
		want            []ai2Want
	}{
		{"KS-AI-001", opaquePod(`"--model", "m"`), "", []ai2Want{{deployRef, "", "vllm", args, Suspect}}},
		{"KS-AI-001", opaquePod(`"--model", "m", "--api-key", "$(KEY)"`), "", nil},
		{"KS-AI-002", opaquePod(`"--model", "m", "--trust-remote-code"`), "", []ai2Want{{deployRef, "", "vllm", args, Suspect}}},
		{"KS-AI-002", opaquePod(`"--model", "m"`), "", nil},
		{"KS-AI-003", opaquePod(`"--model", "m", "--load-format", "pt"`), "", []ai2Want{{deployRef, "", "vllm", args, Suspect}}},
		{"KS-AI-003", opaquePod(`"--model", "m", "--load-format", "safetensors"`), "", nil},
		{"KS-AI-004", opaquePod(`"--model", "m"`), nodePortVLLM, []ai2Want{{svcRef, "", "", serviceTypePath, Suspect}}},
	}
	for _, tc := range cases {
		runAI2Cases(t, tc.id, []ai2Case{{tc.id + " " + tc.spec, deployment(tc.spec) + tc.extra, tc.want}})
	}
	r := runWL(t, "KS-AI-001", deployment(opaquePod(`"--model", "m"`)))
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Message, "not vllm serve") {
		t.Errorf("message must say why it is uncertain: %+v", r.Findings)
	}
}
