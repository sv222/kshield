package check

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	ctr0Path  = podSpecPath + "/containers/0"
	init0Path = podSpecPath + "/initContainers/0"
)

type wlCase struct {
	name  string
	id    string
	spec  string
	extra string
	want  []wantFinding
}

func runWLCases(t *testing.T, cases []wlCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, tc.id, deployment(tc.spec)+tc.extra)
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			got := sortedFindings(r.Findings)
			want := slices.Clone(tc.want)
			slices.SortFunc(want, func(a, b wantFinding) int {
				return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.container, b.container))
			})
			if !slices.Equal(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
			for _, f := range r.Findings {
				if f.Object.String() != deployRef || f.Group != "" || f.Strength != Violation || f.Message == "" {
					t.Errorf("bad finding %+v", f)
				}
			}
		})
	}
}

func serviceAccountDoc(namespace, name, automount string) string {
	doc := "---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\n"
	if automount != "" {
		doc += "automountServiceAccountToken: " + automount + "\n"
	}
	return doc
}

func TestReadOnlyRootFilesystem(t *testing.T) {
	const path = "/securityContext/readOnlyRootFilesystem"
	runWLCases(t, []wlCase{
		{name: "unset", id: "KS-WL-008", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "explicit false", id: "KS-WL-008", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      readOnlyRootFilesystem: false
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "security context without the field", id: "KS-WL-008", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      allowPrivilegeEscalation: false
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "true", id: "KS-WL-008", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      readOnlyRootFilesystem: true
`},
		{name: "init container unset and container true", id: "KS-WL-008", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      readOnlyRootFilesystem: true
`, want: []wantFinding{{"setup", init0Path + path}}},
		{name: "both containers", id: "KS-WL-008", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{
			{"setup", init0Path + path},
			{"vllm", ctr0Path + path},
		}},
	})
}

func TestSeccompProfile(t *testing.T) {
	const path = "/securityContext/seccompProfile"
	runWLCases(t, []wlCase{
		{name: "unset", id: "KS-WL-009", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "container unconfined", id: "KS-WL-009", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      seccompProfile:
        type: Unconfined
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "pod unconfined", id: "KS-WL-009", spec: `
securityContext:
  seccompProfile:
    type: Unconfined
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "container unconfined over pod RuntimeDefault", id: "KS-WL-009", spec: `
securityContext:
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      seccompProfile:
        type: Unconfined
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "container RuntimeDefault over pod unconfined", id: "KS-WL-009", spec: `
securityContext:
  seccompProfile:
    type: Unconfined
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      seccompProfile:
        type: RuntimeDefault
`},
		{name: "pod RuntimeDefault covers every container", id: "KS-WL-009", spec: `
securityContext:
  seccompProfile:
    type: RuntimeDefault
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`},
		{name: "container Localhost", id: "KS-WL-009", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/vllm.json
`},
		{name: "pod Localhost", id: "KS-WL-009", spec: `
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/vllm.json
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`},
		{name: "init container unset and pod unset", id: "KS-WL-009", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      seccompProfile:
        type: RuntimeDefault
`, want: []wantFinding{{"setup", init0Path + path}}},
	})
}

func TestAutomountServiceAccountToken(t *testing.T) {
	const path = podSpecPath + "/automountServiceAccountToken"
	const container = `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`
	finding := []wantFinding{{"", path}}
	runWLCases(t, []wlCase{
		{name: "unset and no service account in the input", id: "KS-WL-010", spec: container, want: finding},
		{name: "pod true", id: "KS-WL-010", spec: "automountServiceAccountToken: true" + container, want: finding},
		{name: "pod true wins over service account false", id: "KS-WL-010", spec: "automountServiceAccountToken: true" + container,
			extra: serviceAccountDoc("ai", "default", "false"), want: finding},
		{name: "pod false", id: "KS-WL-010", spec: "automountServiceAccountToken: false" + container},
		{name: "pod false wins over service account true", id: "KS-WL-010", spec: "automountServiceAccountToken: false" + container,
			extra: serviceAccountDoc("ai", "default", "true")},
		{name: "unset and default service account false", id: "KS-WL-010", spec: container,
			extra: serviceAccountDoc("ai", "default", "false")},
		{name: "unset and named service account false", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "vllm-sa", "false")},
		{name: "unset and deprecated serviceAccount field", id: "KS-WL-010", spec: "serviceAccount: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "vllm-sa", "false")},
		{name: "serviceAccountName wins over deprecated field", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa\nserviceAccount: other" + container,
			extra: serviceAccountDoc("ai", "vllm-sa", "false")},
		{name: "named service account without the field", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "vllm-sa", ""), want: finding},
		{name: "named service account true", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "vllm-sa", "true"), want: finding},
		{name: "named service account in another namespace", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("other", "vllm-sa", "false"), want: finding},
		{name: "service account with another name", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "other", "false"), want: finding},
		{name: "named service account while only default is false", id: "KS-WL-010", spec: "serviceAccountName: vllm-sa" + container,
			extra: serviceAccountDoc("ai", "default", "false"), want: finding},
		{name: "default service account in another namespace", id: "KS-WL-010", spec: container,
			extra: serviceAccountDoc("other", "default", "false"), want: finding},
	})
}

func TestAutomountServiceAccountTokenOnePerWorkload(t *testing.T) {
	r := runWL(t, "KS-WL-010", deployment(`
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
  - name: sidecar
    image: busybox:1.36
`))
	if len(r.Findings) != 1 || r.Findings[0].Container != "" {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestAutomountServiceAccountTokenIgnoresOtherKinds(t *testing.T) {
	cases := map[string]string{
		"apiVersion": "---\napiVersion: example.io/v1\nkind: ServiceAccount\nmetadata:\n  name: default\n  namespace: ai\nautomountServiceAccountToken: false\n",
		"kind":       "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: default\n  namespace: ai\nautomountServiceAccountToken: false\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			r := runWL(t, "KS-WL-010", deployment(`
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`)+extra)
			if len(r.Findings) != 1 {
				t.Fatalf("got %+v", r.Findings)
			}
		})
	}
}

func TestSecretEnv(t *testing.T) {
	runWLCases(t, []wlCase{
		{name: "hf token", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: HF_TOKEN
        value: hf_dummy
`, want: []wantFinding{{"vllm", ctr0Path + "/env/0/value"}}},
		{name: "one finding per variable with its own index", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: HF_HOME
        value: /models
      - name: HF_TOKEN
        value: hf_dummy
      - name: LOG_LEVEL
        value: INFO
      - name: OPENAI_API_KEY
        value: sk-dummy
`, want: []wantFinding{
			{"vllm", ctr0Path + "/env/1/value"},
			{"vllm", ctr0Path + "/env/3/value"},
		}},
		{name: "init container", id: "KS-WL-011", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
    env:
      - name: REGISTRY_PASSWORD
        value: dummy
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"setup", init0Path + "/env/0/value"}}},
		{name: "valueFrom secret", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: HF_TOKEN
        valueFrom:
          secretKeyRef:
            name: hf
            key: token
`},
		{name: "empty value", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: HF_TOKEN
        value: ""
      - name: HF_SECRET
`},
		{name: "non secret name", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: MODEL_NAME
        value: facebook/opt-125m
`},
	})
}

func TestSecretEnvNames(t *testing.T) {
	const literal = "dummy"
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"HF_TOKEN", literal, true},
		{"hf_token", literal, true},
		{"HUGGING_FACE_HUB_TOKEN", literal, true},
		{"GITHUB_TOKEN", literal, true},
		{"TOKEN", literal, true},
		{"DB_SECRET", literal, true},
		{"DB_SECRETS", literal, true},
		{"AWS_SECRET_ACCESS_KEY", literal, true},
		{"CLIENT_SECRET_VALUE", literal, true},
		{"DB_PASSWORD", literal, true},
		{"DB_PASSWORDS", literal, true},
		{"DB_PASSWD", literal, true},
		{"OPENAI_API_KEY", literal, true},
		{"OPENAI_APIKEY", literal, true},
		{"openai_api_key", literal, true},
		{"AWS_ACCESS_KEY_ID", literal, true},
		{"AWS_ACCESSKEY", literal, true},
		{"SSH_PRIVATE_KEY", literal, true},
		{"PRIVATEKEY", literal, true},
		{"GOOGLE_CREDENTIALS", literal, true},
		{"CREDENTIAL", literal, true},
		{"TOKENIZERS_PARALLELISM", "false", false},
		{"MAX_NUM_BATCHED_TOKENS", "8192", false},
		{"MY_TOKENS", literal, false},
		{"NOTOKEN", literal, false},
		{"MYSECRETKEY", literal, false},
		{"HF_HOME", literal, false},
		{"MODEL_NAME", literal, false},
		{"VLLM_PORT", literal, false},
		{"CUDA_VISIBLE_DEVICES", literal, false},
		{"PUBLIC_KEY", literal, false},
		{"KEY", literal, false},
		{"API", literal, false},
		{"ACCESS", literal, false},
		{"PRIVATE", literal, false},
		{"POSTGRES_PASSWORD_FILE", "/run/secrets/pw", false},
		{"HF_TOKEN_FILE", "/run/secrets/hf", false},
		{"hf_token_file", "/run/secrets/hf", false},
		{"TLS_PRIVATE_KEY_PATH", "/etc/tls/key.pem", false},
		{"tls_private_key_path", "/etc/tls/key.pem", false},
		{"CREDENTIAL_FILE", "/etc/cred.json", false},
		{"FILE_TOKEN", literal, true},
		{"PATH_PASSWORD", literal, true},
		{"HF_TOKEN", "$(HF_TOKEN_FROM_SECRET)", false},
		{"HF_TOKEN", "Bearer $(HF_TOKEN_FROM_SECRET)", false},
		{"DB_PASSWORD", "pa$$word", true},
		{"DB_PASSWORD", "Pa$sw0rd", true},
		{"DB_PASSWORD", "$$(NOT_A_REF)", true},
		{"DB_PASSWORD", "abc$(", true},
		{"DB_PASSWORD", "abc$()", true},
		{"DB_PASSWORD", "x$$$(REAL_REF)", false},
		{"DB_PASSWORD", "$", true},
	}
	for _, tc := range cases {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			spec := fmt.Sprintf(`
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: %s
        value: %q
`, tc.name, tc.value)
			r := runWL(t, "KS-WL-011", deployment(spec))
			if got := len(r.Findings) == 1; got != tc.want {
				t.Fatalf("%s=%s: findings %+v, want match=%v", tc.name, tc.value, r.Findings, tc.want)
			}
		})
	}
}

func TestSecretEnvVLLMAPIKeyFlag(t *testing.T) {
	runWLCases(t, []wlCase{
		{name: "literal in args", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/args"}}},
		{name: "literal equals form", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key=sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/args"}}},
		{name: "literal in command", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["vllm", "serve", "m", "--api-key", "sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/command"}}},
		{name: "literal in a shell string in command", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --api-key sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/command"}}},
		{name: "literal in a shell string in args", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c"]
    args: ["vllm serve m --api-key sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/args"}}},
		{name: "literal on a generic image with the vllm module", id: "KS-WL-011", spec: `
containers:
  - name: server
    image: registry.local/python:3.12
    command: ["python3", "-m", "vllm.entrypoints.openai.api_server"]
    args: ["--api-key", "sk-dummy"]
`, want: []wantFinding{{"server", ctr0Path + "/args"}}},
		{name: "underscore flag in args", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api_key", "sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/args"}}},
		{name: "underscore flag equals form in command", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["vllm", "serve", "m", "--api_key=sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/command"}}},
		{name: "underscore flag in a shell string in command", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --api_key sk-dummy"]
`, want: []wantFinding{{"vllm", ctr0Path + "/command"}}},
		{name: "underscore flag from a variable", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api_key", "$(KEY)"]
`},
		{name: "flag twice gives one finding", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", "a", "--api-key", "b"]
`, want: []wantFinding{{"vllm", ctr0Path + "/args"}}},
		{name: "kubernetes variable", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(VLLM_API_KEY)"]
    env:
      - name: VLLM_API_KEY
        valueFrom:
          secretKeyRef:
            name: vllm
            key: key
`},
		{name: "shell variable", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --api-key $VLLM_API_KEY"]
`},
		{name: "empty value", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", ""]
`},
		{name: "no flag", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`},
		{name: "flag on a container that does not run vllm", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
  - name: sidecar
    image: busybox:1.36
    args: ["--api-key", "sk-dummy"]
`},
		{name: "init container", id: "KS-WL-011", spec: `
initContainers:
  - name: warmup
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", "sk-dummy"]
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m"]
`, want: []wantFinding{{"warmup", init0Path + "/args"}}},
		{name: "flag and env together", id: "KS-WL-011", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "sk-dummy"]
    env:
      - name: HF_TOKEN
        value: hf_dummy
`, want: []wantFinding{
			{"vllm", ctr0Path + "/args"},
			{"vllm", ctr0Path + "/env/0/value"},
		}},
	})
}

func TestSecretEnvVLLMAPIKeyFlagMessageDoesNotLeakValue(t *testing.T) {
	r := runWL(t, "KS-WL-011", deployment(`
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--api-key", "sk_super_secret_value"]
`))
	if len(r.Findings) != 1 {
		t.Fatalf("got %+v", r.Findings)
	}
	m := r.Findings[0].Message
	if strings.Contains(m, "sk_super_secret_value") || !strings.Contains(m, "--api-key") {
		t.Errorf("message %q", m)
	}
}

func TestSecretEnvMessageDoesNotLeakValue(t *testing.T) {
	r := runWL(t, "KS-WL-011", deployment(`
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: HF_TOKEN
        value: hf_super_secret_value
`))
	if len(r.Findings) != 1 {
		t.Fatalf("got %+v", r.Findings)
	}
	m := r.Findings[0].Message
	if strings.Contains(m, "hf_super_secret_value") || !strings.Contains(m, "HF_TOKEN") {
		t.Errorf("message %q", m)
	}
}

func TestImageDigest(t *testing.T) {
	const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	runWLCases(t, []wlCase{
		{name: "tag", id: "KS-WL-012", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"vllm", ctr0Path + "/image"}}},
		{name: "no tag", id: "KS-WL-012", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai
`, want: []wantFinding{{"vllm", ctr0Path + "/image"}}},
		{name: "other digest algorithm", id: "KS-WL-012", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai@sha512:abcdef
`, want: []wantFinding{{"vllm", ctr0Path + "/image"}}},
		{name: "digest only", id: "KS-WL-012", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai` + digest + `
`},
		{name: "tag and digest", id: "KS-WL-012", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0` + digest + `
`},
		{name: "init container with tag", id: "KS-WL-012", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai` + digest + `
`, want: []wantFinding{{"setup", init0Path + "/image"}}},
	})
}

func TestMemoryLimit(t *testing.T) {
	const path = "/resources/limits/memory"
	runWLCases(t, []wlCase{
		{name: "no resources", id: "KS-WL-013", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "cpu limit only", id: "KS-WL-013", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    resources:
      limits:
        cpu: "8"
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "memory request only", id: "KS-WL-013", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    resources:
      requests:
        memory: 16Gi
`, want: []wantFinding{{"vllm", ctr0Path + path}}},
		{name: "memory limit", id: "KS-WL-013", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    resources:
      limits:
        memory: 32Gi
`},
		{name: "init container without limit", id: "KS-WL-013", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    resources:
      limits:
        memory: 32Gi
`, want: []wantFinding{{"setup", init0Path + path}}},
	})
}

func TestGPUAccess(t *testing.T) {
	runWLCases(t, []wlCase{
		{name: "hostPath nvidia0", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: data
    emptyDir: {}
  - name: gpu
    hostPath:
      path: /dev/nvidia0
`, want: []wantFinding{{"", podSpecPath + "/volumes/1"}}},
		{name: "hostPath nvidiactl nvidia-uvm and nvidia-caps", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: ctl
    hostPath:
      path: /dev/nvidiactl
  - name: uvm
    hostPath:
      path: /dev/nvidia-uvm
  - name: caps
    hostPath:
      path: /dev/nvidia-caps/nvidia-cap1
`, want: []wantFinding{
			{"", podSpecPath + "/volumes/0"},
			{"", podSpecPath + "/volumes/1"},
			{"", podSpecPath + "/volumes/2"},
		}},
		{name: "hostPath cleaned into nvidia", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: a
    hostPath:
      path: /dev//nvidia0/
  - name: b
    hostPath:
      path: /dev/shm/../nvidia1
`, want: []wantFinding{
			{"", podSpecPath + "/volumes/0"},
			{"", podSpecPath + "/volumes/1"},
		}},
		{name: "other hostPaths", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: dev
    hostPath:
      path: /dev
  - name: shm
    hostPath:
      path: /dev/shm
  - name: nvme
    hostPath:
      path: /dev/nvme0
  - name: nested
    hostPath:
      path: /data/dev/nvidia0
  - name: escaped
    hostPath:
      path: /dev/nvidia0/..
  - name: relative
    hostPath:
      path: dev/nvidia0
`},
		{name: "visible devices all without limit", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: LOG_LEVEL
        value: INFO
      - name: NVIDIA_VISIBLE_DEVICES
        value: all
`, want: []wantFinding{{"vllm", ctr0Path + "/env/1"}}},
		{name: "visible devices index list without limit", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: "0,1"
`, want: []wantFinding{{"vllm", ctr0Path + "/env/0"}}},
		{name: "visible devices in init container", id: "KS-WL-014", spec: `
initContainers:
  - name: setup
    image: busybox:1.36
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: all
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, want: []wantFinding{{"setup", init0Path + "/env/0"}}},
		{name: "visible devices all with gpu limit", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: all
    resources:
      limits:
        nvidia.com/gpu: 1
`},
		{name: "gpu limit on another container only", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    resources:
      limits:
        nvidia.com/gpu: 1
  - name: sidecar
    image: busybox:1.36
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: all
`, want: []wantFinding{{"sidecar", podSpecPath + "/containers/1/env/0"}}},
		{name: "visible devices void and none", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: void
  - name: sidecar
    image: busybox:1.36
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: none
`},
		{name: "visible devices empty and from secret", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: ""
  - name: sidecar
    image: busybox:1.36
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        valueFrom:
          configMapKeyRef:
            name: gpu
            key: devices
`},
		{name: "other env name", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: CUDA_VISIBLE_DEVICES
        value: all
`},
		{name: "hostPath and env together", id: "KS-WL-014", spec: `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    env:
      - name: NVIDIA_VISIBLE_DEVICES
        value: all
volumes:
  - name: gpu
    hostPath:
      path: /dev/nvidiactl
`, want: []wantFinding{
			{"", podSpecPath + "/volumes/0"},
			{"vllm", ctr0Path + "/env/0"},
		}},
	})
}

func TestWorkloadChecks2Applicability(t *testing.T) {
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
          env:
            - name: API_TOKEN
              value: dummy
            - name: NVIDIA_VISIBLE_DEVICES
              value: all
      volumes:
        - name: gpu
          hostPath:
            path: /dev/nvidia0
`
	hardened := deployment(`
automountServiceAccountToken: false
securityContext:
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: vllm
    image: vllm/vllm-openai@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    securityContext:
      readOnlyRootFilesystem: true
    env:
      - name: HF_TOKEN
        valueFrom:
          secretKeyRef:
            name: hf
            key: token
    resources:
      limits:
        memory: 32Gi
        nvidia.com/gpu: 1
`)
	for _, id := range []string{"KS-WL-008", "KS-WL-009", "KS-WL-010", "KS-WL-011", "KS-WL-012", "KS-WL-013", "KS-WL-014"} {
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
				t.Errorf("hardened AI workload: %+v", r)
			}
		})
	}
}

func TestWorkloadChecks2Registered(t *testing.T) {
	want := []struct {
		id    string
		title string
		fix   Fix
		tier  Tier
	}{
		{"KS-WL-008", "Root filesystem writable", FixPatch, Both},
		{"KS-WL-009", "No seccompProfile: RuntimeDefault", FixPatch, Both},
		{"KS-WL-010", "Service account token auto-mounted", FixPatch, Both},
		{"KS-WL-011", "Secret values in plain env (HF_TOKEN, API keys)", FixManual, Manifest},
		{"KS-WL-012", "Image not pinned by digest", FixManual, Manifest},
		{"KS-WL-013", "No memory limit on AI workload", FixManual, Manifest},
		{"KS-WL-014", "GPU access via hostPath /dev/nvidia* or privileged, not device plugin", FixManual, Both},
	}
	all := All()
	const first = 7
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
