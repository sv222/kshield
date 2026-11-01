package check

import (
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

func workloadsOf(t *testing.T, doc string) []model.Workload {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

func vc(words []string) model.Container {
	return model.Container{
		Stack:    model.VLLM,
		Spec:     corev1.Container{Command: words},
		Commands: []model.Command{{Words: words}},
	}
}

func vcEnv(words []string, envs ...corev1.EnvVar) model.Container {
	c := vc(words)
	c.Spec.Env = envs
	return c
}

func vllmImageArgs(args []string) model.Container {
	return model.Container{
		Stack:    model.VLLM,
		Spec:     corev1.Container{Args: args},
		Commands: []model.Command{{Words: args}},
	}
}

func secretEnv(name string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "vllm"},
		Key:                  "key",
	}}}
}

func TestParseVLLM(t *testing.T) {
	generic := model.Container{
		Spec:     corev1.Container{Command: []string{"python3", "app.py", "--api-key", "x"}},
		Commands: []model.Command{{Words: []string{"python3", "app.py", "--api-key", "x"}}},
	}
	wrapperCommand := vllmImageArgs([]string{"--model", "m"})
	wrapperCommand.Spec.Command = []string{"/start.sh"}
	wrapperCommand.Commands = []model.Command{{Words: []string{"/start.sh", "--model", "m"}}}
	moduleOnGeneric := model.Container{Commands: []model.Command{{Words: []string{"python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "m"}}}}
	cases := []struct {
		name string
		c    model.Container
		want VLLMArgs
	}{
		{"serve positional", vc([]string{"vllm", "serve", "/models/q"}), VLLMArgs{Found: true, Model: "/models/q"}},
		{"serve by absolute path", vc([]string{"/usr/local/bin/vllm", "serve", "m"}), VLLMArgs{Found: true, Model: "m"}},
		{"equals form", vc([]string{"vllm", "serve", "m", "--load-format=pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"last wins", vc([]string{"vllm", "serve", "m", "--load-format", "pt", "--load-format", "safetensors"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "safetensors", LoadFormatSet: true}},
		{"python module", vc([]string{"python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "m", "--trust-remote-code"}), VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"python module on a generic container", moduleOnGeneric, VLLMArgs{Found: true, Model: "m"}},
		{"module takes no positional", vc([]string{"python3", "-m", "vllm.entrypoints.openai.api_server", "other"}), VLLMArgs{Found: true}},
		{"model equals form", vc([]string{"vllm", "serve", "--model=m"}), VLLMArgs{Found: true, Model: "m"}},
		{"model flag after positional wins", vc([]string{"vllm", "serve", "a", "--model", "b"}), VLLMArgs{Found: true, Model: "b"}},
		{"no-trust", vc([]string{"vllm", "serve", "m", "--trust-remote-code", "--no-trust-remote-code"}), VLLMArgs{Found: true, Model: "m"}},
		{"trust after no-trust", vc([]string{"vllm", "serve", "m", "--no-trust-remote-code", "--trust-remote-code"}), VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"trust equals true", vc([]string{"vllm", "serve", "m", "--trust-remote-code=true"}), VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"trust equals false", vc([]string{"vllm", "serve", "m", "--trust-remote-code=false"}), VLLMArgs{Found: true, Model: "m"}},
		{"trust equals dynamic", vc([]string{"vllm", "serve", "m", "--trust-remote-code=$TRC"}), VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"underscore trust flag", vc([]string{"vllm", "serve", "m", "--trust_remote_code"}), VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"underscore trust flag equals", vc([]string{"vllm", "serve", "m", "--trust_remote_code=false"}), VLLMArgs{Found: true, Model: "m"}},
		{"underscore no-trust flag", vc([]string{"vllm", "serve", "m", "--trust-remote-code", "--no_trust_remote_code"}), VLLMArgs{Found: true, Model: "m"}},
		{"underscore load format", vc([]string{"vllm", "serve", "m", "--load_format", "pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"underscore load format equals", vc([]string{"vllm", "serve", "m", "--load_format=pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"underscore load format dynamic", vc([]string{"vllm", "serve", "m", "--load_format", "$FMT"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "$FMT", LoadFormatSet: true, LoadFormatDynamic: true}},
		{"underscore api key", vc([]string{"vllm", "serve", "m", "--api_key", "sk-x"}), VLLMArgs{Found: true, Model: "m", APIKey: true, APIKeyLiteral: true}},
		{"underscore api key equals dynamic", vc([]string{"vllm", "serve", "m", "--api_key=$(KEY)"}), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"underscore flags mixed with dashes last wins", vc([]string{"vllm", "serve", "m", "--load-format", "safetensors", "--load_format", "pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"underscore flag on a module", vc([]string{"python3", "-m", "vllm.entrypoints.openai.api_server", "--trust_remote_code", "--api_key", "$K"}), VLLMArgs{Found: true, TrustRemoteCode: true, APIKey: true}},
		{"underscore in a value is kept", vc([]string{"vllm", "serve", "m", "--load-format", "sharded_state"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "sharded_state", LoadFormatSet: true}},
		{"dynamic", vc([]string{"vllm", "serve", "m", "--load-format", "$FMT"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "$FMT", LoadFormatSet: true, LoadFormatDynamic: true}},
		{"dynamic equals", vc([]string{"vllm", "serve", "m", "--load-format=$(FMT)"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "$(FMT)", LoadFormatSet: true, LoadFormatDynamic: true}},
		{"dynamic then static", vc([]string{"vllm", "serve", "m", "--load-format", "$FMT", "--load-format", "pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"api key literal", vc([]string{"vllm", "serve", "m", "--api-key", "s3cr3t"}), VLLMArgs{Found: true, Model: "m", APIKey: true, APIKeyLiteral: true}},
		{"api key equals literal", vc([]string{"vllm", "serve", "m", "--api-key=s3cr3t"}), VLLMArgs{Found: true, Model: "m", APIKey: true, APIKeyLiteral: true}},
		{"api key dynamic", vc([]string{"vllm", "serve", "m", "--api-key", "$(VLLM_API_KEY)"}), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"api key equals dynamic", vc([]string{"vllm", "serve", "m", "--api-key=$KEY"}), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"api key empty", vc([]string{"vllm", "serve", "m", "--api-key", ""}), VLLMArgs{Found: true, Model: "m"}},
		{"api key equals empty", vc([]string{"vllm", "serve", "m", "--api-key="}), VLLMArgs{Found: true, Model: "m"}},
		{"api key last wins", vc([]string{"vllm", "serve", "m", "--api-key", "a", "--api-key", ""}), VLLMArgs{Found: true, Model: "m"}},
		{"api key without value", vc([]string{"vllm", "serve", "m", "--api-key"}), VLLMArgs{Found: true, Model: "m"}},
		{"api key followed by a flag", vc([]string{"vllm", "serve", "m", "--api-key", "--port", "8000"}), VLLMArgs{Found: true, Model: "m"}},
		{"api key env", vcEnv([]string{"vllm", "serve", "m"}, secretEnv("VLLM_API_KEY")), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"api key env literal", vcEnv([]string{"vllm", "serve", "m"}, corev1.EnvVar{Name: "VLLM_API_KEY", Value: "x"}), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"api key env empty", vcEnv([]string{"vllm", "serve", "m"}, corev1.EnvVar{Name: "VLLM_API_KEY"}), VLLMArgs{Found: true, Model: "m"}},
		{"api key env last wins", vcEnv([]string{"vllm", "serve", "m"}, secretEnv("VLLM_API_KEY"), corev1.EnvVar{Name: "VLLM_API_KEY"}), VLLMArgs{Found: true, Model: "m"}},
		{"other env name", vcEnv([]string{"vllm", "serve", "m"}, secretEnv("OPENAI_API_KEY")), VLLMArgs{Found: true, Model: "m"}},
		{"api key env with empty flag", vcEnv([]string{"vllm", "serve", "m", "--api-key", ""}, secretEnv("VLLM_API_KEY")), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"api key env with literal flag", vcEnv([]string{"vllm", "serve", "m", "--api-key", "x"}, secretEnv("VLLM_API_KEY")), VLLMArgs{Found: true, Model: "m", APIKey: true, APIKeyLiteral: true}},
		{"config file", vc([]string{"vllm", "serve", "--config", "/etc/vllm.yaml"}), VLLMArgs{Found: true, ConfigFile: true}},
		{"config file equals", vc([]string{"vllm", "serve", "m", "--config=/etc/vllm.yaml"}), VLLMArgs{Found: true, Model: "m", ConfigFile: true}},
		{"config without value", vc([]string{"vllm", "serve", "m", "--config"}), VLLMArgs{Found: true, Model: "m"}},
		{"first vllm command wins", model.Container{Stack: model.VLLM, Commands: []model.Command{
			{Words: []string{"echo", "start"}},
			{Words: []string{"vllm", "serve", "first"}},
			{Words: []string{"vllm", "serve", "second", "--trust-remote-code"}},
		}}, VLLMArgs{Found: true, Model: "first"}},
		{"unknown flags are skipped", vc([]string{"vllm", "serve", "m", "--port", "8000", "--enforce-eager", "--load-format", "pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"flag value is not a model", vc([]string{"vllm", "serve", "--port", "8000"}), VLLMArgs{Found: true}},
		{"serve without arguments", vc([]string{"vllm", "serve"}), VLLMArgs{Found: true}},
		{"image entrypoint args only", vllmImageArgs([]string{"--model", "m"}), VLLMArgs{Found: true, Model: "m"}},
		{"image entrypoint positional model", vllmImageArgs([]string{"m", "--load-format", "pt"}), VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"image entrypoint with serve word", vllmImageArgs([]string{"serve", "m"}), VLLMArgs{Found: true, Model: "m"}},
		{"image entrypoint without args", vllmImageArgs(nil), VLLMArgs{Found: true}},
		{"image entrypoint with env key", func() model.Container {
			c := vllmImageArgs([]string{"--model", "m"})
			c.Spec.Env = []corev1.EnvVar{secretEnv("VLLM_API_KEY")}
			return c
		}(), VLLMArgs{Found: true, Model: "m", APIKey: true}},
		{"vllm image behind a wrapper command", wrapperCommand, VLLMArgs{Found: true, Model: "m", Opaque: true}},
		{"wrapper command flags are parsed", vc([]string{"/opt/run.sh", "--trust-remote-code", "--api-key", "k", "--load-format", "pt"}), VLLMArgs{Found: true, TrustRemoteCode: true, APIKey: true, APIKeyLiteral: true, LoadFormat: "pt", LoadFormatSet: true, Opaque: true}},
		{"bash script file is opaque", vc([]string{"bash", "/start.sh"}), VLLMArgs{Found: true, Opaque: true}},
		{"shell -c without vllm is not opaque", vc([]string{"sh", "-c", "python serve.py"}), VLLMArgs{Found: true}},
		{"python -m vllm module is not opaque", vc([]string{"python3", "-m", "vllm.scripts", "--model", "m"}), VLLMArgs{Found: true}},
		{"generic container", generic, VLLMArgs{}},
		{"empty container", model.Container{}, VLLMArgs{}},
		{"generic container with vllm env", model.Container{Spec: corev1.Container{Env: []corev1.EnvVar{secretEnv("VLLM_API_KEY")}}}, VLLMArgs{}},
		{"vllm without serve", vc([]string{"vllm", "bench", "--model", "m"}), VLLMArgs{Found: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseVLLM(tc.c); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestNormalizeFlag(t *testing.T) {
	cases := map[string]string{
		"--trust_remote_code":    "--trust-remote-code",
		"--trust-remote-code":    "--trust-remote-code",
		"--a_b.c_d":              "--a-b.c_d",
		"--a.b_c":                "--a.b_c",
		"--a_b_c.":               "--a-b-c.",
		"-x_y":                   "-x_y",
		"plain_word":             "plain_word",
		"--":                     "--",
		"--no_trust_remote_code": "--no-trust-remote-code",
	}
	for in, want := range cases {
		if got := NormalizeFlag(in); got != want {
			t.Errorf("NormalizeFlag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlagField(t *testing.T) {
	cases := []struct {
		name    string
		command []string
		args    []string
		flag    string
		want    string
	}{
		{"in args", nil, []string{"--api-key", "x"}, flagAPIKey, "args"},
		{"in args with equals", nil, []string{"--api-key=x"}, flagAPIKey, "args"},
		{"in command", []string{"vllm", "serve", "--api-key", "x"}, nil, flagAPIKey, "command"},
		{"underscore in args", nil, []string{"--api_key", "x"}, flagAPIKey, "args"},
		{"underscore in command", []string{"vllm", "serve", "--api_key=x"}, nil, flagAPIKey, "command"},
		{"shell string in command", []string{"sh", "-c", "vllm serve m --api-key x"}, nil, flagAPIKey, "command"},
		{"shell string in command with underscore", []string{"sh", "-c", "vllm serve m --api_key x"}, nil, flagAPIKey, "command"},
		{"shell string in command after a quote", []string{"sh", "-c", "vllm serve m --x 'a' \"--api-key\" y"}, nil, flagAPIKey, "command"},
		{"shell string in args", []string{"sh", "-c"}, []string{"vllm serve m --api-key x"}, flagAPIKey, "args"},
		{"in both: the later one wins", []string{"vllm", "serve", "--api-key", "a"}, []string{"--api-key", "b"}, flagAPIKey, "args"},
		{"missing", []string{"vllm", "serve", "m"}, []string{"--port", "8000"}, flagAPIKey, "args"},
		{"longer flag name is not the flag", []string{"vllm", "serve", "--api-key-file", "x"}, nil, flagAPIKey, "args"},
		{"shorter flag name is not the flag", []string{"vllm", "serve", "--api"}, nil, flagAPIKey, "args"},
		{"glued to another word", []string{"sh", "-c", "echo x--api-key y"}, nil, flagAPIKey, "args"},
		{"trust flag in command", []string{"vllm", "serve", "m", "--trust_remote_code"}, nil, flagTrust, "command"},
		{"load format in command", []string{"vllm", "serve", "m", "--load_format=pt"}, nil, flagLoadFormat, "command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := model.Container{Spec: corev1.Container{Command: tc.command, Args: tc.args}}
			if got := flagField(c, tc.flag); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestParseVLLMFromManifest(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want VLLMArgs
	}{
		{"shell string", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["/bin/sh", "-c"]
    args: ["vllm serve /models/q --load-format pt --api-key $KEY"]
`, VLLMArgs{Found: true, Model: "/models/q", LoadFormat: "pt", LoadFormatSet: true, APIKey: true}},
		{"underscore flags in a shell string", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    command: ["sh", "-c", "vllm serve m --load_format pt --api_key sk-x --trust_remote_code"]
`, VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true, APIKey: true, APIKeyLiteral: true, TrustRemoteCode: true}},
		{"shell string with exec and quotes", `
containers:
  - name: vllm
    image: registry.local/serving:1
    command: ["bash", "-lc", "set -e; exec vllm serve 'my model' --load-format=\"safetensors\""]
`, VLLMArgs{Found: true, Model: "my model", LoadFormat: "safetensors", LoadFormatSet: true}},
		{"kubernetes variable expansion", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "$(LOAD_FMT)"]
    env:
      - name: LOAD_FMT
        value: pt
`, VLLMArgs{Found: true, Model: "m", LoadFormat: "pt", LoadFormatSet: true}},
		{"kubernetes variable from a secret stays dynamic", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--load-format", "$(LOAD_FMT)"]
    env:
      - name: LOAD_FMT
        valueFrom:
          configMapKeyRef:
            name: cfg
            key: fmt
`, VLLMArgs{Found: true, Model: "m", LoadFormat: "$(LOAD_FMT)", LoadFormatSet: true, LoadFormatDynamic: true}},
		{"module on a generic image", `
containers:
  - name: server
    image: registry.local/python:3.12
    command: ["python3", "-m", "vllm.entrypoints.openai.api_server"]
    args: ["--model", "m", "--trust-remote-code"]
`, VLLMArgs{Found: true, Model: "m", TrustRemoteCode: true}},
		{"image entrypoint args", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    args: ["--model", "m", "--api-key", "$(KEY)"]
`, VLLMArgs{Found: true, Model: "m", APIKey: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := workloadsOf(t, deployment(tc.spec))
			if len(ws) != 1 || len(ws[0].Containers) != 1 {
				t.Fatalf("got %d workloads", len(ws))
			}
			if got := ParseVLLM(ws[0].Containers[0]); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}
