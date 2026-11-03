package remediate

import "testing"

func TestEditShell(t *testing.T) {
	trust := ShellEdit{Program: "vllm", RemoveFlags: []string{"--trust-remote-code"}}
	load := ShellEdit{Program: "vllm", SetFlag: "--load-format", SetValue: "safetensors"}
	both := ShellEdit{Program: "vllm", RemoveFlags: []string{"--trust-remote-code"}, SetFlag: "--load-format", SetValue: "safetensors"}
	cases := []struct {
		name, script string
		edit         ShellEdit
		want         string
	}{
		{"remove flag", "vllm serve m --trust-remote-code --port 8000", trust, "vllm serve m --port 8000"},
		{"remove equals form", "vllm serve m --trust-remote-code=true --port 8000", trust, "vllm serve m --port 8000"},
		{"remove underscore form", "vllm serve m --trust_remote_code", trust, "vllm serve m"},
		{"remove twice", "vllm serve m --trust-remote-code --trust_remote_code=1", trust, "vllm serve m"},
		{"replace equals value", "pip install x && exec vllm serve m --load-format=pt", load, "pip install x && exec vllm serve m --load-format=safetensors"},
		{"replace value word", "vllm serve m --load-format pt --port 8000", load, "vllm serve m --load-format safetensors --port 8000"},
		{"replace underscore", "vllm serve m --load_format \"pt\"", load, "vllm serve m --load_format safetensors"},
		{"flag without value", "vllm serve m --load-format --port 8000", load, "vllm serve m --load-format=safetensors --port 8000"},
		{"append before and", "vllm serve m && echo done", load, "vllm serve m --load-format safetensors && echo done"},
		{"append before redirect", "vllm serve m > /tmp/log", load, "vllm serve m --load-format safetensors > /tmp/log"},
		{"other call untouched", "echo --trust-remote-code; vllm serve m", trust, "echo --trust-remote-code; vllm serve m"},
		{"quotes kept", `vllm serve "my model" --trust-remote-code`, trust, `vllm serve "my model"`},
		{"single quotes kept", `vllm serve 'my model' --trust-remote-code --port 8000`, trust, `vllm serve 'my model' --port 8000`},
		{"line continuation", "vllm serve m \\\n  --trust-remote-code \\\n  --port 8000", trust, "vllm serve m \\\n  --port 8000"},
		{"python module", "python3 -m vllm.entrypoints.openai.api_server --model m --trust-remote-code", both,
			"python3 -m vllm.entrypoints.openai.api_server --model m --load-format safetensors"},
		{"remove and replace", "vllm serve m --trust-remote-code --load-format pt", both, "vllm serve m --load-format safetensors"},
		{"remove last and append", "vllm serve m --port 8000 --trust-remote-code", both, "vllm serve m --port 8000 --load-format safetensors"},
		{"value already set", "vllm serve m --load-format safetensors", load, "vllm serve m --load-format safetensors"},
		{"path program", "/usr/local/bin/vllm serve m --trust-remote-code", trust, "/usr/local/bin/vllm serve m"},
		{"two calls", "vllm serve a --trust-remote-code; vllm serve b --trust-remote-code", trust, "vllm serve a; vllm serve b"},
		{"env prefix", "HF_HOME=/c vllm serve m --trust-remote-code", trust, "HF_HOME=/c vllm serve m"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := EditShell(c.script, c.edit)
			if !ok {
				t.Fatal("no vllm call matched")
			}
			if got != c.want {
				t.Fatalf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestEditShellNoCall(t *testing.T) {
	edit := ShellEdit{Program: "vllm", RemoveFlags: []string{"--trust-remote-code"}, SetFlag: "--load-format", SetValue: "safetensors"}
	for _, script := range []string{
		"python serve.py --trust-remote-code",
		"echo vllm serve m --trust-remote-code",
		"vllm --version",
		"if then fi (",
	} {
		got, ok := EditShell(script, edit)
		if ok || got != script {
			t.Errorf("%q: got %q, %v", script, got, ok)
		}
	}
}
