package model

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func ctr(command, args []string, env map[string]string) corev1.Container {
	c := corev1.Container{Command: command, Args: args}
	for k, v := range env {
		c.Env = append(c.Env, corev1.EnvVar{Name: k, Value: v})
	}
	return c
}

func wordsOf(cmds []Command) [][]string {
	var out [][]string
	for _, c := range cmds {
		out = append(out, c.Words)
	}
	return out
}

func sh(script string) corev1.Container {
	return ctr([]string{"sh", "-c", script}, nil, nil)
}

func TestResolveCommands(t *testing.T) {
	cases := []struct {
		name string
		c    corev1.Container
		want [][]string
	}{
		{"plain", ctr([]string{"vllm", "serve", "m"}, []string{"--load-format", "pt"}, nil), [][]string{{"vllm", "serve", "m", "--load-format", "pt"}}},
		{"sh -c", ctr([]string{"sh", "-c"}, []string{"vllm serve m --load-format pt"}, nil), [][]string{{"vllm", "serve", "m", "--load-format", "pt"}}},
		{"bash -lc chain exec", ctr([]string{"/bin/bash", "-lc", "pip install x && exec vllm serve m"}, nil, nil), [][]string{{"pip", "install", "x"}, {"vllm", "serve", "m"}}},
		{"sh -ec", ctr([]string{"/bin/sh", "-ec", "vllm serve m"}, nil, nil), [][]string{{"vllm", "serve", "m"}}},
		{"k8s expansion", ctr(nil, []string{"--load-format", "$(LOAD_FMT)"}, map[string]string{"LOAD_FMT": "pt"}), [][]string{{"--load-format", "pt"}}},
		{"k8s escape", ctr(nil, []string{"$$(LOAD_FMT)"}, map[string]string{"LOAD_FMT": "pt"}), [][]string{{"$(LOAD_FMT)"}}},
		{"k8s unknown", ctr(nil, []string{"$(NOPE)"}, nil), [][]string{{"$(NOPE)"}}},
		{"shell var kept", ctr([]string{"sh", "-c", "vllm serve --model=$MODEL"}, nil, nil), [][]string{{"vllm", "serve", "--model=$MODEL"}}},
		{"parse error fallback", ctr([]string{"sh", "-c", "vllm serve 'unterminated"}, nil, nil), [][]string{{"sh", "-c", "vllm serve 'unterminated"}}},
		{"no command", ctr(nil, nil, nil), nil},

		{"args only", ctr(nil, []string{"--model", "m"}, nil), [][]string{{"--model", "m"}}},
		{"args only with shell", ctr(nil, []string{"sh", "-c", "vllm serve m"}, nil), [][]string{{"vllm", "serve", "m"}}},
		{"command only", ctr([]string{"vllm", "serve"}, nil, nil), [][]string{{"vllm", "serve"}}},
		{"zsh by path", ctr([]string{"/usr/bin/zsh", "-c", "a b"}, nil, nil), [][]string{{"a", "b"}}},
		{"dash -euc", ctr([]string{"dash", "-euc", "a b"}, nil, nil), [][]string{{"a", "b"}}},
		{"ash", ctr([]string{"ash", "-c", "a b"}, nil, nil), [][]string{{"a", "b"}}},
		{"option with argument before -c", ctr([]string{"bash", "-o", "pipefail", "-c", "a b"}, nil, nil), [][]string{{"a", "b"}}},
		{"extra positional arguments ignored", ctr([]string{"sh", "-c", "a b", "name", "arg1"}, nil, nil), [][]string{{"a", "b"}}},
		{"not a shell", ctr([]string{"python", "-c", "print(1)"}, nil, nil), [][]string{{"python", "-c", "print(1)"}}},
		{"shell without -c", ctr([]string{"sh", "-x", "run.sh"}, nil, nil), [][]string{{"sh", "-x", "run.sh"}}},
		{"long option is not a cluster", ctr([]string{"bash", "--rcfile", "x", "run.sh"}, nil, nil), [][]string{{"bash", "--rcfile", "x", "run.sh"}}},
		{"-c without script", ctr([]string{"sh", "-c"}, nil, nil), [][]string{{"sh", "-c"}}},
		{"shell alone", ctr([]string{"bash"}, nil, nil), [][]string{{"bash"}}},
		{"similar name is not a shell", ctr([]string{"fish", "-c", "a b"}, nil, nil), [][]string{{"fish", "-c", "a b"}}},

		{"semicolon and or", sh("a 1; b 2 || c 3"), [][]string{{"a", "1"}, {"b", "2"}, {"c", "3"}}},
		{"subshell and block", sh("(a 1); { b 2; }"), [][]string{{"a", "1"}, {"b", "2"}}},
		{"newlines", sh("set -e\npip install x\nexec vllm serve m\n"), [][]string{{"set", "-e"}, {"pip", "install", "x"}, {"vllm", "serve", "m"}}},
		{"line continuation", sh("vllm serve m \\\n  --load-format pt"), [][]string{{"vllm", "serve", "m", "--load-format", "pt"}}},
		{"comment dropped", sh("vllm serve m # note"), [][]string{{"vllm", "serve", "m"}}},
		{"if body", sh("if true; then vllm serve m; fi"), [][]string{{"true"}, {"vllm", "serve", "m"}}},
		{"pipeline", sh("a 1 | b 2"), [][]string{{"a", "1"}, {"b", "2"}}},
		{"background", sh("a 1 & b 2"), [][]string{{"a", "1"}, {"b", "2"}}},
		{"command substitution", sh("vllm serve $(cat /x)"), [][]string{{"vllm", "serve", "$(cat /x)"}, {"cat", "/x"}}},
		{"empty script", sh(""), nil},
		{"comment only script", sh("# nothing"), nil},
		{"bare exec dropped", sh("exec"), nil},
		{"assignment only", sh("FOO=bar"), nil},
		{"assignment prefix dropped", sh("FOO=bar vllm serve m"), [][]string{{"vllm", "serve", "m"}}},
		{"exec after assignment", sh("FOO=bar exec vllm serve m"), [][]string{{"vllm", "serve", "m"}}},
		{"exec only first word", sh("echo exec"), [][]string{{"echo", "exec"}}},

		{"single quotes removed", sh("vllm serve 'my model'"), [][]string{{"vllm", "serve", "my model"}}},
		{"double quotes removed", sh(`vllm serve "my model"`), [][]string{{"vllm", "serve", "my model"}}},
		{"quoted command name", sh(`"vllm" serve`), [][]string{{"vllm", "serve"}}},
		{"adjacent quoted parts", sh(`vllm serve a"b c"'d e'f`), [][]string{{"vllm", "serve", "ab cd ef"}}},
		{"empty quoted word kept", sh(`vllm serve ""`), [][]string{{"vllm", "serve", ""}}},
		{"backslash outside quotes", sh(`vllm serve a\ b`), [][]string{{"vllm", "serve", "a b"}}},
		{"backslash dollar outside quotes", sh(`echo i\$j`), [][]string{{"echo", "i$j"}}},
		{"backslash in double quotes", sh(`echo "a\$b" "c\"d" "e\f" "g\\h"`), [][]string{{"echo", "a$b", `c"d`, `e\f`, `g\h`}}},
		{"backslash in single quotes", sh(`echo 'e\f'`), [][]string{{"echo", `e\f`}}},
		{"glob and tilde stay literal", sh("ls ~/x a*b"), [][]string{{"ls", "~/x", "a*b"}}},
		{"quoted expansion keeps source", sh(`vllm serve --model="$MODEL" "$X"`), [][]string{{"vllm", "serve", `--model="$MODEL"`, `"$X"`}}},
		{"braced parameter keeps source", sh("vllm serve --port ${PORT:-8000}"), [][]string{{"vllm", "serve", "--port", "${PORT:-8000}"}}},
		{"ansi-c quoting keeps source", sh(`echo $'a\nb'`), [][]string{{"echo", `$'a\nb'`}}},
		{"arithmetic is printed by the shell printer", sh("echo $((1+2))"), [][]string{{"echo", "$((1 + 2))"}}},
		{"multi-line quoted expansion", sh("echo \"a\nb $X\""), [][]string{{"echo", "\"a\nb $X\""}}},

		{"k8s expansion inside script", ctr([]string{"sh", "-c", "vllm serve --load-format $(FMT)"}, nil, map[string]string{"FMT": "pt"}), [][]string{{"vllm", "serve", "--load-format", "pt"}}},
		{"k8s expansion before shell quoting", ctr([]string{"sh", "-c", "vllm serve $(NAME)"}, nil, map[string]string{"NAME": "'a b'"}), [][]string{{"vllm", "serve", "a b"}}},
		{"k8s expansion in command and args", ctr([]string{"$(BIN)"}, []string{"--x=$(V)"}, map[string]string{"BIN": "vllm", "V": "1"}), [][]string{{"vllm", "--x=1"}}},
		{"k8s unknown inside script becomes command substitution", sh("echo $(NOPE)"), [][]string{{"echo", "$(NOPE)"}, {"NOPE"}}},
		{"k8s expansion cannot parse", ctr([]string{"sh", "-c", "echo $(Q)"}, nil, map[string]string{"Q": "'x"}), [][]string{{"sh", "-c", "echo 'x"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wordsOf(ResolveCommands(c.c))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestResolveCommandsEnv(t *testing.T) {
	cases := []struct {
		name string
		env  []corev1.EnvVar
		want string
	}{
		{"literal", []corev1.EnvVar{{Name: "X", Value: "a"}}, "a"},
		{"later overrides earlier", []corev1.EnvVar{{Name: "X", Value: "a"}, {Name: "X", Value: "b"}}, "b"},
		{"empty value is literal", []corev1.EnvVar{{Name: "X"}}, ""},
		{"valueFrom only is unknown", []corev1.EnvVar{{Name: "X", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}}, "$(X)"},
		{"later valueFrom hides earlier literal", []corev1.EnvVar{{Name: "X", Value: "a"}, {Name: "X", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}}}, "$(X)"},
		{"later literal overrides earlier valueFrom", []corev1.EnvVar{{Name: "X", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}}, {Name: "X", Value: "b"}}, "b"},
		{"value expands against an earlier entry", []corev1.EnvVar{{Name: "Y", Value: "z"}, {Name: "X", Value: "$(Y)"}}, "z"},
		{"reference before its definition stays", []corev1.EnvVar{{Name: "X", Value: "$(Y)"}, {Name: "Y", Value: "z"}}, "$(Y)"},
		{"reference to an unknown name stays", []corev1.EnvVar{{Name: "X", Value: "$(Y)"}}, "$(Y)"},
		{"expanded value is not expanded again", []corev1.EnvVar{{Name: "Z", Value: "w"}, {Name: "Y", Value: "$$(Z)"}, {Name: "X", Value: "$(Y)"}}, "$(Z)"},
		{"expansion inside a longer value", []corev1.EnvVar{{Name: "Y", Value: "z"}, {Name: "X", Value: "a-$(Y)-b"}}, "a-z-b"},
		{"chain of three", []corev1.EnvVar{{Name: "A", Value: "q"}, {Name: "Y", Value: "$(A)"}, {Name: "X", Value: "$(Y)"}}, "q"},
		{"self reference uses the earlier value", []corev1.EnvVar{{Name: "X", Value: "a"}, {Name: "X", Value: "$(X)b"}}, "ab"},
		{"self reference without earlier value stays", []corev1.EnvVar{{Name: "X", Value: "$(X)b"}}, "$(X)b"},
		{"reference to a valueFrom entry stays", []corev1.EnvVar{{Name: "Y", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}, {Name: "X", Value: "$(Y)"}}, "$(Y)"},
		{"reference to a name hidden by valueFrom stays", []corev1.EnvVar{{Name: "Y", Value: "z"}, {Name: "Y", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}}, {Name: "X", Value: "$(Y)"}}, "$(Y)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wordsOf(ResolveCommands(corev1.Container{Command: []string{"$(X)"}, Env: c.env}))
			if want := [][]string{{c.want}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestResolveCommandsEnvChain(t *testing.T) {
	chain := []corev1.EnvVar{{Name: "BASE", Value: "pt"}, {Name: "FMT", Value: "$(BASE)"}}
	reversed := []corev1.EnvVar{{Name: "FMT", Value: "$(BASE)"}, {Name: "BASE", Value: "pt"}}
	cases := []struct {
		name string
		c    corev1.Container
		want [][]string
	}{
		{"args", corev1.Container{Args: []string{"--load-format", "$(FMT)"}, Env: chain}, [][]string{{"--load-format", "pt"}}},
		{"command and args", corev1.Container{Command: []string{"vllm", "serve"}, Args: []string{"--load-format=$(FMT)"}, Env: chain}, [][]string{{"vllm", "serve", "--load-format=pt"}}},
		{"shell script", corev1.Container{Command: []string{"sh", "-c", "vllm serve m --load-format $(FMT)"}, Env: chain}, [][]string{{"vllm", "serve", "m", "--load-format", "pt"}}},
		{"definition after use", corev1.Container{Args: []string{"--load-format", "$(FMT)"}, Env: reversed}, [][]string{{"--load-format", "$(BASE)"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wordsOf(ResolveCommands(c.c))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestResolveCommandsDoesNotMutate(t *testing.T) {
	c := ctr([]string{"sh", "-c", "a $(X)"}, []string{"$(X)"}, map[string]string{"X": "1"})
	ResolveCommands(c)
	if !reflect.DeepEqual(c.Command, []string{"sh", "-c", "a $(X)"}) || !reflect.DeepEqual(c.Args, []string{"$(X)"}) {
		t.Fatalf("container mutated: %+v", c)
	}
}

func TestExpandK8s(t *testing.T) {
	env := map[string]string{"X": "1", "Y": "two", "E": "", "N": "$(Y)"}
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"$", "$"},
		{"$$", "$"},
		{"$$$$", "$$"},
		{"$$(X)", "$(X)"},
		{"$$$(X)", "$1"},
		{"$(X)", "1"},
		{"a$(X)b", "a1b"},
		{"$(X)$(Y)", "1two"},
		{"$(X)-$(Y)", "1-two"},
		{"$(E)", ""},
		{"a$(E)b", "ab"},
		{"$(NOPE)", "$(NOPE)"},
		{"$()", "$()"},
		{"$(X", "$(X"},
		{"$(", "$("},
		{"$(X) $(", "1 $("},
		{"$X", "$X"},
		{"${X}", "${X}"},
		{"$ X", "$ X"},
		{"$é", "$é"},
		{"x$", "x$"},
		{"$(N)", "$(Y)"},
		{"--model=$(X)", "--model=1"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := ExpandK8s(c.in, env); got != c.want {
				t.Fatalf("ExpandK8s(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	if got := ExpandK8s("$(X)", nil); got != "$(X)" {
		t.Errorf("nil env: got %q", got)
	}
}

func TestHasK8sReference(t *testing.T) {
	cases := map[string]bool{
		"$(NAME)":         true,
		"Bearer $(TOKEN)": true,
		"$$$(NAME)":       true,
		"plain":           false,
		"":                false,
		"$":               false,
		"Pa$sw0rd":        false,
		"pa$$word":        false,
		"$$(NAME)":        false,
		"$(":              false,
		"abc$(open":       false,
		"$()":             false,
		"${NAME}":         false,
		"$NAME":           false,
	}
	for in, want := range cases {
		if got := HasK8sReference(in); got != want {
			t.Errorf("HasK8sReference(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsShellScript(t *testing.T) {
	cases := []struct {
		words []string
		want  bool
	}{
		{[]string{"sh", "-c", "vllm serve m"}, true},
		{[]string{"/bin/bash", "-lc", "echo"}, true},
		{[]string{"bash", "/start.sh"}, false},
		{[]string{"/start.sh", "--model", "m"}, false},
		{[]string{"sh", "-c"}, false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := IsShellScript(tc.words); got != tc.want {
			t.Errorf("IsShellScript(%q) = %v, want %v", tc.words, got, tc.want)
		}
	}
}
