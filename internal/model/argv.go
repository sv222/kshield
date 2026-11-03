package model

import (
	"bytes"
	"path"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"mvdan.cc/sh/v3/syntax"
)

var shells = []string{"sh", "bash", "dash", "ash", "zsh"}

func ResolveCommands(c corev1.Container) []Command {
	env := envMap(c.Env)
	words := make([]string, 0, len(c.Command)+len(c.Args))
	for _, w := range slices.Concat(c.Command, c.Args) {
		words = append(words, ExpandK8s(w, env))
	}
	if len(words) == 0 {
		return nil
	}
	if script, ok := shellScript(words); ok {
		if cmds, ok := parseScript(script); ok {
			return cmds
		}
	}
	return []Command{{Words: words}}
}

// source: https://github.com/kubernetes/kubernetes/blob/v1.37.1/pkg/kubelet/kubelet_pods.go@v1.37.1
func envMap(env []corev1.EnvVar) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		if e.ValueFrom != nil {
			delete(m, e.Name)
			continue
		}
		m[e.Name] = ExpandK8s(e.Value, m)
	}
	return m
}

func IsShellScript(words []string) bool {
	if len(words) == 0 {
		return false
	}
	_, ok := shellScript(words)
	return ok
}

func shellScript(words []string) (string, bool) {
	i, ok := ShellScriptIndex(words)
	if !ok {
		return "", false
	}
	return words[i], true
}

func ShellScriptIndex(words []string) (int, bool) {
	if len(words) == 0 || !slices.Contains(shells, path.Base(words[0])) {
		return 0, false
	}
	for i := 1; i < len(words)-1; i++ {
		if isCommandFlag(words[i]) {
			return i + 1, true
		}
	}
	return 0, false
}

func isCommandFlag(w string) bool {
	return len(w) > 1 && w[0] == '-' && !strings.Contains(w[1:], "-") && strings.Contains(w, "c")
}

func parseScript(script string) ([]Command, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, false
	}
	printer := syntax.NewPrinter(syntax.SingleLine(true))
	var out []Command
	failed := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if failed {
			return false
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		words := make([]string, 0, len(call.Args))
		for _, w := range call.Args {
			text, err := wordText(printer, w)
			if err != nil {
				failed = true
				return false
			}
			words = append(words, text)
		}
		if len(words) > 0 && words[0] == "exec" {
			words = words[1:]
		}
		if len(words) > 0 {
			out = append(out, Command{Words: words})
		}
		return true
	})
	if failed {
		return nil, false
	}
	return out, true
}

func wordText(printer *syntax.Printer, w *syntax.Word) (string, error) {
	if v, ok := LiteralWord(w); ok {
		return v, nil
	}
	var buf bytes.Buffer
	if err := printer.Print(&buf, w); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func LiteralWord(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescape(p.Value, false))
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false
			}
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(unescape(lit.Value, true))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func unescape(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (!quoted || strings.IndexByte("$`\"\\", s[i+1]) >= 0) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
