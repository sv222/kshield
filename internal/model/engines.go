package model

import (
	"slices"
	"strings"
	"unicode"
)

type engine struct {
	stack    Stack
	segments []string
	words    []string
	binaries []string
	modules  []string
}

var engines = []engine{
	{stack: Triton, segments: []string{"tritonserver"}, binaries: []string{"tritonserver"}},
	{stack: TGI, segments: []string{"text-generation-inference"}, words: []string{"tgi"}, binaries: []string{"text-generation-launcher", "text-generation-router"}},
	{stack: TEI, segments: []string{"text-embeddings-inference"}, binaries: []string{"text-embeddings-router"}},
	{stack: LocalAI, segments: []string{"local-ai", "localai"}, binaries: []string{"local-ai"}},
	{stack: SGLang, segments: []string{"sglang"}, binaries: []string{"sglang"}, modules: []string{"sglang"}},
	{stack: LlamaCpp, segments: []string{"llama.cpp", "llama-cpp"}, binaries: []string{"llama-server"}},
	{stack: LMDeploy, segments: []string{"lmdeploy"}, binaries: []string{"lmdeploy"}},
	{stack: TRTLLM, segments: []string{"tensorrt-llm"}, binaries: []string{"trtllm-serve"}},
}

var rayServeSubcommands = []string{"run", "deploy", "shutdown"}

func engineOf(repo []string, cmds []Command) (Stack, bool) {
	for _, e := range engines {
		if e.matchesImage(repo) || slices.ContainsFunc(cmds, e.runs) {
			return e.stack, true
		}
	}
	return Generic, false
}

func (e engine) matchesImage(repo []string) bool {
	return slices.ContainsFunc(repo, func(seg string) bool {
		if slices.ContainsFunc(e.segments, func(p string) bool { return strings.Contains(seg, p) }) {
			return true
		}
		if len(e.words) == 0 {
			return false
		}
		tokens := strings.FieldsFunc(seg, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		return slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(e.words, t) })
	})
}

func (e engine) runs(c Command) bool {
	if slices.Contains(e.binaries, program(c)) {
		return true
	}
	return slices.ContainsFunc(e.modules, func(m string) bool { return runsModule(c, m) })
}

func runsModule(c Command, module string) bool {
	for i := 0; i+1 < len(c.Words); i++ {
		if c.Words[i] != "-m" {
			continue
		}
		if name := c.Words[i+1]; name == module || strings.HasPrefix(name, module+".") {
			return true
		}
	}
	return false
}

func isRayServe(repo []string, cmds []Command) bool {
	if slices.ContainsFunc(repo, func(seg string) bool { return strings.Contains(seg, "ray-serve") }) {
		return true
	}
	return slices.ContainsFunc(cmds, func(c Command) bool {
		if runsModule(c, "ray.serve") {
			return true
		}
		if len(c.Words) < 2 {
			return false
		}
		switch program(c) {
		case "serve":
			return slices.Contains(rayServeSubcommands, c.Words[1])
		case "ray":
			return c.Words[1] == "serve"
		}
		return false
	})
}
