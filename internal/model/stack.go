package model

import (
	"path"
	"slices"
	"strings"
)

func ImageRepo(image string) []string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, ':'); i > strings.LastIndexByte(image, '/') {
		image = image[:i]
	}
	if image == "" {
		return nil
	}
	return strings.Split(strings.ToLower(image), "/")
}

func Classify(w *Workload) {
	var stacks []Stack
	for i := range w.Containers {
		c := &w.Containers[i]
		c.Commands = ResolveCommands(c.Spec)
		c.Stack = stackOf(ImageRepo(c.Spec.Image), c.Commands)
		if c.Stack != Generic {
			stacks = append(stacks, c.Stack)
		}
	}
	switch w.Owner.Kind {
	case "RayCluster", "RayService", "RayJob":
		stacks = append(stacks, Ray)
	case "InferenceService", "ServingRuntime", "ClusterServingRuntime":
		stacks = append(stacks, KServe)
	}
	slices.Sort(stacks)
	w.Stacks = slices.Compact(stacks)
}

func stackOf(repo []string, cmds []Command) Stack {
	switch {
	case slices.ContainsFunc(repo, func(s string) bool { return strings.Contains(s, "vllm") }),
		slices.ContainsFunc(cmds, runsVLLM):
		return VLLM
	case slices.Contains(repo, "ollama"),
		slices.ContainsFunc(cmds, func(c Command) bool { return program(c) == "ollama" }):
		return Ollama
	case slices.Contains(repo, "qdrant"):
		return Qdrant
	case slices.Contains(repo, "milvus"):
		return Milvus
	case isRayImage(repo):
		return Ray
	}
	return Generic
}

func runsVLLM(c Command) bool {
	if program(c) == "vllm" {
		return true
	}
	for i := 0; i+1 < len(c.Words); i++ {
		if c.Words[i] == "-m" && strings.HasPrefix(c.Words[i+1], "vllm.entrypoints") {
			return true
		}
	}
	return false
}

func program(c Command) string {
	if len(c.Words) == 0 {
		return ""
	}
	return path.Base(c.Words[0])
}

func isRayImage(repo []string) bool {
	for i := 0; i+1 < len(repo); i++ {
		if repo[i] == "rayproject" && (repo[i+1] == "ray" || repo[i+1] == "ray-ml") {
			return true
		}
	}
	return false
}
