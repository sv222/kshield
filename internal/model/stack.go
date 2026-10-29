package model

import (
	"path"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
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
		c.Stack = stackOf(c.Spec, c.Commands)
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

func stackOf(spec corev1.Container, cmds []Command) Stack {
	repo := ImageRepo(spec.Image)
	switch {
	case slices.ContainsFunc(repo, func(s string) bool { return strings.Contains(s, "vllm") }),
		slices.ContainsFunc(cmds, runsVLLM):
		return VLLM
	case slices.Contains(repo, "ollama"),
		slices.ContainsFunc(cmds, func(c Command) bool { return program(c) == "ollama" }),
		ollamaSignal(spec):
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

const ollamaPort int32 = 11434

// ollamaSignal reports a container signal that marks a custom image (no
// ollama name segment, no ollama command) as Ollama: the default port, an
// OLLAMA_ env name, or a .ollama mount path. Owner ruling of 2026-10-26:
// any-of rule; detection only widens the AI set.
func ollamaSignal(c corev1.Container) bool {
	for _, p := range c.Ports {
		if p.ContainerPort == ollamaPort || strings.EqualFold(p.Name, "ollama") {
			return true
		}
	}
	for _, e := range c.Env {
		if strings.HasPrefix(e.Name, "OLLAMA_") {
			return true
		}
	}
	for _, m := range c.VolumeMounts {
		if strings.Contains(m.MountPath, ".ollama") {
			return true
		}
	}
	return false
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
