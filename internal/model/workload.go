package model

import (
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/load"
)

type Stack string

const (
	Generic Stack = ""
	VLLM    Stack = "vllm"
	Ray     Stack = "ray"
	Ollama  Stack = "ollama"
	Qdrant  Stack = "qdrant"
	Milvus  Stack = "milvus"
	KServe  Stack = "kserve"
)

type Command struct {
	Words []string
}

type Container struct {
	Index    int
	Init     bool
	Spec     corev1.Container
	Path     string
	Stack    Stack
	Commands []Command
}

type Workload struct {
	Owner       load.ObjectRef
	Object      *load.Object
	SpecPath    string
	Group       string
	Labels      map[string]string
	Annotations map[string]string
	Spec        corev1.PodSpec
	Containers  []Container
	Stacks      []Stack
}

func (w Workload) IsAI() bool {
	return len(w.Stacks) > 0
}

func (w Workload) HasStack(s Stack) bool {
	return slices.Contains(w.Stacks, s)
}
