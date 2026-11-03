package model

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/load"
)

func img(image string, command, args []string) corev1.Container {
	return corev1.Container{Image: image, Command: command, Args: args}
}

func wl(kind string, cs ...corev1.Container) *Workload {
	w := &Workload{Owner: load.ObjectRef{Kind: kind}}
	for i, c := range cs {
		w.Containers = append(w.Containers, Container{Index: i, Spec: c})
	}
	return w
}

func TestImageRepo(t *testing.T) {
	cases := []struct {
		image string
		want  []string
	}{
		{"vllm/vllm-openai:v0.6.0", []string{"vllm", "vllm-openai"}},
		{"nginx", []string{"nginx"}},
		{"nginx:1.27", []string{"nginx"}},
		{"Nginx:Latest", []string{"nginx"}},
		{"reg:5000/vllm/vllm-openai:v1", []string{"reg:5000", "vllm", "vllm-openai"}},
		{"reg:5000/vllm/vllm-openai", []string{"reg:5000", "vllm", "vllm-openai"}},
		{"localhost:5000/app:dev", []string{"localhost:5000", "app"}},
		{"vllm/vllm-openai@sha256:0123abcd", []string{"vllm", "vllm-openai"}},
		{"vllm/vllm-openai:v1@sha256:0123abcd", []string{"vllm", "vllm-openai"}},
		{"reg:5000/vllm/vllm-openai:v1@sha256:0123abcd", []string{"reg:5000", "vllm", "vllm-openai"}},
		{"quay.io/rayproject/ray-ml:2.9.0-gpu", []string{"quay.io", "rayproject", "ray-ml"}},
		{"REG.IO:5000/Org/Image:Tag@sha256:ABCD", []string{"reg.io:5000", "org", "image"}},
		{"ollama/ollama", []string{"ollama", "ollama"}},
		{"nginx@sha256:0123abcd", []string{"nginx"}},
		{"", nil},
	}
	for _, c := range cases {
		t.Run(c.image, func(t *testing.T) {
			if got := ImageRepo(c.image); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ImageRepo(%q) = %q, want %q", c.image, got, c.want)
			}
		})
	}
}

func TestClassifyContainer(t *testing.T) {
	cases := []struct {
		name string
		c    corev1.Container
		want Stack
	}{
		{"vllm image with args only", img("vllm/vllm-openai:v0.6.0", nil, []string{"--model", "m"}), VLLM},
		{"vllm image bare", img("vllm/vllm-openai", nil, nil), VLLM},
		{"vllm image with registry port", img("reg:5000/vllm/vllm-openai:v1", nil, nil), VLLM},
		{"vllm image by digest", img("vllm/vllm-openai@sha256:0123abcd", nil, nil), VLLM},
		{"vllm image uppercase", img("VLLM/vLLM-OpenAI:v1", nil, nil), VLLM},
		{"vllm substring in segment", img("myorg/custom-vllm-build:1", nil, nil), VLLM},
		{"python -m vllm.entrypoints", img("python:3.12", []string{"python3", "-m", "vllm.entrypoints.openai.api_server"}, []string{"--model", "m"}), VLLM},
		{"python -m vllm.entrypoints in sh -c", img("python:3.12", []string{"sh", "-c", "python3 -m vllm.entrypoints.openai.api_server --model m"}, nil), VLLM},
		{"vllm binary", img("python:3.12", []string{"vllm", "serve", "m"}, nil), VLLM},
		{"vllm binary by path", img("python:3.12", []string{"/usr/local/bin/vllm", "serve", "m"}, nil), VLLM},
		{"vllm binary after install", img("python:3.12", []string{"bash", "-c", "pip install vllm && exec vllm serve m"}, nil), VLLM},
		{"vllm binary from args", img("python:3.12", nil, []string{"vllm", "serve", "m"}), VLLM},
		{"-m without module", img("python:3.12", []string{"python", "-m"}, nil), Generic},
		{"-m other module", img("python:3.12", []string{"python", "-m", "http.server"}, nil), Generic},
		{"module prefix must start the word", img("python:3.12", []string{"python", "-m", "x.vllm.entrypoints"}, nil), Generic},
		{"vllm as argument only", img("python:3.12", []string{"echo", "vllm"}, nil), Generic},
		{"pip install vllm only", img("python:3.12", []string{"pip", "install", "vllm"}, nil), Generic},

		{"ollama image", img("ollama/ollama:0.5.0", nil, nil), Ollama},
		{"ollama binary", img("ubuntu:24.04", []string{"/usr/bin/ollama", "serve"}, nil), Ollama},
		{"ollama binary in script", img("ubuntu:24.04", []string{"sh", "-c", "ollama serve & sleep 5; ollama pull m"}, nil), Ollama},
		{"qdrant image", img("qdrant/qdrant:v1.12.0", nil, nil), Qdrant},
		{"qdrant by registry", img("docker.io/qdrant/qdrant", nil, nil), Qdrant},
		{"milvus image", img("milvusdb/milvus:v2.4.0", nil, nil), Milvus},
		{"ray image", img("rayproject/ray:2.9.0", nil, nil), Ray},
		{"ray-ml image", img("rayproject/ray-ml:2.9.0-gpu", nil, nil), Ray},
		{"ray image with registry", img("quay.io/rayproject/ray:2.9.0", nil, nil), Ray},
		{"rayproject other image", img("rayproject/other:1", nil, nil), Generic},
		{"ray without rayproject", img("someorg/ray:1", nil, nil), Generic},
		{"rayproject not followed by ray", img("rayproject/x/ray:1", nil, nil), Generic},
		{"qdrant as command word only", img("busybox", []string{"echo", "qdrant"}, nil), Generic},

		{"first match wins: vllm command over ollama image", img("ollama/ollama", []string{"vllm", "serve", "m"}, nil), VLLM},
		{"first match wins: vllm segment under rayproject", img("rayproject/vllm", nil, nil), VLLM},
		{"first match wins: ollama command over qdrant image", img("qdrant/qdrant", []string{"ollama", "serve"}, nil), Ollama},

		{"nginx", img("nginx:1.27", nil, nil), Generic},
		{"no image", corev1.Container{}, Generic},
		{"shell parse error falls back to raw words", img("busybox", []string{"sh", "-c", "vllm serve 'oops"}, nil), Generic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := wl("Deployment", c.c)
			Classify(w)
			if got := w.Containers[0].Stack; got != c.want {
				t.Fatalf("Stack = %q, want %q", got, c.want)
			}
			wantStacks := []Stack(nil)
			if c.want != Generic {
				wantStacks = []Stack{c.want}
			}
			if !reflect.DeepEqual(w.Stacks, wantStacks) {
				t.Fatalf("Stacks = %v, want %v", w.Stacks, wantStacks)
			}
			if w.IsAI() != (c.want != Generic) {
				t.Fatalf("IsAI = %v", w.IsAI())
			}
		})
	}
}

func TestClassifyWorkload(t *testing.T) {
	vllm := img("vllm/vllm-openai:v0.6.0", nil, nil)
	cases := []struct {
		name       string
		kind       string
		containers []corev1.Container
		stacks     []Stack
		perCont    []Stack
	}{
		{"ray worker with ray image", "RayCluster", []corev1.Container{img("rayproject/ray:2.9.0", nil, nil)}, []Stack{Ray}, []Stack{Ray}},
		{"ray worker with vllm image", "RayCluster", []corev1.Container{vllm}, []Stack{Ray, VLLM}, []Stack{VLLM}},
		{"ray worker with generic image", "RayCluster", []corev1.Container{img("nginx", nil, nil)}, []Stack{Ray}, []Stack{Generic}},
		{"ray owner without containers", "RayCluster", nil, []Stack{Ray}, nil},
		{"rayservice", "RayService", []corev1.Container{img("nginx", nil, nil)}, []Stack{Ray}, []Stack{Generic}},
		{"rayjob", "RayJob", []corev1.Container{vllm}, []Stack{Ray, VLLM}, []Stack{VLLM}},
		{"inferenceservice with vllm image", "InferenceService", []corev1.Container{vllm}, []Stack{KServe, VLLM}, []Stack{VLLM}},
		{"inferenceservice generic", "InferenceService", []corev1.Container{img("kserve/huggingfaceserver:v0.14.0", nil, nil)}, []Stack{KServe}, []Stack{Generic}},
		{"servingruntime", "ServingRuntime", []corev1.Container{img("nginx", nil, nil)}, []Stack{KServe}, []Stack{Generic}},
		{"clusterservingruntime", "ClusterServingRuntime", []corev1.Container{vllm}, []Stack{KServe, VLLM}, []Stack{VLLM}},
		{"deployment generic", "Deployment", []corev1.Container{img("nginx", nil, nil)}, nil, []Stack{Generic}},
		{"deployment without containers", "Deployment", nil, nil, nil},
		{"sorted and unique", "Deployment", []corev1.Container{vllm, img("ollama/ollama", nil, nil), vllm, img("qdrant/qdrant", nil, nil)}, []Stack{Ollama, Qdrant, VLLM}, []Stack{VLLM, Ollama, VLLM, Qdrant}},
		{"ray owner and ray image are one entry", "RayCluster", []corev1.Container{img("rayproject/ray", nil, nil), img("rayproject/ray-ml", nil, nil)}, []Stack{Ray}, []Stack{Ray, Ray}},
		{"milvus and generic", "StatefulSet", []corev1.Container{img("busybox", nil, nil), img("milvusdb/milvus", nil, nil)}, []Stack{Milvus}, []Stack{Generic, Milvus}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := wl(c.kind, c.containers...)
			Classify(w)
			if !reflect.DeepEqual(w.Stacks, c.stacks) {
				t.Errorf("Stacks = %v, want %v", w.Stacks, c.stacks)
			}
			var got []Stack
			for _, ct := range w.Containers {
				got = append(got, ct.Stack)
			}
			if !reflect.DeepEqual(got, c.perCont) {
				t.Errorf("container stacks = %v, want %v", got, c.perCont)
			}
			if w.IsAI() != (len(c.stacks) > 0) {
				t.Errorf("IsAI = %v", w.IsAI())
			}
		})
	}
}

func TestClassifyInitContainers(t *testing.T) {
	w := wl("Deployment", img("qdrant/qdrant", nil, nil), img("nginx", nil, nil))
	w.Containers[0].Init = true
	Classify(w)
	if w.Containers[0].Stack != Qdrant || w.Containers[1].Stack != Generic {
		t.Fatalf("container stacks = %q, %q", w.Containers[0].Stack, w.Containers[1].Stack)
	}
	if want := []Stack{Qdrant}; !reflect.DeepEqual(w.Stacks, want) {
		t.Fatalf("Stacks = %v, want %v", w.Stacks, want)
	}
}

func TestClassifySetsCommands(t *testing.T) {
	w := wl("Deployment",
		img("busybox", []string{"sh", "-c", "pip install x && exec vllm serve m"}, nil),
		img("vllm/vllm-openai", nil, []string{"--model", "m"}),
		img("nginx", nil, nil),
	)
	Classify(w)
	want := [][][]string{
		{{"pip", "install", "x"}, {"vllm", "serve", "m"}},
		{{"--model", "m"}},
		nil,
	}
	for i, c := range w.Containers {
		if got := wordsOf(c.Commands); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("container %d commands = %q, want %q", i, got, want[i])
		}
	}
	if c := w.Containers[2]; c.Commands != nil {
		t.Errorf("container without command has Commands = %v, want nil", c.Commands)
	}
}

func TestClassifyUsesLiteralEnv(t *testing.T) {
	c := img("python:3.12", []string{"$(BIN)", "serve"}, nil)
	c.Env = []corev1.EnvVar{{Name: "BIN", Value: "vllm"}}
	w := wl("Deployment", c)
	Classify(w)
	if w.Containers[0].Stack != VLLM {
		t.Fatalf("Stack = %q, want vllm", w.Containers[0].Stack)
	}
}

func TestExtractClassifies(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: ray.io/v1
kind: RayCluster
metadata: {name: rc, namespace: ai}
spec:
  headGroupSpec:
    template:
      spec:
        containers:
          - {name: head, image: "rayproject/ray:2.9.0"}
  workerGroupSpecs:
    - groupName: cpu
      template:
        spec:
          containers:
            - {name: w, image: "nginx"}
    - groupName: gpu
      template:
        spec:
          containers:
            - name: w
              image: "vllm/vllm-openai:v0.6.0"
              args: ["--model", "m"]
---
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: llm, namespace: ai}
spec:
  predictor:
    containers:
      - name: kserve-container
        image: "python:3.12"
        command: ["sh", "-c", "exec python3 -m vllm.entrypoints.openai.api_server --model m"]
  transformer:
    containers:
      - {name: t, image: "nginx"}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: ai}
spec:
  template:
    spec:
      containers:
        - {name: web, image: "nginx"}
`))
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		owner  string
		group  string
		stacks []Stack
		ai     bool
		cont   []Stack
	}
	var gotAll []got
	for _, w := range ws {
		g := got{w.Owner.String(), w.Group, w.Stacks, w.IsAI(), nil}
		for _, c := range w.Containers {
			g.cont = append(g.cont, c.Stack)
		}
		gotAll = append(gotAll, g)
	}
	want := []got{
		{"RayCluster/ai/rc", "head", []Stack{Ray}, true, []Stack{Ray}},
		{"RayCluster/ai/rc", "cpu", []Stack{Ray}, true, []Stack{Generic}},
		{"RayCluster/ai/rc", "gpu", []Stack{Ray, VLLM}, true, []Stack{VLLM}},
		{"InferenceService/ai/llm", "predictor", []Stack{KServe, VLLM}, true, []Stack{VLLM}},
		{"InferenceService/ai/llm", "transformer", []Stack{KServe}, true, []Stack{Generic}},
		{"Deployment/ai/web", "", nil, false, []Stack{Generic}},
	}
	if !reflect.DeepEqual(gotAll, want) {
		t.Fatalf("got  %+v\nwant %+v", gotAll, want)
	}
	if cmds := wordsOf(ws[2].Containers[0].Commands); !reflect.DeepEqual(cmds, [][]string{{"--model", "m"}}) {
		t.Errorf("gpu worker commands = %q", cmds)
	}
	wantCmds := [][]string{{"python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "m"}}
	if cmds := wordsOf(ws[3].Containers[0].Commands); !reflect.DeepEqual(cmds, wantCmds) {
		t.Errorf("predictor commands = %q, want %q", cmds, wantCmds)
	}
}
