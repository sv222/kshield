package model

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestClassifyEngines(t *testing.T) {
	cases := []struct {
		name string
		c    corev1.Container
		want Stack
	}{
		{"triton image", img("nvcr.io/nvidia/tritonserver:24.05-py3", nil, nil), Triton},
		{"triton binary", img("registry.example.com/serving/runtime:1", []string{"tritonserver", "--model-repository=/models"}, nil), Triton},
		{"triton binary by path in script", img("busybox", []string{"sh", "-c", "exec /opt/tritonserver/bin/tritonserver --model-repository=/models"}, nil), Triton},
		{"tgi long image", img("ghcr.io/huggingface/text-generation-inference:3.3.4", nil, nil), TGI},
		{"tgi short image", img("ghcr.io/huggingface/tgi:3.3.4", nil, nil), TGI},
		{"tgi word in a dashed segment", img("registry.example.com/ml/tgi-gaudi:2", nil, nil), TGI},
		{"tgi launcher", img("registry.example.com/serving/runtime:1", []string{"text-generation-launcher", "--model-id", "m"}, nil), TGI},
		{"tgi router", img("registry.example.com/serving/runtime:1", []string{"/usr/local/bin/text-generation-router"}, nil), TGI},
		{"tgi letters inside another word", img("registry.example.com/ml/sgtgix:1", nil, nil), Generic},
		{"tei image", img("ghcr.io/huggingface/text-embeddings-inference:cpu-1.8", nil, nil), TEI},
		{"tei router", img("registry.example.com/serving/runtime:1", []string{"text-embeddings-router", "--model-id", "m"}, nil), TEI},
		{"localai image", img("quay.io/go-skynet/local-ai:latest", nil, nil), LocalAI},
		{"localai one word", img("localai/localai:latest-gpu", nil, nil), LocalAI},
		{"localai binary", img("registry.example.com/serving/runtime:1", []string{"local-ai", "run"}, nil), LocalAI},
		{"sglang image", img("lmsysorg/sglang:v0.4.6", nil, nil), SGLang},
		{"sglang binary", img("registry.example.com/serving/runtime:1", []string{"sglang", "serve"}, nil), SGLang},
		{"sglang module", img("python:3.12", []string{"python3", "-m", "sglang.launch_server", "--model-path", "m"}, nil), SGLang},
		{"sglang module in script", img("python:3.12", []string{"sh", "-c", "cd /srv && python -m sglang.launch_server --model-path m"}, nil), SGLang},
		{"llama.cpp image", img("ghcr.io/ggml-org/llama.cpp:server", nil, nil), LlamaCpp},
		{"llama-cpp image", img("registry.example.com/ml/llama-cpp-python:1", nil, nil), LlamaCpp},
		{"llama-server binary", img("registry.example.com/serving/runtime:1", []string{"/app/llama-server", "-m", "model.gguf"}, nil), LlamaCpp},
		{"lmdeploy image", img("openmmlab/lmdeploy:v0.9.0", nil, nil), LMDeploy},
		{"lmdeploy binary", img("python:3.12", nil, []string{"lmdeploy", "serve", "api_server", "m"}), LMDeploy},
		{"tensorrt-llm image", img("nvcr.io/nvidia/tensorrt-llm/release:1.0", nil, nil), TRTLLM},
		{"trtllm-serve binary", img("python:3.12", []string{"trtllm-serve", "m"}, nil), TRTLLM},
		{"ray serve cli", img("python:3.12", []string{"serve", "run", "app:graph"}, nil), Ray},
		{"ray serve deploy", img("python:3.12", []string{"serve", "deploy", "config.yaml"}, nil), Ray},
		{"ray command with serve", img("python:3.12", []string{"ray", "serve", "run", "app:graph"}, nil), Ray},
		{"ray serve image name", img("registry.example.com/ml/ray-serve-app:1", nil, nil), Ray},
		{"static file server named serve", img("node:22", []string{"serve", "-s", "build"}, nil), Generic},
		{"ray start alone", img("python:3.12", []string{"ray", "start", "--head"}, nil), Generic},

		{"postgis", img("postgis/postgis:16-3.4", nil, nil), Generic},
		{"wget probe", img("busybox", []string{"wget"}, []string{"rel-ollama:11434"}), Generic},
		{"engine name as an argument", img("registry.example.com/platform/web:1.0", nil, []string{"--backend", "triton", "--served-model-name", "llama.cpp"}), Generic},
		{"engine name in an echo", img("busybox", []string{"echo", "tritonserver"}, nil), Generic},
		{"pip install sglang only", img("python:3.12", []string{"pip", "install", "sglang"}, nil), Generic},
		{"vllm still first", img("lmsysorg/sglang", []string{"vllm", "serve", "m"}, nil), VLLM},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := wl("Deployment", c.c)
			Classify(w)
			if got := w.Containers[0].Stack; got != c.want {
				t.Fatalf("Stack = %q, want %q", got, c.want)
			}
			if w.IsAI() != (c.want != Generic) {
				t.Fatalf("IsAI = %v", w.IsAI())
			}
		})
	}
}

func TestEngineWords(t *testing.T) {
	cases := []struct {
		name      string
		c         corev1.Container
		want      []string
		certain   bool
		wantStack Stack
	}{
		{"args of an image-detected engine", img("ghcr.io/huggingface/text-generation-inference:3", nil, []string{"--model-id", "m", "--debug"}), []string{"--model-id", "m", "--debug"}, true, TGI},
		{"engine command picked from a script", img("busybox", []string{"sh", "-c", "pip install x --debug && exec tritonserver --model-repository=/m"}, nil), []string{"tritonserver", "--model-repository=/m"}, true, Triton},
		{"several commands and no engine command", img("lmsysorg/sglang", []string{"sh", "-c", "a --x && b --y"}, nil), []string{"a", "--x", "b", "--y"}, false, SGLang},
		{"single command that is not the engine", img("lmsysorg/sglang", []string{"python", "serve.py", "--x"}, nil), []string{"python", "serve.py", "--x"}, true, SGLang},
		{"no command", img("lmsysorg/sglang", nil, nil), nil, true, SGLang},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := wl("Deployment", c.c)
			Classify(w)
			if w.Containers[0].Stack != c.wantStack {
				t.Fatalf("Stack = %q, want %q", w.Containers[0].Stack, c.wantStack)
			}
			words, certain := w.Containers[0].EngineWords()
			if !reflect.DeepEqual(words, c.want) || certain != c.certain {
				t.Fatalf("EngineWords = %q, %v; want %q, %v", words, certain, c.want, c.certain)
			}
		})
	}
}
