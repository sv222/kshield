package model

import (
	"fmt"
	"testing"
)

const optInDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: genai
  namespace: ai
%s
spec:
  template:
    metadata:
%s
    spec:
      containers:
        - {name: server, image: registry.example.com/platform/genai-service:1.2}
`

func TestOptInMarkers(t *testing.T) {
	cases := []struct {
		name         string
		objectMeta   string
		templateMeta string
		optIn        bool
	}{
		{"object label", "  labels: {kshield.io/ai: \"true\"}", "      labels: {app: x}", true},
		{"object annotation", "  annotations: {kshield.io/ai: \"true\"}", "      labels: {app: x}", true},
		{"template label", "  labels: {app: x}", "      labels: {kshield.io/ai: \"true\"}", true},
		{"template annotation", "  labels: {app: x}", "      annotations: {kshield.io/ai: \"true\"}", true},
		{"value false", "  labels: {kshield.io/ai: \"false\"}", "      labels: {app: x}", false},
		{"other key", "  labels: {ai.infra.guard/enabled: \"true\"}", "      labels: {app: x}", false},
		{"no marker", "  labels: {app: x}", "      labels: {app: x}", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws, err := Extract(readInline(t, fmt.Sprintf(optInDeployment, c.objectMeta, c.templateMeta)))
			if err != nil {
				t.Fatal(err)
			}
			if len(ws) != 1 {
				t.Fatalf("got %d workloads", len(ws))
			}
			w := ws[0]
			if w.OptIn != c.optIn || w.IsAI() != c.optIn {
				t.Fatalf("OptIn = %v, IsAI = %v, want %v", w.OptIn, w.IsAI(), c.optIn)
			}
			wantStack := Generic
			if c.optIn {
				wantStack = Custom
			}
			if got := w.Containers[0].Stack; got != wantStack {
				t.Fatalf("container stack = %q, want %q", got, wantStack)
			}
		})
	}
}

func TestOptInKeepsDetectedStack(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai, labels: {kshield.io/ai: "true"}}
spec:
  template:
    spec:
      containers:
        - {name: server, image: ollama/ollama}
        - {name: proxy, image: envoyproxy/envoy:v1.31}
`))
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]
	if !w.OptIn || len(w.Stacks) != 1 || w.Stacks[0] != Ollama {
		t.Fatalf("OptIn = %v, Stacks = %v", w.OptIn, w.Stacks)
	}
	if w.Containers[1].Stack != Generic {
		t.Fatalf("proxy stack = %q", w.Containers[1].Stack)
	}
}

func TestOptInManyContainersHasNoEngineContainer(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai, labels: {kshield.io/ai: "true"}}
spec:
  template:
    spec:
      initContainers:
        - {name: init, image: busybox}
      containers:
        - {name: app, image: registry.example.com/platform/app:1}
        - {name: proxy, image: envoyproxy/envoy:v1.31}
`))
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]
	if !w.IsAI() || !w.HasStack(Custom) {
		t.Fatalf("Stacks = %v", w.Stacks)
	}
	for _, c := range w.Containers {
		if c.Stack != Generic {
			t.Fatalf("container %s stack = %q", c.Spec.Name, c.Stack)
		}
	}
}

func TestOptInInitContainerDoesNotCount(t *testing.T) {
	ws, err := Extract(readInline(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ai, labels: {kshield.io/ai: "true"}}
spec:
  template:
    spec:
      initContainers:
        - {name: init, image: busybox}
      containers:
        - {name: app, image: registry.example.com/platform/app:1}
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ws[0].Containers {
		want := Generic
		if !c.Init {
			want = Custom
		}
		if c.Stack != want {
			t.Fatalf("container %s stack = %q, want %q", c.Spec.Name, c.Stack, want)
		}
	}
}

func TestWorkloadSelector(t *testing.T) {
	doc := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: genai, namespace: ai, labels: {team: ml}}
spec:
  template:
    metadata:
      labels: {app: genai, tier: backend}
    spec:
      containers:
        - {name: server, image: registry.example.com/platform/genai-service:1.2}
`
	cases := []struct {
		selector string
		optIn    bool
	}{
		{"app=genai", true},
		{"team=ml", true},
		{"tier in (backend, worker)", true},
		{"app=genai,tier=front", false},
		{"app=other", false},
		{"missing", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.selector, func(t *testing.T) {
			sel, err := ParseSelector(c.selector)
			if err != nil {
				t.Fatal(err)
			}
			ws, err := Extract(readInline(t, doc), WithSelector(sel))
			if err != nil {
				t.Fatal(err)
			}
			if ws[0].OptIn != c.optIn || ws[0].IsAI() != c.optIn {
				t.Fatalf("OptIn = %v, IsAI = %v", ws[0].OptIn, ws[0].IsAI())
			}
		})
	}
}

func TestParseSelectorInvalid(t *testing.T) {
	for _, s := range []string{"a b", "app in (", "!!"} {
		if _, err := ParseSelector(s); err == nil {
			t.Errorf("ParseSelector(%q) = nil error", s)
		}
	}
	if sel, err := ParseSelector("  "); err != nil || sel != nil {
		t.Errorf("blank selector = %v, %v", sel, err)
	}
}
