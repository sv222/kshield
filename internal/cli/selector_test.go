package cli

import (
	"strings"
	"testing"
)

const customImageDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: genai
  namespace: llm
spec:
  selector:
    matchLabels:
      app: genai
  template:
    metadata:
      labels:
        app: genai
        tier: model
    spec:
      containers:
        - name: server
          image: registry.example.com/platform/genai-service:1.2
`

func TestScanManifestWorkloadSelector(t *testing.T) {
	path := writeManifest(t, "in.yaml", customImageDeployment)
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--deterministic", "--fail-on", "never")
	if code != ExitOK || errs != "" || !strings.Contains(out, "0 AI workloads") {
		t.Fatalf("without selector: code=%d stderr=%q stdout=%q", code, errs, out)
	}
	code, out, errs = run(t, "", "scan", "manifest", "-f", path, "--deterministic", "--fail-on", "never", "--workload-selector", "tier=model")
	if code != ExitOK || errs != "" || !strings.Contains(out, "1 AI workloads") {
		t.Fatalf("with selector: code=%d stderr=%q stdout=%q", code, errs, out)
	}
	code, out, _ = run(t, "", "scan", "manifest", "-f", path, "--deterministic", "--fail-on", "never", "--workload-selector", "tier=model", "--format", "json")
	if code != ExitOK || !strings.Contains(out, `"workloadSelector": "tier=model"`) {
		t.Fatalf("json must record the selector: code=%d %q", code, out)
	}
	code, _, errs = run(t, "", "scan", "manifest", "-f", path, "--workload-selector", "tier in (")
	if code != ExitUsage || !strings.Contains(errs, "invalid workload selector") {
		t.Fatalf("bad selector: code=%d stderr=%q", code, errs)
	}
}

func TestScanClusterWorkloadSelectorIsAFlag(t *testing.T) {
	code, _, errs := run(t, "", "scan", "cluster", "--workload-selector", "tier in (", "--kubeconfig", "/nonexistent")
	if code != ExitUsage || !strings.Contains(errs, "invalid workload selector") {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
}
