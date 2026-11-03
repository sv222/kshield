//go:build kind

package kind

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/sv222/kshield/internal/cli"
	"github.com/sv222/kshield/internal/report"
)

const (
	toxicInput  = "../corpus/baseline/toxic/input.yaml"
	rayCRD      = "crds/ray.io_rayclusters.yaml"
	toxicNS     = "ai-inference"
	probeCheck  = "KS-PRE-004"
	hostLSM     = "lockdown,capability,landlock,yama,apparmor"
	probeBPFMsg = "bpf is not in the active LSM list (" + hostLSM + "); kernel has CONFIG_BPF_LSM=y, add bpf to the lsm= boot parameter"
)

type scanResult struct {
	Code   int
	Stdout string
	Stderr string
}

func runScan(t *testing.T, kubeconfigPath string, args ...string) scanResult {
	t.Helper()
	full := append([]string{"scan", "cluster", "--kubeconfig", kubeconfigPath}, args...)
	var stdout, stderr bytes.Buffer
	code := cli.Run(full, strings.NewReader(""), &stdout, &stderr)
	return scanResult{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
}

func decodeReport(t *testing.T, res scanResult) *report.Report {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil {
		t.Fatalf("scan output is not a JSON report: %v\nexit %d\nstderr: %s\nstdout: %.400s", err, res.Code, res.Stderr, res.Stdout)
	}
	return &r
}

func findingsOf(r *report.Report, id string) []report.Finding {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Findings
		}
	}
	return nil
}

func wantExit(t *testing.T, res scanResult, want int) {
	t.Helper()
	if res.Code != want {
		t.Fatalf("exit %d, want %d\nstderr: %s\nstdout: %.600s", res.Code, want, res.Stderr, res.Stdout)
	}
}

func installRayCRD(t *testing.T) {
	t.Helper()
	applyFile(t, rayCRD, nil)
}

func applyToxic(t *testing.T, ns string) {
	t.Helper()
	installRayCRD(t)
	applyFile(t, toxicInput, func(u *unstructured.Unstructured) {
		u.SetNamespace(ns)
		if u.GetKind() == "Deployment" {
			if err := unstructured.SetNestedField(u.Object, int64(0), "spec", "replicas"); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func fixedNamespace(t *testing.T, name string) {
	t.Helper()
	_, cs := clients(t)
	if _, err := cs.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := cs.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("delete namespace %s: %v", name, err)
		}
	})
}

func nodeName() string {
	return os.Getenv("KSHIELD_KIND_CLUSTER") + "-control-plane"
}

func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyDir(t *testing.T, src string, mutate func(name string, data []byte) []byte) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "pack")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data := mutate(e.Name(), readFileT(t, filepath.Join(src, e.Name())))
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}
