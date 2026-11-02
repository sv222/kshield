package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/cluster/clustertest"
)

func scanClusterFile(t *testing.T, args ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scan.json")
	code, _, errs := run(t, "", append([]string{"scan", "cluster", "--format", "json", "--deterministic", "--out", out}, args...)...)
	if code != ExitFindings && code != ExitOK {
		t.Fatalf("scan cluster: code=%d stderr=%q", code, errs)
	}
	return out
}

func rootCluster() *clustertest.Cluster {
	return clustertest.New(clustertest.Object("v1", "Namespace", "", "ai"), clustertest.RootVLLM("ai"))
}

func TestRemediateFromCluster(t *testing.T) {
	c := rootCluster()
	calls := useCluster(t, c)
	sj := scanClusterFile(t)
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errs := run(t, "", "remediate", "--from", sj, "--out", out)
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if want := (connectCall{"", clustertest.Context}); (*calls)[len(*calls)-1] != want {
		t.Errorf("connect calls %v, want the last to be %v", *calls, want)
	}
	if !strings.Contains(stdout, filepath.ToSlash(filepath.Join(out, "base/manifests.yaml"))) {
		t.Errorf("stdout lacks base/manifests.yaml:\n%s", stdout)
	}
	base, err := os.ReadFile(filepath.Join(out, "base", "manifests.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(base), "kind: Deployment") || strings.Contains(string(base), "uid:") {
		t.Errorf("base:\n%s", base)
	}
}

func TestRemediateFromClusterFlags(t *testing.T) {
	useCluster(t, rootCluster())
	sj := scanClusterFile(t)
	calls := useCluster(t, rootCluster())
	out := filepath.Join(t.TempDir(), "bundle")
	code, _, errs := run(t, "", "remediate", "--from", sj, "--out", out, "--kubeconfig", "kc.yaml", "--context", "prod")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if !slices.Equal(*calls, []connectCall{{"kc.yaml", "prod"}}) {
		t.Errorf("connect calls %v", *calls)
	}
}

func TestRemediateFromClusterUsesScanNamespaces(t *testing.T) {
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "ai"),
		clustertest.Object("v1", "Namespace", "", "other"),
		clustertest.RootVLLM("ai"),
	)
	useCluster(t, c)
	sj := scanClusterFile(t, "-n", "ai")
	c.Dynamic.ClearActions()
	code, _, errs := run(t, "", "remediate", "--from", sj, "--out", filepath.Join(t.TempDir(), "bundle"))
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	listed := 0
	for _, a := range c.Dynamic.Actions() {
		if a.GetVerb() != "list" || a.GetResource().Resource != "pods" {
			continue
		}
		listed++
		if a.GetNamespace() != "ai" {
			t.Errorf("pods listed in namespace %q, want ai", a.GetNamespace())
		}
	}
	if listed == 0 {
		t.Error("the re-scan listed no pods")
	}
}

func TestClusterRefusesFiles(t *testing.T) {
	useCluster(t, rootCluster())
	sj := scanClusterFile(t)
	calls := useCluster(t, rootCluster())
	in := writeManifest(t, "in.yaml", rootVLLMDeployment)
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errs := run(t, "", "remediate", "--from", sj, "-f", in, "--out", out)
	if code != ExitUsage || stdout != "" || !strings.Contains(errs, "remediate: a cluster scan cannot be matched to files; scan the files with scan manifest") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, errs)
	}
	if len(*calls) != 0 {
		t.Errorf("connected despite the refusal: %v", *calls)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("the refusal wrote the bundle dir")
	}
	code, _, errs = run(t, "", "remediate", "--from", sj, "-n", "ai", "--out", out)
	if code != ExitUsage || !strings.Contains(errs, "-n does not apply") {
		t.Fatalf("-n: code=%d stderr=%q", code, errs)
	}
}

func TestClusterIncompleteRescan(t *testing.T) {
	useCluster(t, rootCluster())
	sj := scanClusterFile(t)
	c := rootCluster()
	c.Dynamic.PrependReactor("list", "networkpolicies", forbiddenList("networkpolicies"))
	useCluster(t, c)
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errs := run(t, "", "remediate", "--from", sj, "--out", out)
	if code != ExitIncomplete || stdout != "" || !strings.Contains(errs, "re-scan is incomplete") || !strings.Contains(errs, "networkpolicies") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, errs)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an incomplete re-scan wrote the bundle dir")
	}
}

func TestClusterMismatch(t *testing.T) {
	useCluster(t, rootCluster())
	sj := scanClusterFile(t)
	useCluster(t, clustertest.New(clustertest.Object("v1", "Namespace", "", "other"), clustertest.RootVLLM("other")))
	out := filepath.Join(t.TempDir(), "bundle")
	code, stdout, errs := run(t, "", "remediate", "--from", sj, "--out", out)
	if code != ExitUsage || stdout != "" || !strings.Contains(errs, "does not match") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, errs)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a mismatch wrote the bundle dir")
	}
}

func TestRemediateClusterFlagsNeedClusterScan(t *testing.T) {
	calls := useCluster(t, rootCluster())
	sj := remediateScan(t, "", "-f", writeManifest(t, "in.yaml", rootVLLMDeployment), "-n", "ai")
	for _, flag := range []string{"--kubeconfig", "--context"} {
		code, stdout, errs := run(t, "", "remediate", "--from", sj, flag, "x", "--out", filepath.Join(t.TempDir(), "bundle"))
		if code != ExitUsage || stdout != "" || !strings.Contains(errs, "cluster scan") {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", flag, code, stdout, errs)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("connected for a manifest scan: %v", *calls)
	}
}
