package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/cluster/clustertest"
)

type appliedPatch struct {
	resource, namespace, name string
	options                   metav1.PatchOptions
}

func recordPatches(c *clustertest.Cluster) *[]appliedPatch {
	var got []appliedPatch
	c.Dynamic.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pa := a.(clienttesting.PatchActionImpl)
		got = append(got, appliedPatch{pa.GetResource().Resource, pa.GetNamespace(), pa.GetName(), pa.PatchOptions})
		return true, &unstructured.Unstructured{Object: map[string]any{}}, nil
	})
	return &got
}

func withTerminal(t *testing.T, terminal bool) {
	t.Helper()
	old := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return terminal }
	t.Cleanup(func() { stdinIsTerminal = old })
}

func applyScan(t *testing.T) string {
	t.Helper()
	return remediateScan(t, "", "-f", writeManifest(t, "in.yaml", rootVLLMDeployment), "-n", "ai")
}

func applyRun(t *testing.T, stdin string, sj string, extra ...string) (int, string, string, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle")
	args := append([]string{"remediate", "--from", sj, "--out", out}, extra...)
	code, stdout, errs := run(t, stdin, args...)
	return code, stdout, errs, out
}

func patchNames(ps []appliedPatch) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.resource+"/"+p.namespace+"/"+p.name)
	}
	return out
}

func TestRemediateWithoutApplyDoesNotTouchTheCluster(t *testing.T) {
	c := clustertest.New()
	calls := useCluster(t, c)
	patches := recordPatches(c)
	code, _, errs, _ := applyRun(t, "", applyScan(t))
	if code != ExitOK || errs != "" || len(*calls) != 0 || len(*patches) != 0 {
		t.Fatalf("code=%d stderr=%q connects=%v patches=%v", code, errs, *calls, *patches)
	}
}

func TestRemediateApplyYesAppliesPoliciesOnly(t *testing.T) {
	c := clustertest.New()
	calls := useCluster(t, c)
	patches := recordPatches(c)
	code, stdout, errs, out := applyRun(t, "", applyScan(t), "--apply", "--yes", "--kubeconfig", "kc.yaml", "--context", "prod")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errs, stdout)
	}
	if !slices.Equal(*calls, []connectCall{{"kc.yaml", "prod"}}) {
		t.Errorf("connect calls %v", *calls)
	}
	want := []string{
		"ciliumnetworkpolicies/ai/kshield-egress",
		"tracingpoliciesnamespaced/ai/kshield-shell-exec",
		"tracingpoliciesnamespaced/ai/kshield-egress-connect",
		"policies/ai/kshield-admission",
	}
	if got := patchNames(*patches); !slices.Equal(got, want) {
		t.Fatalf("applied %q, want %q", got, want)
	}
	for _, p := range *patches {
		if p.options.FieldManager != "kshield" || p.options.Force != nil && *p.options.Force || len(p.options.DryRun) != 0 {
			t.Errorf("%s: options %+v", p.name, p.options)
		}
	}
	for _, line := range []string{
		`cluster: context "test-ctx", server ` + clustertest.Server,
		"apply CiliumNetworkPolicy/ai/kshield-egress (policy)",
		"workload patches are not applied (they restart pods): add --apply-patches to include them",
		"applied Policy/ai/kshield-admission",
	} {
		if !strings.Contains(stdout, line) {
			t.Errorf("stdout lacks %q:\n%s", line, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "kustomization.yaml")); err != nil {
		t.Errorf("the bundle was not written: %v", err)
	}
}

func TestRemediateApplyPatchesAddsTheWorkloads(t *testing.T) {
	c := clustertest.New()
	useCluster(t, c)
	patches := recordPatches(c)
	code, stdout, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--apply-patches", "--yes")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if got := patchNames(*patches); len(got) != 5 || got[0] != "deployments/ai/vllm" {
		t.Fatalf("applied %q", got)
	}
	if !strings.Contains(stdout, "workload patches are applied: the pods of the patched workloads restart") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

func TestRemediateApplyPrompt(t *testing.T) {
	cases := []struct {
		name    string
		answer  string
		code    int
		applied int
	}{
		{"yes", "y\n", ExitOK, 4},
		{"long yes", "YES\n", ExitOK, 4},
		{"no", "n\n", ExitUsage, 0},
		{"empty", "\n", ExitUsage, 0},
		{"end of input", "", ExitUsage, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := clustertest.New()
			useCluster(t, c)
			patches := recordPatches(c)
			withTerminal(t, true)
			code, stdout, errs, _ := applyRun(t, tc.answer, applyScan(t), "--apply")
			if code != tc.code || len(*patches) != tc.applied {
				t.Fatalf("code=%d applied=%d stderr=%q", code, len(*patches), errs)
			}
			if !strings.Contains(stdout, `Apply 4 objects to context "test-ctx"? [y/N] `) || !strings.Contains(stdout, "add --apply-patches") {
				t.Errorf("stdout:\n%s", stdout)
			}
			if tc.code == ExitUsage && !strings.Contains(errs, "nothing was applied") {
				t.Errorf("stderr %q", errs)
			}
		})
	}
}

func TestRemediateApplyWithoutTerminalNeedsYes(t *testing.T) {
	c := clustertest.New()
	useCluster(t, c)
	patches := recordPatches(c)
	withTerminal(t, false)
	code, stdout, errs, _ := applyRun(t, "y\n", applyScan(t), "--apply")
	if code != ExitUsage || len(*patches) != 0 || !strings.Contains(errs, "--yes") {
		t.Fatalf("code=%d applied=%d stderr=%q", code, len(*patches), errs)
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Errorf("prompted without a terminal:\n%s", stdout)
	}
}

func TestRemediateApplyDryRun(t *testing.T) {
	c := clustertest.New()
	useCluster(t, c)
	patches := recordPatches(c)
	withTerminal(t, false)
	code, stdout, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--dry-run")
	if code != ExitOK || errs != "" || len(*patches) != 4 {
		t.Fatalf("code=%d stderr=%q applied=%d", code, errs, len(*patches))
	}
	for _, p := range *patches {
		if !slices.Equal(p.options.DryRun, []string{metav1.DryRunAll}) {
			t.Errorf("%s: dry run %v", p.name, p.options.DryRun)
		}
	}
	if !strings.Contains(stdout, "dry run ok Policy/ai/kshield-admission") || strings.Contains(stdout, "\napplied ") || strings.Contains(stdout, "[y/N]") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

func clusterWithout(c *clustertest.Cluster, groups ...string) {
	lists := c.Discovery.Resources
	c.Discovery.Resources = nil
	for _, l := range lists {
		gv, _ := schema.ParseGroupVersion(l.GroupVersion)
		if !slices.Contains(groups, gv.Group) {
			c.Discovery.Resources = append(c.Discovery.Resources, l)
		}
	}
}

func TestRemediateApplyRefusesMissingCRDs(t *testing.T) {
	c := clustertest.New()
	clusterWithout(c, "kyverno.io", "cilium.io")
	useCluster(t, c)
	patches := recordPatches(c)
	code, _, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--yes")
	if code != ExitUsage || len(*patches) != 0 {
		t.Fatalf("code=%d applied=%d stderr=%q", code, len(*patches), errs)
	}
	for _, want := range []string{"kyverno.io/v1 Policy is not served by the cluster (is Kyverno installed?)", "cilium.io/v2 CiliumNetworkPolicy is not served by the cluster (is Cilium installed?)", "cilium.io/v1alpha1 TracingPolicyNamespaced is not served by the cluster (is Tetragon installed?)", "--skip-missing-crds"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
}

func TestRemediateApplySkipMissingCRDs(t *testing.T) {
	c := clustertest.New()
	clusterWithout(c, "kyverno.io")
	useCluster(t, c)
	patches := recordPatches(c)
	code, stdout, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--yes", "--skip-missing-crds")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if got := patchNames(*patches); len(got) != 3 || slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "policies/") }) {
		t.Errorf("applied %q", got)
	}
	if !strings.Contains(stdout, "skipping 1 object(s): kyverno.io/v1 Policy is not served by the cluster") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

func TestRemediateApplyConflictExitsWithApplyFailed(t *testing.T) {
	c := clustertest.New()
	useCluster(t, c)
	calls := 0
	c.Dynamic.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 2 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "x"}, "x", errors.New("owned by kubectl"))
		}
		return true, &unstructured.Unstructured{Object: map[string]any{}}, nil
	})
	code, stdout, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--yes")
	if code != ExitApplyFailed || calls != 2 {
		t.Fatalf("code=%d calls=%d stderr=%q", code, calls, errs)
	}
	if !strings.Contains(errs, "--force-conflicts") || !strings.Contains(stdout, "applied CiliumNetworkPolicy/ai/kshield-egress") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", stdout, errs)
	}
}

func TestRemediateApplyForceConflicts(t *testing.T) {
	c := clustertest.New()
	useCluster(t, c)
	patches := recordPatches(c)
	code, _, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--yes", "--force-conflicts")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	for _, p := range *patches {
		if p.options.Force == nil || !*p.options.Force {
			t.Errorf("%s: force not set", p.name)
		}
	}
}

func TestRemediateApplyFlagsNeedApply(t *testing.T) {
	useCluster(t, clustertest.New())
	sj := applyScan(t)
	for _, flag := range []string{"--apply-patches", "--yes", "--dry-run", "--force-conflicts", "--skip-missing-crds"} {
		code, stdout, errs, out := applyRun(t, "", sj, flag)
		if code != ExitUsage || stdout != "" || !strings.Contains(errs, "need --apply") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", flag, code, stdout, errs)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s wrote the bundle", flag)
		}
	}
}

func TestRemediateApplyConnectError(t *testing.T) {
	old := connect
	t.Cleanup(func() { connect = old })
	connect = func(string, string) (*cluster.Client, error) { return nil, errors.New("no such context") }
	code, _, errs, _ := applyRun(t, "", applyScan(t), "--apply", "--yes")
	if code != ExitUsage || !strings.Contains(errs, "no such context") {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
}

func TestRemediateApplyUsesTheScanContext(t *testing.T) {
	c := rootCluster()
	calls := useCluster(t, c)
	sj := scanClusterFile(t)
	patches := recordPatches(c)
	code, _, errs, _ := applyRun(t, "", sj, "--apply", "--yes")
	if code != ExitOK || len(*patches) == 0 {
		t.Fatalf("code=%d applied=%d stderr=%q", code, len(*patches), errs)
	}
	if last := (*calls)[len(*calls)-1]; last != (connectCall{"", clustertest.Context}) {
		t.Errorf("apply connected with %v", last)
	}
}
