//go:build kind

package kind

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/sv222/kshield/internal/cli"
)

const kshieldManager = "kshield"

var policyCRDFiles = []string{
	"../crds/cilium/ciliumnetworkpolicies.yaml",
	"../crds/tetragon/cilium.io_tracingpoliciesnamespaced.yaml",
	"../crds/kyverno/kyverno.io_policies.yaml",
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

func installCRDs(t *testing.T, files ...string) {
	t.Helper()
	dyn, _ := clients(t)
	for _, f := range files {
		applyFile(t, f, nil)
		for _, o := range readObjects(t, f) {
			name := o.GetName()
			t.Cleanup(func() { deleteCRD(t, dyn, name) })
		}
	}
}

func deleteCRD(t *testing.T, dyn dynamic.Interface, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := dyn.Resource(crdGVR).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("delete CRD %s: %v", name, err)
		return
	}
	for {
		_, err := dyn.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if ctx.Err() != nil {
			t.Errorf("CRD %s is still there after its deletion: %v", name, err)
			return
		}
		time.Sleep(time.Second)
	}
}

func installPolicyCRDs(t *testing.T) {
	t.Helper()
	installCRDs(t, policyCRDFiles...)
}

type remediateRun struct {
	code           int
	stdout, stderr string
}

func remediateApply(t *testing.T, kc, scanPath string, extra ...string) remediateRun {
	t.Helper()
	args := append([]string{"remediate", "--from", scanPath, "--kubeconfig", kc, "--out", filepath.Join(t.TempDir(), "bundle"), "--apply"}, extra...)
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, strings.NewReader(""), &stdout, &stderr)
	return remediateRun{code, stdout.String(), stderr.String()}
}

func writeScan(t *testing.T, kc, ns string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	wantExit(t, runScan(t, kc, "-n", ns, "--format", "json", "--deterministic", "--out", path), 1)
	return path
}

func liveObject(t *testing.T, gvk schema.GroupVersionKind, ns, name string) *unstructured.Unstructured {
	t.Helper()
	dyn, cs := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	mapping := restMapping(t, mapper, "live", gvk)
	u, err := dyn.Resource(mapping.Resource).Namespace(ns).Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s %s/%s: %v", gvk.Kind, ns, name, err)
	}
	return u
}

func managedBy(u *unstructured.Unstructured, manager string) bool {
	for _, mf := range u.GetManagedFields() {
		if mf.Manager == manager && mf.Operation == metav1.ManagedFieldsOperationApply {
			return true
		}
	}
	return false
}

func TestKindRemediateApplyPolicies(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)
	installPolicyCRDs(t)
	kc := kubeconfig(t)
	scanPath := writeScan(t, kc, ns)

	dry := remediateApply(t, kc, scanPath, "--mode", "enforce", "--dry-run")
	if dry.code != 0 || !strings.Contains(dry.stdout, "dry run ok CiliumNetworkPolicy/"+ns+"/kshield-egress") {
		t.Fatalf("dry run exit %d\nstderr: %s\nstdout: %s", dry.code, dry.stderr, dry.stdout)
	}
	dyn, cs := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	cnp := restMapping(t, mapper, "live", schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"})
	if _, err := dyn.Resource(cnp.Resource).Namespace(ns).Get(t.Context(), "kshield-egress", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("the dry run created the policy: %v", err)
	}

	res := remediateApply(t, kc, scanPath, "--mode", "enforce", "--yes")
	if res.code != 0 {
		t.Fatalf("apply exit %d\nstderr: %s\nstdout: %s", res.code, res.stderr, res.stdout)
	}
	for _, want := range []string{
		"applied CiliumNetworkPolicy/" + ns + "/kshield-egress",
		"applied TracingPolicyNamespaced/" + ns + "/kshield-shell-exec",
		"applied Policy/" + ns + "/kshield-admission",
		"workload patches are not applied",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, res.stdout)
		}
	}
	for _, o := range []struct {
		gvk  schema.GroupVersionKind
		name string
	}{
		{schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}, "kshield-egress"},
		{schema.GroupVersionKind{Group: "cilium.io", Version: "v1alpha1", Kind: "TracingPolicyNamespaced"}, "kshield-shell-exec"},
		{schema.GroupVersionKind{Group: "cilium.io", Version: "v1alpha1", Kind: "TracingPolicyNamespaced"}, "kshield-egress-connect"},
		{schema.GroupVersionKind{Group: "kyverno.io", Version: "v1", Kind: "Policy"}, "kshield-admission"},
	} {
		u := liveObject(t, o.gvk, ns, o.name)
		if !managedBy(u, kshieldManager) {
			t.Errorf("%s %s is not managed by %s: %v", o.gvk.Kind, o.name, kshieldManager, u.GetManagedFields())
		}
	}
	dep, err := cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dep.Spec.Template.Spec.Containers[0].SecurityContext != nil {
		t.Errorf("the policies-only apply changed the vllm Deployment: %+v", dep.Spec.Template.Spec.Containers[0].SecurityContext)
	}
	r := decodeReport(t, runScan(t, kc, "-n", ns, "--format", "json", "--deterministic"))
	for _, id := range []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003"} {
		for _, f := range findingsOf(r, id) {
			if id == "KS-RT-001" && f.Object.Kind == "RayCluster" {
				continue
			}
			t.Errorf("%s after the apply: %s %s: %s", id, f.Verdict, f.Object, f.Message)
		}
	}
}

func rootDeploymentWithRunAsNonRootFalse(t *testing.T, ns string) {
	t.Helper()
	applyFile(t, filepath.Join("testdata", "drift-root.yaml"), func(u *unstructured.Unstructured) {
		u.SetNamespace(ns)
		if u.GetKind() != "Deployment" {
			return
		}
		if err := unstructured.SetNestedField(u.Object, int64(0), "spec", "replicas"); err != nil {
			t.Fatal(err)
		}
		containers, _, err := unstructured.NestedSlice(u.Object, "spec", "template", "spec", "containers")
		if err != nil {
			t.Fatal(err)
		}
		containers[0].(map[string]any)["securityContext"] = map[string]any{"runAsNonRoot": false}
		if err := unstructured.SetNestedSlice(u.Object, containers, "spec", "template", "spec", "containers"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestKindRemediateApplyPatches(t *testing.T) {
	ns := tempNamespace(t, nil)
	installPolicyCRDs(t)
	rootDeploymentWithRunAsNonRootFalse(t, ns)
	kc := kubeconfig(t)
	scanPath := writeScan(t, kc, ns)
	_, cs := clients(t)

	conflict := remediateApply(t, kc, scanPath, "--apply-patches", "--yes")
	if conflict.code != cli.ExitApplyFailed || !strings.Contains(conflict.stderr, "--force-conflicts") || !strings.Contains(conflict.stderr, "nothing was applied") {
		t.Fatalf("apply without force: exit %d, want %d\nstderr: %s\nstdout: %s", conflict.code, cli.ExitApplyFailed, conflict.stderr, conflict.stdout)
	}
	dep, err := cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sc := dep.Spec.Template.Spec.Containers[0].SecurityContext; sc == nil || sc.RunAsNonRoot == nil || *sc.RunAsNonRoot {
		t.Fatalf("a refused apply changed the Deployment: %+v", sc)
	}

	res := remediateApply(t, kc, scanPath, "--apply-patches", "--force-conflicts", "--yes")
	if res.code != 0 {
		t.Fatalf("apply with force: exit %d\nstderr: %s\nstdout: %s", res.code, res.stderr, res.stdout)
	}
	dep, err = cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sc := dep.Spec.Template.Spec.Containers[0].SecurityContext; sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Errorf("the Deployment was not patched: %+v", sc)
	}
	u := liveObject(t, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, ns, "vllm")
	if !managedBy(u, kshieldManager) {
		t.Errorf("the Deployment is not managed by %s", kshieldManager)
	}
	r := decodeReport(t, runScan(t, kc, "-n", ns, "--format", "json", "--deterministic"))
	for _, f := range findingsOf(r, "KS-WL-001") {
		t.Errorf("KS-WL-001 after the patches: %s %s", f.Object, f.Message)
	}
}

func TestKindRemediateApplyRejectedPatchChangesNothing(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)
	installPolicyCRDs(t)
	kc := kubeconfig(t)
	scanPath := writeScan(t, kc, ns)
	_, cs := clients(t)

	res := remediateApply(t, kc, scanPath, "--apply-patches", "--force-conflicts", "--yes")
	if res.code != cli.ExitApplyFailed || !strings.Contains(res.stderr, "dry run failed, nothing was applied") {
		t.Fatalf("exit %d, want %d\nstderr: %s\nstdout: %s", res.code, cli.ExitApplyFailed, res.stderr, res.stdout)
	}
	for _, name := range []string{"vllm", "qdrant"} {
		dep, err := cs.AppsV1().Deployments(ns).Get(t.Context(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if sc := dep.Spec.Template.Spec.Containers[0].SecurityContext; sc != nil && sc.RunAsNonRoot != nil {
			t.Errorf("%s was changed by a refused apply: %+v", name, sc)
		}
	}
	dyn, _ := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	cnp := restMapping(t, mapper, "live", schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"})
	if _, err := dyn.Resource(cnp.Resource).Namespace(ns).Get(t.Context(), "kshield-egress", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a refused apply created a policy: %v", err)
	}
}

func TestKindHTTPRouteExposure(t *testing.T) {
	ns := tempNamespace(t, nil)
	installCRDs(t, "crds/gateway.networking.k8s.io_httproutes.yaml", "crds/gateway.envoyproxy.io_securitypolicies.yaml")
	applyFile(t, filepath.Join("testdata", "httproute.yaml"), func(u *unstructured.Unstructured) { u.SetNamespace(ns) })

	res := runScan(t, kubeconfig(t), "-n", ns, "--format", "json", "--deterministic")
	wantExit(t, res, 1)
	r := decodeReport(t, res)
	if len(r.Errors) > 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	got := map[string]string{}
	msgs := map[string]string{}
	for _, f := range findingsOf(r, "KS-AI-013") {
		got[f.Object.Name] = f.Verdict
		msgs[f.Object.Name] = f.Message
	}
	want := map[string]string{"open": "FAIL", "jwt": "INFO", "elsewhere": "WARN"}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("HTTPRoute %s: %q, want %s (%s)", name, got[name], v, msgs[name])
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings %v", got)
	}
	if !strings.Contains(msgs["jwt"], "SecurityPolicy "+ns+"/jwt") {
		t.Errorf("the jwt finding does not name the policy: %s", msgs["jwt"])
	}
}
