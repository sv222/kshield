package remediate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/kshield/internal/cluster/clustertest"
)

func toxicBundle(t *testing.T, mode string) *Bundle {
	t.Helper()
	t.Chdir("../..")
	b, err := Run(Options{ScanJSON: scanJSON(t, "ai-inference", toxicInput), Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func labels(objs []ApplyObject) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = o.Role + " " + o.Label()
	}
	return out
}

func TestPlanApplyPoliciesOnly(t *testing.T) {
	b := toxicBundle(t, "audit")
	objs, err := PlanApply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"policy CiliumNetworkPolicy/ai-inference/kshield-egress",
		"policy TracingPolicyNamespaced/ai-inference/kshield-shell-exec",
		"policy TracingPolicyNamespaced/ai-inference/kshield-egress-connect",
		"policy Policy/ai-inference/kshield-admission",
	}
	if got := labels(objs); !slices.Equal(got, want) {
		t.Fatalf("objects:\n got %q\nwant %q", got, want)
	}
}

func TestPlanApplyWithPatchesAddsOnlyPatchedWorkloads(t *testing.T) {
	b := toxicBundle(t, "audit")
	objs, err := PlanApply(b, true)
	if err != nil {
		t.Fatal(err)
	}
	var workloads []string
	for _, o := range objs {
		if o.Role == RoleWorkload {
			workloads = append(workloads, o.Label())
		}
	}
	want := []string{"Deployment/ai-inference/qdrant", "Deployment/ai-inference/vllm", "RayCluster/ai-inference/rc"}
	slices.Sort(workloads)
	if !slices.Equal(workloads, want) {
		t.Fatalf("workloads %q, want %q", workloads, want)
	}
	if len(objs) != len(want)+4 {
		t.Errorf("%d objects, want %d", len(objs), len(want)+4)
	}
	for _, o := range objs[:len(want)] {
		if o.Role != RoleWorkload {
			t.Errorf("workloads must come first: %v", labels(objs))
		}
	}
}

func TestPlanApplyPatchedWorkloadCarriesThePatch(t *testing.T) {
	b := toxicBundle(t, "audit")
	objs, err := PlanApply(b, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		if o.Label() != "Deployment/ai-inference/vllm" {
			continue
		}
		containers, _ := o.Object.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
		sc, _ := containers[0].(map[string]any)["securityContext"].(map[string]any)
		if sc["runAsNonRoot"] != true {
			t.Fatalf("vllm container securityContext %v lacks the patch", sc)
		}
		return
	}
	t.Fatal("vllm is not in the plan")
}

func TestPlanApplyEmptyBundle(t *testing.T) {
	objs, err := PlanApply(&Bundle{Files: map[string][]byte{FilePolicies: nil}}, false)
	if err != nil || len(objs) != 0 {
		t.Fatalf("objects %v err %v", labels(objs), err)
	}
}

func TestPlanApplyBadPolicies(t *testing.T) {
	if _, err := PlanApply(&Bundle{Files: map[string][]byte{FilePolicies: []byte("a: [unterminated")}}, false); err == nil {
		t.Fatal("expected an error")
	}
}

func discoveryWith(kinds ...clustertest.Kind) *discoveryfake.FakeDiscovery {
	var lists []*metav1.APIResourceList
	for _, k := range kinds {
		i := slices.IndexFunc(lists, func(l *metav1.APIResourceList) bool { return l.GroupVersion == k.APIVersion() })
		if i < 0 {
			lists = append(lists, &metav1.APIResourceList{GroupVersion: k.APIVersion()})
			i = len(lists) - 1
		}
		lists[i].APIResources = append(lists[i].APIResources, metav1.APIResource{Name: k.Resource, Kind: k.Kind, Namespaced: k.Namespaced})
	}
	return &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}
}

func kindsWithout(skip ...string) []clustertest.Kind {
	var out []clustertest.Kind
	for _, k := range clustertest.Kinds {
		if !slices.Contains(skip, k.Group) && !slices.Contains(skip, k.Kind) {
			out = append(out, k)
		}
	}
	return out
}

func TestResolveFindsResourcesAndScope(t *testing.T) {
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	found, missing, err := Resolve(discoveryWith(clustertest.Kinds...), objs)
	if err != nil || len(missing) != 0 || len(found) != len(objs) {
		t.Fatalf("found %d missing %v err %v", len(found), missing, err)
	}
	byLabel := map[string]ApplyObject{}
	for _, o := range found {
		byLabel[o.Label()] = o
	}
	cnp := byLabel["CiliumNetworkPolicy/ai-inference/kshield-egress"]
	if cnp.Resource.Resource != "ciliumnetworkpolicies" || cnp.Resource.Version != "v2" || !cnp.Namespaced {
		t.Errorf("CiliumNetworkPolicy resolved to %+v", cnp)
	}
}

func TestResolveReportsEveryMissingKind(t *testing.T) {
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	found, missing, err := Resolve(discoveryWith(kindsWithout("kyverno.io", "TracingPolicyNamespaced")...), objs)
	if err != nil {
		t.Fatal(err)
	}
	if got := labels(found); !slices.Equal(got, []string{"policy CiliumNetworkPolicy/ai-inference/kshield-egress"}) {
		t.Errorf("found %q", got)
	}
	var got []string
	for _, m := range missing {
		got = append(got, m.APIVersion+" "+m.Kind+" "+m.Product+" "+strconv.Itoa(len(m.Objects)))
	}
	want := []string{
		"cilium.io/v1alpha1 TracingPolicyNamespaced Tetragon 2",
		"kyverno.io/v1 Policy Kyverno 1",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("missing %q, want %q", got, want)
	}
}

func TestResolveMissingCiliumNamesCilium(t *testing.T) {
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	_, missing, err := Resolve(discoveryWith(kindsWithout("CiliumNetworkPolicy")...), objs)
	if err != nil || len(missing) != 1 || missing[0].Product != "Cilium" {
		t.Fatalf("missing %+v err %v", missing, err)
	}
}

func TestResolveKeepsAKindMissingFromAServedGroup(t *testing.T) {
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	_, missing, err := Resolve(discoveryWith(kindsWithout("Policy")...), objs)
	if err != nil || len(missing) != 1 || missing[0].Kind != "Policy" {
		t.Fatalf("missing %+v err %v", missing, err)
	}
}

type failingDiscovery struct {
	*discoveryfake.FakeDiscovery
}

func (failingDiscovery) ServerResourcesForGroupVersion(string) (*metav1.APIResourceList, error) {
	return nil, errors.New("connection refused")
}

func TestResolveDiscoveryError(t *testing.T) {
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(failingDiscovery{discoveryWith(clustertest.Kinds...)}, objs); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err %v", err)
	}
}

type recordedPatch struct {
	resource  string
	namespace string
	name      string
	patchType types.PatchType
	options   metav1.PatchOptions
}

func applyFixture(t *testing.T) (*dynamicfake.FakeDynamicClient, *[]recordedPatch, []ApplyObject) {
	t.Helper()
	objs, err := PlanApply(toxicBundle(t, "audit"), false)
	if err != nil {
		t.Fatal(err)
	}
	found, missing, err := Resolve(discoveryWith(clustertest.Kinds...), objs)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing %v err %v", missing, err)
	}
	listKinds := map[schema.GroupVersionResource]string{}
	for _, k := range clustertest.Kinds {
		listKinds[k.GVR()] = k.Kind + "List"
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	var patches []recordedPatch
	client.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pa := a.(clienttesting.PatchActionImpl)
		patches = append(patches, recordedPatch{pa.GetResource().Resource, pa.GetNamespace(), pa.GetName(), pa.GetPatchType(), pa.PatchOptions})
		return true, &unstructured.Unstructured{Object: map[string]any{}}, nil
	})
	return client, &patches, found
}

func TestRunApplyUsesServerSideApply(t *testing.T) {
	client, patches, objs := applyFixture(t)
	var out bytes.Buffer
	if err := RunApply(context.Background(), client, objs, ApplyOptions{}, &out); err != nil {
		t.Fatal(err)
	}
	if len(*patches) != len(objs) {
		t.Fatalf("%d patches, want %d", len(*patches), len(objs))
	}
	for i, p := range *patches {
		if p.patchType != types.ApplyPatchType || p.options.FieldManager != "kshield" || p.options.Force != nil && *p.options.Force || len(p.options.DryRun) != 0 {
			t.Errorf("patch %d: %+v", i, p)
		}
		if p.namespace != "ai-inference" || p.name != objs[i].Object.GetName() {
			t.Errorf("patch %d targets %s/%s", i, p.namespace, p.name)
		}
	}
	for _, want := range []string{"applied CiliumNetworkPolicy/ai-inference/kshield-egress", "applied Policy/ai-inference/kshield-admission"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRunApplyForceConflicts(t *testing.T) {
	client, patches, objs := applyFixture(t)
	if err := RunApply(context.Background(), client, objs, ApplyOptions{ForceConflicts: true}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, p := range *patches {
		if p.options.Force == nil || !*p.options.Force {
			t.Errorf("%s: force not set: %+v", p.name, p.options)
		}
	}
}

func TestRunApplyDryRun(t *testing.T) {
	client, patches, objs := applyFixture(t)
	var out bytes.Buffer
	if err := RunApply(context.Background(), client, objs, ApplyOptions{DryRun: true}, &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range *patches {
		if !slices.Equal(p.options.DryRun, []string{metav1.DryRunAll}) {
			t.Errorf("%s: dry run %v", p.name, p.options.DryRun)
		}
	}
	if !strings.Contains(out.String(), "dry run ok CiliumNetworkPolicy/ai-inference/kshield-egress") || strings.Contains(out.String(), "applied") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestRunApplyStopsAtAConflict(t *testing.T) {
	client, patches, objs := applyFixture(t)
	calls := 0
	client.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 2 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "kyverno.io", Resource: "policies"}, "x", errors.New("field owned by kubectl"))
		}
		return false, nil, nil
	})
	var out bytes.Buffer
	err := RunApply(context.Background(), client, objs, ApplyOptions{}, &out)
	var ae *ApplyError
	if !errors.As(err, &ae) {
		t.Fatalf("err %v", err)
	}
	if ae.Applied != 1 || !ae.Conflict || ae.Object.Label() != objs[1].Label() {
		t.Errorf("apply error %+v", ae)
	}
	if !strings.Contains(err.Error(), "--force-conflicts") || !strings.Contains(err.Error(), objs[1].Label()) {
		t.Errorf("message %q", err)
	}
	if len(*patches) != 1 {
		t.Errorf("%d objects applied after the conflict", len(*patches))
	}
}

func TestRunApplyOtherErrorHasNoForceHint(t *testing.T) {
	client, _, objs := applyFixture(t)
	client.PrependReactor("patch", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "policies"}, "x", errors.New("RBAC: denied"))
	})
	err := RunApply(context.Background(), client, objs, ApplyOptions{}, io.Discard)
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.Conflict || ae.Applied != 0 || strings.Contains(err.Error(), "--force-conflicts") {
		t.Fatalf("err %v", err)
	}
}

func TestRunApplyClusterScopedObject(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	var got []recordedPatch
	client.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pa := a.(clienttesting.PatchActionImpl)
		got = append(got, recordedPatch{pa.GetResource().Resource, pa.GetNamespace(), pa.GetName(), pa.GetPatchType(), pa.PatchOptions})
		return true, &unstructured.Unstructured{Object: map[string]any{}}, nil
	})
	obj := ApplyObject{
		Role:     RolePolicy,
		Object:   &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicy", "metadata": map[string]any{"name": "tp"}}},
		Resource: schema.GroupVersionResource{Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpolicies"},
	}
	if err := RunApply(context.Background(), client, []ApplyObject{obj}, ApplyOptions{}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].namespace != "" || got[0].resource != "tracingpolicies" {
		t.Errorf("patches %+v", got)
	}
}
