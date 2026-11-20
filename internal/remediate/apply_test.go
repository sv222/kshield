package remediate

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryfake "k8s.io/client-go/discovery/fake"
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
