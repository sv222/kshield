package remediate

import (
	"slices"
	"testing"
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
