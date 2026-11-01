package scan

import (
	"cmp"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
)

func TestClusterDepsCoverClusterChecks(t *testing.T) {
	readSet := map[string]bool{}
	for _, gr := range cluster.ReadSet() {
		readSet[gr.Group+"/"+gr.Resource] = true
	}
	ids := map[string]bool{}
	for _, c := range check.All() {
		ids[c.ID] = true
		_, ok := clusterDeps[c.ID]
		switch {
		case c.Tier == check.Manifest && ok:
			t.Errorf("%s is Manifest tier and has a dependency entry", c.ID)
		case c.Tier != check.Manifest && !ok:
			t.Errorf("%s (tier %d) has no dependency entry", c.ID, c.Tier)
		}
	}
	for id, list := range clusterDeps {
		if !ids[id] {
			t.Errorf("dependency entry for unknown check %s", id)
		}
		if len(list) == 0 {
			t.Errorf("%s: empty dependency list", id)
		}
		for _, d := range list {
			if !readSet[d.group+"/"+d.resource] {
				t.Errorf("%s: %s/%s is not in the reader's read set", id, d.group, d.resource)
			}
		}
	}
}

func TestClusterDepsWorkloadKinds(t *testing.T) {
	want := []string{
		"/pods", "apps/deployments", "apps/statefulsets", "apps/daemonsets", "apps/replicasets",
		"batch/jobs", "batch/cronjobs", "ray.io/rayclusters", "ray.io/rayservices", "ray.io/rayjobs",
		"serving.kserve.io/inferenceservices", "serving.kserve.io/servingruntimes", "serving.kserve.io/clusterservingruntimes",
	}
	var got []string
	for _, d := range workloadDeps {
		got = append(got, d.group+"/"+d.resource)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("workload deps:\n got %q\nwant %q", got, want)
	}
}

func failRun(t *testing.T, opt ClusterOptions) *report.Report {
	t.Helper()
	opt.ProfileID, opt.Deterministic = "dora", true
	r, err := ClusterObjects(readObjects(t, vllmDeployment), nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func unknownIDs(r *report.Report) []string {
	var out []string
	for _, c := range r.Checks {
		if c.Verdict == report.VerdictUnknown {
			out = append(out, c.ID)
		}
	}
	return out
}

func assertUnknown(t *testing.T, r *report.Report, want ...string) {
	t.Helper()
	if got := unknownIDs(r); !slices.Equal(got, want) {
		t.Fatalf("UNKNOWN checks:\n got %q\nwant %q", got, want)
	}
}

func assertOthersUnchanged(t *testing.T, base, got *report.Report) {
	t.Helper()
	for i, c := range got.Checks {
		if c.Verdict == report.VerdictUnknown {
			continue
		}
		b := base.Checks[i]
		if c.ID != b.ID || c.Verdict != b.Verdict || len(c.Findings) != len(b.Findings) {
			t.Errorf("%s changed: %s %d findings, was %s %d", c.ID, c.Verdict, len(c.Findings), b.Verdict, len(b.Findings))
		}
	}
}

func TestFailedNetworkPoliciesMakesNetChecksUnknown(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	if v := checkByID(t, base, "KS-NET-001").Verdict; v != report.VerdictFail {
		t.Fatalf("baseline KS-NET-001 %s, want FAIL", v)
	}
	line := "cluster: list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: networkpolicies.networking.k8s.io is forbidden: RBAC: denied"
	r := failRun(t, ClusterOptions{
		Errors: []string{line},
		Failed: []cluster.FailedRead{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}},
	})
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002")
	assertOthersUnchanged(t, base, r)
	for _, id := range []string{"KS-NET-001", "KS-NET-002"} {
		c := checkByID(t, r, id)
		if len(c.Findings) != 1 {
			t.Fatalf("%s findings %+v", id, c.Findings)
		}
		f := c.Findings[0]
		if f.Object.String() != "Namespace/*" || f.Object.APIVersion != "v1" || f.Verdict != report.VerdictUnknown || f.Source != nil {
			t.Errorf("%s finding %+v", id, f)
		}
		want := "not judged: cannot list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: networkpolicies.networking.k8s.io is forbidden: RBAC: denied"
		if f.Message != want {
			t.Errorf("%s message %q, want %q", id, f.Message, want)
		}
	}
	if !slices.Equal(r.Errors, []string{line}) || !r.Summary.Incomplete || r.Summary.Unknown != 2 {
		t.Errorf("errors %v incomplete %v summary %+v", r.Errors, r.Summary.Incomplete, r.Summary)
	}
}

func TestFailedDaemonSetsMakesPrerequisiteChecksUnknown(t *testing.T) {
	line := "cluster: list apps/v1 daemonsets in all namespaces: Forbidden: no"
	r := failRun(t, ClusterOptions{
		Errors: []string{line},
		Failed: []cluster.FailedRead{{Group: "apps", Version: "v1", Resource: "daemonsets"}},
	})
	for _, id := range []string{"KS-PRE-001", "KS-PRE-002", "KS-NET-003"} {
		c := checkByID(t, r, id)
		if c.Verdict != report.VerdictUnknown || len(c.Findings) != 1 {
			t.Fatalf("%s: %s %+v", id, c.Verdict, c.Findings)
		}
		if m := c.Findings[0].Message; strings.Contains(m, "not found") || m != "not judged: cannot list apps/v1 daemonsets in all namespaces: Forbidden: no" {
			t.Errorf("%s message %q", id, m)
		}
	}
	for _, c := range check.All() {
		want := report.VerdictUnknown
		if c.Tier == check.Manifest {
			want = report.VerdictNA
		}
		if v := checkByID(t, r, c.ID).Verdict; v != want {
			t.Errorf("%s verdict %s, want %s (a DaemonSet can be a workload)", c.ID, v, want)
		}
	}
}

func TestFailedReadDropsFindings(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	if got := checkByID(t, base, "KS-NET-001").Findings; len(got) == 0 || got[0].Verdict != report.VerdictFail {
		t.Fatalf("baseline findings %+v", got)
	}
	r := failRun(t, ClusterOptions{
		Errors: []string{"cluster: list cilium.io/v2 ciliumnetworkpolicies in all namespaces: Forbidden: no"},
		Failed: []cluster.FailedRead{{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}},
	})
	c := checkByID(t, r, "KS-NET-001")
	if c.Verdict != report.VerdictUnknown || len(c.Findings) != 1 || c.Findings[0].Verdict != report.VerdictUnknown {
		t.Fatalf("KS-NET-001 %s %+v", c.Verdict, c.Findings)
	}
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002")
}

func TestFailedReadOneFindingPerRead(t *testing.T) {
	r := failRun(t, ClusterOptions{
		Errors: []string{
			"cluster: list cilium.io/v2 ciliumnetworkpolicies in ai: Forbidden: a",
			"cluster: list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: b",
			"cluster: list networking.k8s.io/v1 networkpolicies in ai: Forbidden: c",
		},
		Failed: []cluster.FailedRead{
			{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies", Namespace: "ai"},
			{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies", Namespace: "ai"},
			{Version: "v1", Resource: "services"},
		},
		Namespaces: []string{"ai"},
	})
	var got []string
	for _, f := range checkByID(t, r, "KS-NET-001").Findings {
		got = append(got, f.Object.String()+" | "+f.Message)
	}
	want := []string{
		"Namespace/* | not judged: cannot list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: b",
		"Namespace/ai | not judged: cannot list cilium.io/v2 ciliumnetworkpolicies in ai: Forbidden: a",
		"Namespace/ai | not judged: cannot list networking.k8s.io/v1 networkpolicies in ai: Forbidden: c",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got %q\nwant %q", got, want)
	}
}

func TestFailedGroupDiscoveryCountsForEveryResource(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	r := failRun(t, ClusterOptions{
		Errors: []string{"cluster: discover cilium.io/v2: ServiceUnavailable: down"},
		Failed: []cluster.FailedRead{{Group: "cilium.io", Version: "v2"}},
	})
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002", "KS-RT-001", "KS-RT-002")
	assertOthersUnchanged(t, base, r)
	if m := checkByID(t, r, "KS-RT-001").Findings[0].Message; m != "not judged: cannot list cilium.io/v2 * in all namespaces: ServiceUnavailable: down" {
		t.Errorf("message %q", m)
	}
}

func TestFailedReadNamespaceScope(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	r := failRun(t, ClusterOptions{
		Errors:     []string{"cluster: list networking.k8s.io/v1 networkpolicies in other: Forbidden: no"},
		Failed:     []cluster.FailedRead{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies", Namespace: "other"}},
		Namespaces: []string{"ai"},
	})
	assertUnknown(t, r)
	assertOthersUnchanged(t, base, r)

	r = failRun(t, ClusterOptions{
		Errors:     []string{"cluster: list networking.k8s.io/v1 networkpolicies in ai: Forbidden: no"},
		Failed:     []cluster.FailedRead{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies", Namespace: "ai"}},
		Namespaces: []string{"ai"},
	})
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002")
	if o := checkByID(t, r, "KS-NET-001").Findings[0].Object.String(); o != "Namespace/ai" {
		t.Errorf("object %s", o)
	}
}

func TestFailedCiliumConfigOutsideScope(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	r := failRun(t, ClusterOptions{
		Errors:     []string{`cluster: get v1 configmaps cilium-config in kube-system: Forbidden: no`},
		Failed:     []cluster.FailedRead{{Version: "v1", Resource: "configmaps", Namespace: "kube-system"}},
		Namespaces: []string{"ai"},
	})
	assertUnknown(t, r, "KS-NET-003")
	assertOthersUnchanged(t, base, r)
	f := checkByID(t, r, "KS-NET-003").Findings[0]
	if f.Object.String() != "Namespace/kube-system" || f.Message != "not judged: cannot get v1 configmaps in kube-system: Forbidden: no" {
		t.Errorf("finding %+v", f)
	}
}

func TestFailedNamespaceGetMakesAdmissionGuardUnknown(t *testing.T) {
	base := failRun(t, ClusterOptions{})
	r := failRun(t, ClusterOptions{
		Errors:     []string{`cluster: get v1 namespaces ai: Forbidden: no`},
		Failed:     []cluster.FailedRead{{Version: "v1", Resource: "namespaces", Namespace: "ai"}},
		Namespaces: []string{"ai"},
	})
	assertUnknown(t, r, "KS-RT-003")
	assertOthersUnchanged(t, base, r)
	if m := checkByID(t, r, "KS-RT-003").Findings[0].Message; m != "not judged: cannot get v1 namespaces in ai: Forbidden: no" {
		t.Errorf("message %q", m)
	}
}

func TestFailedReadWithoutErrorLine(t *testing.T) {
	r := failRun(t, ClusterOptions{
		Failed: []cluster.FailedRead{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, {Version: "v1", Resource: "secrets"}},
	})
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002")
	want := "cluster: list networking.k8s.io/v1 networkpolicies in all namespaces: read failed"
	if !slices.Equal(r.Errors, []string{want}) || !r.Summary.Incomplete {
		t.Fatalf("errors %v incomplete %v", r.Errors, r.Summary.Incomplete)
	}
	if m := checkByID(t, r, "KS-NET-001").Findings[0].Message; m != "not judged: cannot list networking.k8s.io/v1 networkpolicies in all namespaces: read failed" {
		t.Errorf("message %q", m)
	}
}

func TestFailedReadEveryUnknownHasErrorLine(t *testing.T) {
	failed := []cluster.FailedRead{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		{Group: "cilium.io", Version: "v2"},
		{Version: "v1", Resource: "namespaces", Namespace: "ai"},
		{Group: "apps", Version: "v1", Resource: "daemonsets"},
	}
	reasons := []string{"Forbidden: np", "ServiceUnavailable: cilium", "", "Forbidden: ds"}
	var given, want []string
	for i, f := range failed {
		reason := reasons[i]
		if reason == "" {
			reason = "read failed"
		} else {
			given = append(given, f.Prefix()+reason)
		}
		want = append(want, f.Prefix()+reason)
	}
	slices.Sort(want)
	r := failRun(t, ClusterOptions{Failed: failed, Errors: given})
	if !slices.Equal(r.Errors, want) {
		t.Fatalf("errors:\n got %q\nwant %q", r.Errors, want)
	}
	seen := 0
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Verdict != report.VerdictUnknown {
				continue
			}
			seen++
			if !slices.ContainsFunc(reasons, func(reason string) bool {
				return strings.HasSuffix(f.Message, ": "+cmp.Or(reason, "read failed"))
			}) {
				t.Errorf("%s: UNKNOWN %q matches no error line in %q", c.ID, f.Message, r.Errors)
			}
		}
	}
	if seen == 0 || !r.Summary.Incomplete {
		t.Errorf("unknown findings %d incomplete %v", seen, r.Summary.Incomplete)
	}
}

func prereqLists() []cluster.FailedRead {
	return []cluster.FailedRead{
		{Group: "apps", Version: "v1", Resource: "daemonsets"},
		{Group: "apps", Version: "v1", Resource: "deployments"},
	}
}

func TestFailedPrerequisiteListsWithNamespaces(t *testing.T) {
	scoped := ClusterOptions{Namespaces: []string{"ai"}}
	base := failRun(t, scoped)
	if v := checkByID(t, base, "KS-WL-001").Verdict; v != report.VerdictFail {
		t.Fatalf("baseline KS-WL-001 %s", v)
	}
	opt := scoped
	opt.Failed = prereqLists()
	opt.Errors = []string{
		"cluster: list apps/v1 daemonsets in all namespaces: Forbidden: ds",
		"cluster: list apps/v1 deployments in all namespaces: Forbidden: dep",
	}
	r := failRun(t, opt)
	assertUnknown(t, r, "KS-NET-003", "KS-PRE-001", "KS-PRE-002", "KS-PRE-003")
	assertOthersUnchanged(t, base, r)
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictFail {
		t.Errorf("KS-WL-001 %s, want FAIL", v)
	}
	if n := len(checkByID(t, r, "KS-NET-003").Findings); n != 1 {
		t.Errorf("KS-NET-003 findings %d, want 1 (daemonsets only)", n)
	}

	opt.Namespaces = nil
	r = failRun(t, opt)
	for _, c := range check.All() {
		if c.Tier != check.Manifest && checkByID(t, r, c.ID).Verdict != report.VerdictUnknown {
			t.Errorf("without -n, %s is %s, want UNKNOWN", c.ID, checkByID(t, r, c.ID).Verdict)
		}
	}
}

func TestFailedNamespacedWorkloadListWithNamespaces(t *testing.T) {
	r := failRun(t, ClusterOptions{
		Namespaces: []string{"ai"},
		Errors:     []string{"cluster: list apps/v1 daemonsets in ai: Forbidden: ds"},
		Failed:     []cluster.FailedRead{{Group: "apps", Version: "v1", Resource: "daemonsets", Namespace: "ai"}},
	})
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictUnknown {
		t.Errorf("KS-WL-001 %s, want UNKNOWN", v)
	}
}

const inferenceService = `apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: isvc
  namespace: ai
spec:
  predictor:
    containers:
      - name: kserve-container
        image: example.invalid/model:1
`

func TestFailedClusterServingRuntimesNeedsInferenceService(t *testing.T) {
	opt := ClusterOptions{
		Errors: []string{"cluster: list serving.kserve.io/v1alpha1 clusterservingruntimes in all namespaces: Forbidden: csr"},
		Failed: []cluster.FailedRead{{Group: "serving.kserve.io", Version: "v1alpha1", Resource: "clusterservingruntimes"}},
	}
	base := failRun(t, ClusterOptions{})
	r := failRun(t, opt)
	assertUnknown(t, r)
	assertOthersUnchanged(t, base, r)

	opt.ProfileID, opt.Deterministic = "dora", true
	r, err := ClusterObjects(readObjects(t, vllmDeployment, inferenceService), nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictUnknown {
		t.Errorf("KS-WL-001 with an InferenceService read: %s, want UNKNOWN", v)
	}
}

func TestFailedReadLeavesManifestTierNA(t *testing.T) {
	r := failRun(t, ClusterOptions{
		Errors: []string{"cluster: list v1 pods in all namespaces: Forbidden: no"},
		Failed: []cluster.FailedRead{{Version: "v1", Resource: "pods"}},
	})
	for _, c := range check.All() {
		v := checkByID(t, r, c.ID).Verdict
		if c.Tier == check.Manifest && v != report.VerdictNA {
			t.Errorf("%s verdict %s, want N/A", c.ID, v)
		}
		if c.Tier != check.Manifest && v != report.VerdictUnknown {
			t.Errorf("%s verdict %s, want UNKNOWN", c.ID, v)
		}
	}
}

func TestFailedReadNoAIWorkloadsStillUnknown(t *testing.T) {
	objs := []load.Object{}
	r, err := ClusterObjects(objs, nil, ClusterOptions{
		ProfileID: "dora", Deterministic: true,
		Errors: []string{"cluster: list v1 pods in all namespaces: Forbidden: no"},
		Failed: []cluster.FailedRead{{Version: "v1", Resource: "pods"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictUnknown {
		t.Errorf("KS-WL-001 %s, want UNKNOWN", v)
	}
}
