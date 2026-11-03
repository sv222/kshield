package check

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

func ref(kind, ns, name string) load.ObjectRef {
	return load.ObjectRef{APIVersion: "v1", Kind: kind, Namespace: ns, Name: name}
}

func withCatalog(t *testing.T, cs []Check) {
	t.Helper()
	saved := catalog
	catalog = cs
	t.Cleanup(func() { catalog = saved })
}

func TestTierValues(t *testing.T) {
	if Manifest != 1 || Cluster != 2 || Both != 3 {
		t.Fatalf("Manifest=%d Cluster=%d Both=%d", Manifest, Cluster, Both)
	}
	if Both != Manifest|Cluster {
		t.Fatal("Both must be Manifest|Cluster")
	}
}

func TestFixValues(t *testing.T) {
	if FixPatch != "patch" || FixPolicy != "policy" || FixManual != "manual" {
		t.Fatalf("%q %q %q", FixPatch, FixPolicy, FixManual)
	}
}

func TestStrengthValues(t *testing.T) {
	if Violation != 0 || Suspect != 1 || Unknown != 2 {
		t.Fatalf("Violation=%d Suspect=%d Unknown=%d", Violation, Suspect, Unknown)
	}
}

func TestEvaluateClusterOnlyIsNA(t *testing.T) {
	c := Check{ID: "KS-T-001", Tier: Cluster, Run: func(*Input) Result { t.Fatal("must not run"); return Result{} }}
	if r := Evaluate(c, &Input{}); r.Applicable {
		t.Fatal("cluster-only check must be N/A in a manifest scan")
	}
}

func TestEvaluateClusterOnlyNAHasNoFindings(t *testing.T) {
	c := Check{ID: "KS-T-001", Tier: Cluster, Run: func(*Input) Result {
		return Result{Applicable: true, Findings: []Finding{{Message: "x"}}}
	}}
	r := Evaluate(c, &Input{})
	if r.Applicable || r.Findings != nil {
		t.Fatalf("got %+v", r)
	}
}

func TestEvaluateRunsWhereApplicable(t *testing.T) {
	facts := &ClusterFacts{}
	cases := []struct {
		name    string
		tier    Tier
		cluster *ClusterFacts
		runs    bool
	}{
		{"manifest without cluster", Manifest, nil, true},
		{"manifest with cluster", Manifest, facts, false},
		{"both without cluster", Both, nil, true},
		{"both with cluster", Both, facts, true},
		{"cluster without cluster", Cluster, nil, false},
		{"cluster with cluster", Cluster, facts, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			c := Check{ID: "KS-T-001", Tier: tc.tier, Run: func(*Input) Result {
				ran = true
				return Result{Applicable: true}
			}}
			r := Evaluate(c, &Input{Cluster: tc.cluster})
			if ran != tc.runs || r.Applicable != tc.runs {
				t.Fatalf("ran=%v applicable=%v want %v", ran, r.Applicable, tc.runs)
			}
		})
	}
}

func TestEvaluateManifestTierNAInCluster(t *testing.T) {
	doc := deployment(vllmPod(`"--model", "m", "--trust-remote-code"`))
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := ByID("KS-AI-002")
	if !ok || c.Tier != Manifest {
		t.Fatalf("KS-AI-002 registered=%v tier=%d, want Manifest", ok, c.Tier)
	}
	if r := Evaluate(c, &Input{Objects: objs, Workloads: ws}); !r.Applicable || len(r.Findings) != 1 {
		t.Fatalf("manifest scan: got %+v, want one finding", r)
	}
	r := Evaluate(c, &Input{Objects: objs, Workloads: ws, Cluster: &ClusterFacts{}})
	if r.Applicable || r.Findings != nil {
		t.Fatalf("cluster scan: got %+v, want N/A", r)
	}
}

func TestEvaluatePassesInput(t *testing.T) {
	in := &Input{Objects: []load.Object{{Ref: ref("Pod", "a", "p")}}}
	var got *Input
	c := Check{ID: "KS-T-001", Tier: Manifest, Run: func(i *Input) Result { got = i; return Result{Applicable: true} }}
	Evaluate(c, in)
	if got != in {
		t.Fatal("Run must receive the same input")
	}
}

func TestEvaluateKeepsNotApplicableFromRun(t *testing.T) {
	c := Check{ID: "KS-T-001", Tier: Manifest, Run: func(*Input) Result { return Result{} }}
	if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestEvaluateSortsFindings(t *testing.T) {
	a := ref("Deployment", "a", "x")
	b := ref("Deployment", "b", "x")
	unsorted := []Finding{
		{Object: b, Group: "g", Path: "/p", Container: "c", Message: "m"},
		{Object: a, Group: "g", Path: "/p", Container: "c", Message: "m"},
	}
	r := Evaluate(Check{Tier: Manifest, Run: func(*Input) Result {
		return Result{Applicable: true, Findings: slices.Clone(unsorted)}
	}}, &Input{})
	if r.Findings[0].Object != a || r.Findings[1].Object != b {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestEvaluateSortKeys(t *testing.T) {
	base := Finding{Object: ref("Pod", "n", "p"), Group: "g2", Path: "/p2", Container: "c2", Message: "m2"}
	vary := func(f func(*Finding)) Finding {
		x := base
		f(&x)
		return x
	}
	cases := []struct {
		name         string
		first, later Finding
	}{
		{"object", vary(func(f *Finding) { f.Object = ref("Pod", "n", "a") }), vary(func(f *Finding) { f.Object = ref("Pod", "n", "z") })},
		{"object string not fields", vary(func(f *Finding) { f.Object = ref("Pod", "a", "a") }), vary(func(f *Finding) { f.Object = ref("Pod", "", "z") })},
		{"group", vary(func(f *Finding) { f.Group = "g1" }), base},
		{"path", vary(func(f *Finding) { f.Path = "/p1" }), base},
		{"container", vary(func(f *Finding) { f.Container = "c1" }), base},
		{"message", vary(func(f *Finding) { f.Message = "m1" }), base},
		{"strength", base, vary(func(f *Finding) { f.Strength = Suspect })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, in := range [][]Finding{{tc.first, tc.later}, {tc.later, tc.first}} {
				r := Evaluate(Check{Tier: Manifest, Run: func(*Input) Result {
					return Result{Applicable: true, Findings: slices.Clone(in)}
				}}, &Input{})
				want := []Finding{tc.first, tc.later}
				if !reflect.DeepEqual(r.Findings, want) {
					t.Fatalf("got %+v want %+v", r.Findings, want)
				}
			}
		})
	}
}

func TestEvaluateSortPrecedence(t *testing.T) {
	o1 := ref("Pod", "n", "a")
	o2 := ref("Pod", "n", "b")
	want := []Finding{
		{Object: o1, Group: "a", Path: "/z", Container: "z", Message: "z"},
		{Object: o1, Group: "b", Path: "/a", Container: "a", Message: "a"},
		{Object: o1, Group: "b", Path: "/b", Container: "a", Message: "a"},
		{Object: o1, Group: "b", Path: "/b", Container: "b", Message: "a"},
		{Object: o1, Group: "b", Path: "/b", Container: "b", Message: "b"},
		{Object: o2, Group: "a", Path: "/a", Container: "a", Message: "a"},
	}
	shuffled := []Finding{want[4], want[0], want[5], want[2], want[1], want[3]}
	r := Evaluate(Check{Tier: Manifest, Run: func(*Input) Result {
		return Result{Applicable: true, Findings: slices.Clone(shuffled)}
	}}, &Input{})
	if !reflect.DeepEqual(r.Findings, want) {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestAIWorkloads(t *testing.T) {
	ai1 := model.Workload{Owner: ref("Deployment", "a", "ai1"), Stacks: []model.Stack{model.VLLM}}
	plain := model.Workload{Owner: ref("Deployment", "a", "plain")}
	ai2 := model.Workload{Owner: ref("RayCluster", "a", "ai2"), Stacks: []model.Stack{model.Ray}}
	in := &Input{Workloads: []model.Workload{ai1, plain, ai2}}
	got := AIWorkloads(in)
	if len(got) != 2 || got[0].Owner != ai1.Owner || got[1].Owner != ai2.Owner {
		t.Fatalf("got %+v", got)
	}
}

func TestAIWorkloadsNone(t *testing.T) {
	in := &Input{Workloads: []model.Workload{{Owner: ref("Deployment", "a", "plain")}}}
	if got := AIWorkloads(in); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	if got := AIWorkloads(&Input{}); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestAllAndByID(t *testing.T) {
	noop := func(*Input) Result { return Result{} }
	withCatalog(t, []Check{
		{ID: "KS-T-002", Title: "second", Tier: Manifest, Fix: FixPatch, Run: noop},
		{ID: "KS-T-001", Title: "first", Tier: Cluster, Fix: FixManual, Run: noop},
	})
	all := All()
	if len(all) != 2 || all[0].ID != "KS-T-002" || all[1].ID != "KS-T-001" {
		t.Fatalf("All must keep catalog order, got %+v", all)
	}
	all[0].ID = "mutated"
	if All()[0].ID != "KS-T-002" {
		t.Fatal("All must return a copy")
	}
	c, ok := ByID("KS-T-001")
	if !ok || c.Title != "first" || c.Tier != Cluster || c.Fix != FixManual {
		t.Fatalf("got %+v ok=%v", c, ok)
	}
	if _, ok := ByID("KS-T-999"); ok {
		t.Fatal("unknown id must not be found")
	}
	if _, ok := ByID(""); ok {
		t.Fatal("empty id must not be found")
	}
}

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if c.ID == "" {
			t.Fatalf("check with empty ID: %+v", c)
		}
		if seen[c.ID] {
			t.Fatalf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" {
			t.Errorf("%s: empty title", c.ID)
		}
		if strings.ContainsAny(c.Title, "`") || strings.Contains(c.Title, "section") || strings.Contains(c.Title, "always FAIL") {
			t.Errorf("%s: title %q carries markdown or a spec cross-reference", c.ID, c.Title)
		}
		if c.Run == nil {
			t.Errorf("%s: nil Run", c.ID)
		}
		if c.Tier != Manifest && c.Tier != Cluster && c.Tier != Both {
			t.Errorf("%s: invalid tier %d", c.ID, c.Tier)
		}
		if c.Fix != FixPatch && c.Fix != FixPolicy && c.Fix != FixManual {
			t.Errorf("%s: invalid fix %q", c.ID, c.Fix)
		}
	}
}
