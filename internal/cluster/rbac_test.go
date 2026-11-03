package cluster

import (
	"maps"
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func readRBAC[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := yaml.UnmarshalStrict(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func grants(t *testing.T, rules []rbacv1.PolicyRule) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, r := range rules {
		if len(r.ResourceNames) > 0 || len(r.NonResourceURLs) > 0 {
			t.Errorf("rule %+v: resourceNames or nonResourceURLs", r)
		}
		verbs := slices.Sorted(slices.Values(r.Verbs))
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				key := g + "/" + res
				if _, dup := out[key]; dup {
					t.Errorf("%s granted twice", key)
				}
				out[key] = verbs
			}
		}
	}
	return out
}

func TestRBACMatchesReadSet(t *testing.T) {
	role := readRBAC[rbacv1.ClusterRole](t, "../../deploy/rbac/kshield-scan.yaml")
	if role.APIVersion != "rbac.authorization.k8s.io/v1" || role.Kind != "ClusterRole" || role.Name != "kshield-scan" || role.Namespace != "" {
		t.Fatalf("header %s %s %s/%s", role.APIVersion, role.Kind, role.Namespace, role.Name)
	}
	if role.AggregationRule != nil {
		t.Fatal("aggregationRule set")
	}
	want := map[string][]string{"/secrets": {"get"}, "/nodes": {"list"}}
	for _, r := range readSet {
		want[r.Group+"/"+r.Resource] = []string{"get", "list"}
	}
	got := grants(t, role.Rules)
	assertGrants(t, got, want)
	for k, verbs := range got {
		for _, v := range verbs {
			if v != "get" && v != "list" {
				t.Errorf("%s: verb %s", k, v)
			}
		}
	}
}

func assertGrants(t *testing.T, got, want map[string][]string) {
	t.Helper()
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if !slices.Equal(got[k], want[k]) {
			t.Errorf("%s: verbs %v, want %v", k, got[k], want[k])
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: granted %v, not in the read set", k, got[k])
		}
	}
}

func TestRBACNodeProbeRole(t *testing.T) {
	role := readRBAC[rbacv1.Role](t, "../../deploy/rbac/kshield-node-probe.yaml")
	if role.APIVersion != "rbac.authorization.k8s.io/v1" || role.Kind != "Role" || role.Name != "kshield-node-probe" || role.Namespace != "kube-system" {
		t.Fatalf("header %s %s %s/%s", role.APIVersion, role.Kind, role.Namespace, role.Name)
	}
	assertGrants(t, grants(t, role.Rules), map[string][]string{
		"/pods":     {"create", "delete", "get", "list"},
		"/pods/log": {"get"},
	})
}
