package remediate

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func applyRoles(t *testing.T) map[string]rbacv1.ClusterRole {
	t.Helper()
	data, err := os.ReadFile("../../deploy/rbac/kshield-apply.yaml")
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]rbacv1.ClusterRole{}
	for _, doc := range bytes.Split(data, []byte("\n---\n")) {
		var role rbacv1.ClusterRole
		if err := yaml.UnmarshalStrict(doc, &role); err != nil {
			t.Fatal(err)
		}
		if role.APIVersion != "rbac.authorization.k8s.io/v1" || role.Kind != "ClusterRole" || role.Namespace != "" {
			t.Fatalf("header %s %s %s/%s", role.APIVersion, role.Kind, role.Namespace, role.Name)
		}
		roles[role.Name] = role
	}
	return roles
}

func grantsOf(t *testing.T, role rbacv1.ClusterRole) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, r := range role.Rules {
		if len(r.ResourceNames) > 0 || len(r.NonResourceURLs) > 0 {
			t.Errorf("%s: resourceNames or nonResourceURLs in %+v", role.Name, r)
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				key := g + "/" + res
				if _, dup := out[key]; dup {
					t.Errorf("%s: %s granted twice", role.Name, key)
				}
				out[key] = slices.Sorted(slices.Values(r.Verbs))
			}
		}
	}
	return out
}

func TestApplyRolePolicies(t *testing.T) {
	roles := applyRoles(t)
	got := grantsOf(t, roles["kshield-apply"])
	want := map[string][]string{
		"kyverno.io/policies":                 {"create", "patch"},
		"cilium.io/ciliumnetworkpolicies":     {"create", "patch"},
		"cilium.io/tracingpoliciesnamespaced": {"create", "patch"},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("kshield-apply grants %v, want %v", got, want)
	}
}

func TestApplyRolePatchesOnlyPatches(t *testing.T) {
	got := grantsOf(t, applyRoles(t)["kshield-apply-patches"])
	if len(got) == 0 {
		t.Fatal("no grants")
	}
	for k, verbs := range got {
		if !slices.Equal(verbs, []string{"patch"}) {
			t.Errorf("%s: verbs %v, want only patch", k, verbs)
		}
	}
	for _, k := range []string{"/secrets", "/pods", "apps/replicasets"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s must not be granted", k)
		}
	}
}

func TestApplyRoleCoversTheKindsOfThePolicyBundle(t *testing.T) {
	grants := grantsOf(t, applyRoles(t)["kshield-apply"])
	objs, err := PlanApply(toxicBundle(t, "enforce"), false)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]string{
		"Policy":                  "kyverno.io/policies",
		"CiliumNetworkPolicy":     "cilium.io/ciliumnetworkpolicies",
		"TracingPolicyNamespaced": "cilium.io/tracingpoliciesnamespaced",
	}
	for _, o := range objs {
		key, ok := covered[o.Object.GetKind()]
		if !ok {
			t.Errorf("the bundle holds a %s, which the apply role does not cover", o.Label())
			continue
		}
		if _, ok := grants[key]; !ok {
			t.Errorf("%s is not granted", key)
		}
	}
}
