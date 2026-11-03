//go:build kind

package kind

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/report"
)

const (
	rbacScan     = "../../deploy/rbac/kshield-scan.yaml"
	rbacProbe    = "../../deploy/rbac/kshield-node-probe.yaml"
	scanRoleName = "kshield-scan"
	probeRole    = "kshield-node-probe"
	probeRoleNS  = "kube-system"
)

func cleanupDelete(t *testing.T, what string, del func(ctx context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := del(ctx); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("delete %s: %v", what, err)
		}
	})
}

func newServiceAccount(t *testing.T, cs kubernetes.Interface, ns, name string) {
	t.Helper()
	if _, err := cs.CoreV1().ServiceAccounts(ns).Create(t.Context(), &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
		t.Fatalf("create service account %s/%s: %v", ns, name, err)
	}
}

func bindClusterRole(t *testing.T, cs kubernetes.Interface, ns, sa, role string) {
	t.Helper()
	name := "kshield-t-" + sa + "-" + ns
	b := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: sa, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Create(t.Context(), b, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
		t.Fatalf("create cluster role binding %s: %v", name, err)
	}
	cleanupDelete(t, "cluster role binding "+name, func(ctx context.Context) error {
		return cs.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
	})
}

func bindRole(t *testing.T, cs kubernetes.Interface, saNS, sa, roleNS, role string) {
	t.Helper()
	name := "kshield-t-" + sa + "-" + saNS
	b := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: roleNS},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: sa, Namespace: saNS}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role},
	}
	if _, err := cs.RbacV1().RoleBindings(roleNS).Create(t.Context(), b, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
		t.Fatalf("create role binding %s/%s: %v", roleNS, name, err)
	}
	cleanupDelete(t, "role binding "+roleNS+"/"+name, func(ctx context.Context) error {
		return cs.RbacV1().RoleBindings(roleNS).Delete(ctx, name, metav1.DeleteOptions{})
	})
}

func waitAllowed(t *testing.T, cs kubernetes.Interface, ns, sa, group, resource, verb, inNS string) {
	t.Helper()
	user := "system:serviceaccount:" + ns + ":" + sa
	waitFor(t, 30*time.Second, user+" to be allowed to "+verb+" "+resource, func() (bool, string) {
		sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User:               user,
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: group, Resource: resource, Namespace: inNS},
		}}
		got, err := cs.AuthorizationV1().SubjectAccessReviews().Create(t.Context(), sar, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("subject access review: %v", err)
		}
		return got.Status.Allowed, got.Status.Reason
	})
}

func serviceAccountKubeconfig(t *testing.T, cs kubernetes.Interface, ns, sa string) string {
	t.Helper()
	expires := int64(3600)
	tr, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(t.Context(), sa, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &expires},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("token for %s/%s: %v", ns, sa, err)
	}
	admin := restConfig(t)
	kc := clientcmdapi.NewConfig()
	kc.Clusters["sa"] = &clientcmdapi.Cluster{
		Server:                   admin.Host,
		CertificateAuthorityData: admin.CAData,
		CertificateAuthority:     admin.CAFile,
	}
	kc.AuthInfos["sa"] = &clientcmdapi.AuthInfo{Token: tr.Status.Token}
	kc.Contexts["sa"] = &clientcmdapi.Context{Cluster: "sa", AuthInfo: "sa"}
	kc.CurrentContext = "sa"
	path := filepath.Join(t.TempDir(), sa+".kubeconfig")
	if err := clientcmd.WriteToFile(*kc, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKindRBAC(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)
	_, cs := clients(t)

	applyFile(t, rbacScan, nil)
	cleanupDelete(t, "cluster role "+scanRoleName, func(ctx context.Context) error {
		return cs.RbacV1().ClusterRoles().Delete(ctx, scanRoleName, metav1.DeleteOptions{})
	})
	applyFile(t, rbacProbe, nil)
	cleanupDelete(t, "role "+probeRoleNS+"/"+probeRole, func(ctx context.Context) error {
		return cs.RbacV1().Roles(probeRoleNS).Delete(ctx, probeRole, metav1.DeleteOptions{})
	})

	t.Run("scan role only", func(t *testing.T) {
		newServiceAccount(t, cs, ns, "scan-only")
		bindClusterRole(t, cs, ns, "scan-only", scanRoleName)
		waitAllowed(t, cs, ns, "scan-only", "networking.k8s.io", "networkpolicies", "list", ns)
		kc := serviceAccountKubeconfig(t, cs, ns, "scan-only")
		res := runScan(t, kc, "-n", ns, "--format", "json")
		wantExit(t, res, 1)
		r := decodeReport(t, res)
		if len(r.Errors) > 0 || r.Summary.Incomplete {
			t.Errorf("errors %v, incomplete %v, want none", r.Errors, r.Summary.Incomplete)
		}
		if len(findingsOf(r, "KS-WL-001")) == 0 {
			t.Error("no KS-WL-001 finding: the scan did not read the workloads")
		}
	})

	t.Run("scan role without networkpolicies", func(t *testing.T) {
		var role rbacv1.ClusterRole
		if err := yaml.UnmarshalStrict(readFileT(t, rbacScan), &role); err != nil {
			t.Fatal(err)
		}
		role.Name = "kshield-scan-nonp-" + ns
		removed := 0
		for i := range role.Rules {
			var kept []string
			for _, res := range role.Rules[i].Resources {
				if res == "networkpolicies" {
					removed++
					continue
				}
				kept = append(kept, res)
			}
			role.Rules[i].Resources = kept
		}
		if removed != 1 {
			t.Fatalf("removed %d networkpolicies entries from %s, want 1", removed, rbacScan)
		}
		if _, err := cs.RbacV1().ClusterRoles().Create(t.Context(), &role, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
			t.Fatal(err)
		}
		cleanupDelete(t, "cluster role "+role.Name, func(ctx context.Context) error {
			return cs.RbacV1().ClusterRoles().Delete(ctx, role.Name, metav1.DeleteOptions{})
		})
		newServiceAccount(t, cs, ns, "no-netpol")
		bindClusterRole(t, cs, ns, "no-netpol", role.Name)
		waitAllowed(t, cs, ns, "no-netpol", "apps", "deployments", "list", ns)
		kc := serviceAccountKubeconfig(t, cs, ns, "no-netpol")
		res := runScan(t, kc, "-n", ns, "--format", "json")
		wantExit(t, res, 3)
		r := decodeReport(t, res)
		if len(r.Errors) == 0 || !r.Summary.Incomplete {
			t.Fatalf("errors %v, incomplete %v, want errors and incomplete", r.Errors, r.Summary.Incomplete)
		}
		for _, e := range r.Errors {
			if !strings.Contains(e, "networking.k8s.io/v1 networkpolicies") {
				t.Errorf("error line %q does not name networking.k8s.io/v1 networkpolicies", e)
			}
		}
	})

	t.Run("scan role and node probe role", func(t *testing.T) {
		newServiceAccount(t, cs, ns, "scan-probe")
		bindClusterRole(t, cs, ns, "scan-probe", scanRoleName)
		bindRole(t, cs, ns, "scan-probe", probeRoleNS, probeRole)
		waitAllowed(t, cs, ns, "scan-probe", "", "nodes", "list", "")
		waitAllowed(t, cs, ns, "scan-probe", "", "pods", "create", probeRoleNS)
		kc := serviceAccountKubeconfig(t, cs, ns, "scan-probe")
		res := runScan(t, kc, "-n", ns, "--node-probe", "--probe-timeout", "120s", "--format", "json")
		wantExit(t, res, 1)
		r := decodeReport(t, res)
		if len(r.Errors) > 0 || r.Summary.Incomplete {
			t.Errorf("errors %v, incomplete %v, want none", r.Errors, r.Summary.Incomplete)
		}
		got := findingsOf(r, probeCheck)
		if len(got) != 1 || got[0].Verdict != report.VerdictWarn || got[0].Object.Name != nodeName() {
			t.Errorf("%s findings %+v, want one WARN on Node/%s", probeCheck, got, nodeName())
		}
	})
}
