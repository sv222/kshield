package scan

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/cluster/clustertest"
	"github.com/sv222/kshield/internal/report"
)

func forbidden(resource string) clienttesting.ReactionFunc {
	return func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("RBAC: denied"))
	}
}

func scanCluster(t *testing.T, c *clustertest.Cluster, opt ClusterOptions) *report.Report {
	t.Helper()
	opt.ProfileID, opt.Deterministic, opt.Client = "dora", true, c.Client
	r, _, err := Cluster(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestClusterReadsAndReports(t *testing.T) {
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "ai"),
		clustertest.RootVLLM("ai"),
	)
	r := scanCluster(t, c, ClusterOptions{})
	info := r.Scan.Cluster
	if info == nil || info.Context != clustertest.Context || info.Server != clustertest.Server || info.NodeProbe || info.ProbeNamespace != "" || info.Namespaces == nil || len(info.Namespaces) != 0 {
		t.Fatalf("cluster info %+v", info)
	}
	if r.Scan.Mode != report.ModeCluster || r.Scan.Objects != 2 || r.Scan.AIWorkloads != 1 || len(r.Errors) != 0 || r.Summary.Incomplete {
		t.Fatalf("scan %+v errors %v", r.Scan, r.Errors)
	}
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictFail {
		t.Errorf("KS-WL-001 %s", v)
	}
	if v := checkByID(t, r, "KS-PRE-004").Verdict; v != report.VerdictNA {
		t.Errorf("KS-PRE-004 without probe %s, want N/A", v)
	}
	for _, a := range c.Dynamic.Actions() {
		if a.GetVerb() != "get" && a.GetVerb() != "list" {
			t.Errorf("dynamic client verb %s on %v", a.GetVerb(), a.GetResource())
		}
	}
	if acts := c.Core.Actions(); len(acts) != 0 {
		t.Errorf("core client used without a node probe: %v", acts)
	}
}

func TestClusterNamespacesInfoSorted(t *testing.T) {
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "a"),
		clustertest.Object("v1", "Namespace", "", "b"),
		clustertest.RootVLLM("b"),
	)
	r := scanCluster(t, c, ClusterOptions{Namespaces: []string{"b", "a", "b"}})
	if got := r.Scan.Cluster.Namespaces; !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("namespaces %v", got)
	}
}

func TestClusterForbiddenKindIsUnknown(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.Dynamic.PrependReactor("list", "networkpolicies", forbidden("networkpolicies"))
	r := scanCluster(t, c, ClusterOptions{})
	assertUnknown(t, r, "KS-NET-001", "KS-NET-002")
	want := "cluster: list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: networkpolicies is forbidden: RBAC: denied"
	if !slices.Equal(r.Errors, []string{want}) || !r.Summary.Incomplete {
		t.Fatalf("errors %v", r.Errors)
	}
	if m := checkByID(t, r, "KS-NET-001").Findings[0].Message; m != "not judged: cannot list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: networkpolicies is forbidden: RBAC: denied" {
		t.Errorf("message %q", m)
	}
}

func TestClusterForbiddenCiliumConfigIsUnknown(t *testing.T) {
	cilium := map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"}
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "ai"),
		clustertest.RootVLLM("ai"),
		clustertest.Labelled(clustertest.Object("apps/v1", "DaemonSet", "kube-system", "cilium"), cilium),
	)
	c.Dynamic.PrependReactor("get", "configmaps", forbidden("configmaps"))
	r := scanCluster(t, c, ClusterOptions{Namespaces: []string{"ai"}})
	assertUnknown(t, r, "KS-NET-003")
	f := checkByID(t, r, "KS-NET-003").Findings[0]
	if f.Object.String() != "Namespace/kube-system" || !strings.HasPrefix(f.Message, "not judged: cannot get v1 configmaps in kube-system: Forbidden:") {
		t.Errorf("finding %+v", f)
	}
}

func TestClusterNodeProbeDenied(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.AddNode("n1")
	c.Core.PrependReactor("create", "pods", forbidden("pods"))
	r := scanCluster(t, c, ClusterOptions{NodeProbe: true})
	info := r.Scan.Cluster
	if !info.NodeProbe || info.ProbeNamespace != cluster.DefaultProbeNamespace {
		t.Fatalf("cluster info %+v", info)
	}
	assertUnknown(t, r, "KS-PRE-004")
	if len(r.Errors) != 1 || !strings.HasPrefix(r.Errors[0], "node probe n1: probe denied in namespace kube-system: ") || !r.Summary.Incomplete {
		t.Fatalf("errors %v", r.Errors)
	}
	for _, a := range c.Core.Actions() {
		okList := a.GetVerb() == "list" && a.GetResource().Resource == "nodes"
		okCreate := a.GetVerb() == "create" && a.GetResource().Resource == "pods"
		if !okList && !okCreate {
			t.Errorf("core client action %s %v", a.GetVerb(), a.GetResource())
		}
	}
}

func TestClusterNodeProbeNamespace(t *testing.T) {
	c := clustertest.New()
	c.AddNode("n1")
	c.Core.PrependReactor("create", "pods", forbidden("pods"))
	r := scanCluster(t, c, ClusterOptions{NodeProbe: true, Probe: cluster.ProbeOptions{Namespace: "kshield-probe"}})
	if r.Scan.Cluster.ProbeNamespace != "kshield-probe" {
		t.Fatalf("cluster info %+v", r.Scan.Cluster)
	}
}

func TestClusterMissingNamespaceIsError(t *testing.T) {
	c := clustertest.New(clustertest.Object("v1", "Namespace", "", "a"))
	r, _, err := Cluster(context.Background(), ClusterOptions{ProfileID: "dora", Client: c.Client, Namespaces: []string{"a", "x"}})
	if err == nil || err.Error() != `namespace "x" not found` || r != nil {
		t.Fatalf("report %v err %v", r, err)
	}
}

func TestClusterConnectError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	r, _, err := Cluster(context.Background(), ClusterOptions{ProfileID: "dora", Kubeconfig: missing})
	if err == nil || !strings.Contains(err.Error(), missing) || r != nil {
		t.Fatalf("report %v err %v", r, err)
	}
}

func TestClusterBadObjectShapeIsSkippedAndIncomplete(t *testing.T) {
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "ai"),
		clustertest.RootVLLM("ai"),
		clustertest.WithSpec(clustertest.Object("apps/v1", "Deployment", "ai", "broken"), map[string]any{"template": "oops"}),
	)
	r := scanCluster(t, c, ClusterOptions{})
	if !slices.ContainsFunc(r.Errors, func(e string) bool {
		return strings.HasPrefix(e, "cluster: read workloads of apps/v1 Deployment/ai/broken: ")
	}) || !r.Summary.Incomplete {
		t.Fatalf("errors %v incomplete %v", r.Errors, r.Summary.Incomplete)
	}
	if r.Scan.AIWorkloads != 1 || r.Scan.Objects != 3 {
		t.Errorf("scan %+v", r.Scan)
	}
	if v := checkByID(t, r, "KS-WL-001").Verdict; v != report.VerdictFail {
		t.Errorf("KS-WL-001 %s", v)
	}
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if strings.Contains(f.Object.String(), "broken") {
				t.Errorf("%s: finding on the skipped object %+v", c.ID, f)
			}
		}
	}
}

func TestClusterDeterministic(t *testing.T) {
	build := func() *report.Report {
		c := clustertest.New(clustertest.Object("v1", "Namespace", "", "ai"), clustertest.RootVLLM("ai"))
		return scanCluster(t, c, ClusterOptions{Namespaces: []string{"ai"}})
	}
	var a, b strings.Builder
	if err := report.WriteJSON(&a, build()); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteJSON(&b, build()); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("two deterministic cluster scans differ")
	}
}

func TestClusterUnknownProfileBeforeAnyRead(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.AddNode("n1")
	r, _, err := Cluster(context.Background(), ClusterOptions{ProfileID: "bogus", Client: c.Client, NodeProbe: true})
	if err == nil || r != nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("report %v err %v", r, err)
	}
	if n := len(c.Dynamic.Actions()) + len(c.Core.Actions()); n != 0 {
		t.Errorf("%d API calls before the profile error", n)
	}
	if err := CheckProfile("dora"); err != nil {
		t.Errorf("dora: %v", err)
	}
}

func TestClusterReturnsObjects(t *testing.T) {
	c := clustertest.New(clustertest.Object("v1", "Namespace", "", "ai"), clustertest.RootVLLM("ai"))
	r, objs, err := Cluster(context.Background(), ClusterOptions{ProfileID: "dora", Deterministic: true, Client: c.Client})
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != r.Scan.Objects || len(objs) != 2 {
		t.Fatalf("%d objects returned, report says %d", len(objs), r.Scan.Objects)
	}
	again, in, err := ClusterObjectsInput(objs, nil, ClusterOptions{ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	var a, b strings.Builder
	if err := report.WriteJSON(&a, again); err != nil {
		t.Fatal(err)
	}
	r.Scan.Cluster = again.Scan.Cluster
	if err := report.WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("a report built again from the returned objects differs from the scan")
	}
	if in.Cluster == nil || len(in.Workloads) != 1 {
		t.Errorf("input cluster %v workloads %d", in.Cluster, len(in.Workloads))
	}
}
