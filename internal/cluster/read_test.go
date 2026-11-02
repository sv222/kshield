package cluster

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

type testKind struct {
	group, version, resource, kind string
	namespaced                     bool
}

var testKinds = []testKind{
	{"", "v1", "pods", "Pod", true},
	{"", "v1", "services", "Service", true},
	{"", "v1", "serviceaccounts", "ServiceAccount", true},
	{"", "v1", "configmaps", "ConfigMap", true},
	{"", "v1", "namespaces", "Namespace", false},
	{"apps", "v1", "deployments", "Deployment", true},
	{"apps", "v1", "statefulsets", "StatefulSet", true},
	{"apps", "v1", "daemonsets", "DaemonSet", true},
	{"apps", "v1", "replicasets", "ReplicaSet", true},
	{"batch", "v1", "jobs", "Job", true},
	{"batch", "v1", "cronjobs", "CronJob", true},
	{"networking.k8s.io", "v1", "ingresses", "Ingress", true},
	{"networking.k8s.io", "v1", "networkpolicies", "NetworkPolicy", true},
	{"ray.io", "v1", "rayclusters", "RayCluster", true},
	{"ray.io", "v1", "rayservices", "RayService", true},
	{"ray.io", "v1", "rayjobs", "RayJob", true},
	{"serving.kserve.io", "v1beta1", "inferenceservices", "InferenceService", true},
	{"serving.kserve.io", "v1alpha1", "servingruntimes", "ServingRuntime", true},
	{"serving.kserve.io", "v1alpha1", "clusterservingruntimes", "ClusterServingRuntime", false},
	{"serving.knative.dev", "v1", "services", "Service", true},
	{"serving.knative.dev", "v1", "configurations", "Configuration", true},
	{"serving.knative.dev", "v1", "revisions", "Revision", true},
	{"cilium.io", "v2", "ciliumnetworkpolicies", "CiliumNetworkPolicy", true},
	{"cilium.io", "v2", "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy", false},
	{"cilium.io", "v1alpha1", "tracingpolicies", "TracingPolicy", false},
	{"cilium.io", "v1alpha1", "tracingpoliciesnamespaced", "TracingPolicyNamespaced", true},
	{"kyverno.io", "v1", "policies", "Policy", true},
	{"kyverno.io", "v1", "clusterpolicies", "ClusterPolicy", false},
}

var secretKind = testKind{"", "v1", "secrets", "Secret", true}

func (k testKind) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: k.group, Version: k.version, Resource: k.resource}
}

func (k testKind) apiVersion() string {
	return schema.GroupVersion{Group: k.group, Version: k.version}.String()
}

func kindOf(apiVersion, kind string) testKind {
	for _, k := range append(slices.Clone(testKinds), secretKind) {
		if k.apiVersion() == apiVersion && k.kind == kind {
			return k
		}
	}
	panic("no test kind " + apiVersion + " " + kind)
}

func discoveryOf(kinds []testKind) *discoveryfake.FakeDiscovery {
	var lists []*metav1.APIResourceList
	for _, k := range kinds {
		gv := k.apiVersion()
		i := slices.IndexFunc(lists, func(l *metav1.APIResourceList) bool { return l.GroupVersion == gv })
		if i < 0 {
			lists = append(lists, &metav1.APIResourceList{GroupVersion: gv})
			i = len(lists) - 1
		}
		lists[i].APIResources = append(lists[i].APIResources, metav1.APIResource{
			Name: k.resource, Kind: k.kind, Namespaced: k.namespaced, Verbs: metav1.Verbs{"get", "list"},
		})
	}
	return &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}
}

type fixture struct {
	client *Client
	dyn    *dynamicfake.FakeDynamicClient
	disc   *discoveryfake.FakeDiscovery
}

func newFixture(t *testing.T, kinds []testKind, objs ...*unstructured.Unstructured) fixture {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{}
	for _, k := range append(slices.Clone(testKinds), secretKind) {
		listKinds[k.gvr()] = k.kind + "List"
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	for _, o := range objs {
		if err := dyn.Tracker().Create(kindOf(o.GetAPIVersion(), o.GetKind()).gvr(), o, o.GetNamespace()); err != nil {
			t.Fatal(err)
		}
	}
	disc := discoveryOf(kinds)
	return fixture{client: &Client{Dynamic: dyn, Discovery: disc}, dyn: dyn, disc: disc}
}

func live(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":          name,
			"uid":           apiVersion + "/" + kind + "/" + ns + "/" + name,
			"managedFields": []any{map[string]any{"manager": "kubectl", "operation": "Apply"}},
		},
	}}
	if ns != "" {
		u.SetNamespace(ns)
	}
	return u
}

func labelled(u *unstructured.Unstructured, labels map[string]string) *unstructured.Unstructured {
	u.SetLabels(labels)
	return u
}

func withSpec(u *unstructured.Unstructured, spec map[string]any) *unstructured.Unstructured {
	u.Object["spec"] = spec
	return u
}

func refsOf(objs []load.Object) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.Ref.APIVersion+" "+o.Ref.String())
	}
	return out
}

func mustRead(t *testing.T, f fixture, opt ReadOptions) *Snapshot {
	t.Helper()
	snap, err := Read(context.Background(), f.client, opt)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func assertRefs(t *testing.T, got []load.Object, want []string) {
	t.Helper()
	if g := refsOf(got); !slices.Equal(g, want) {
		t.Fatalf("objects:\n got %q\nwant %q", g, want)
	}
}

func assertErrors(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("errors:\n got %q\nwant %q", got, want)
	}
}

func assertFailed(t *testing.T, got, want []FailedRead) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("failed reads:\n got %+v\nwant %+v", got, want)
	}
}

func TestReadAll(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Pod", "a", "p1"),
		live("apps/v1", "Deployment", "a", "d1"),
		live("v1", "Service", "b", "s1"),
		live("v1", "Namespace", "", "a"),
		live("v1", "Namespace", "", "b"),
		live("kyverno.io/v1", "ClusterPolicy", "", "cp1"),
		live("serving.kserve.io/v1alpha1", "ServingRuntime", "a", "sr"),
		live("serving.kserve.io/v1beta1", "InferenceService", "a", "isvc"),
		live("cilium.io/v1alpha1", "TracingPolicy", "", "tp"),
		live("cilium.io/v2", "CiliumNetworkPolicy", "b", "cnp"),
		live("ray.io/v1", "RayCluster", "b", "rc"),
		live("serving.knative.dev/v1", "Revision", "a", "rev"),
		live("serving.knative.dev/v1", "Service", "a", "ksvc"),
	)
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{
		"kyverno.io/v1 ClusterPolicy/cp1",
		"v1 Namespace/a",
		"v1 Namespace/b",
		"cilium.io/v1alpha1 TracingPolicy/tp",
		"apps/v1 Deployment/a/d1",
		"serving.kserve.io/v1beta1 InferenceService/a/isvc",
		"v1 Pod/a/p1",
		"serving.knative.dev/v1 Revision/a/rev",
		"serving.knative.dev/v1 Service/a/ksvc",
		"serving.kserve.io/v1alpha1 ServingRuntime/a/sr",
		"cilium.io/v2 CiliumNetworkPolicy/b/cnp",
		"ray.io/v1 RayCluster/b/rc",
		"v1 Service/b/s1",
	})
	for _, o := range snap.Objects {
		if o.Source != (load.Source{File: "cluster"}) {
			t.Errorf("%s: source %+v", o.Ref, o.Source)
		}
		if _, ok := o.U.Object["metadata"].(map[string]any)["managedFields"]; ok {
			t.Errorf("%s: managedFields kept", o.Ref)
		}
		if o.U.GetUID() == "" {
			t.Errorf("%s: uid dropped", o.Ref)
		}
	}
	assertErrors(t, snap.Errors, nil)
	assertFailed(t, snap.Failed, nil)
}

func TestReadForbiddenKind(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Pod", "a", "p1"),
		live("networking.k8s.io/v1", "NetworkPolicy", "a", "np"),
	)
	f.dyn.PrependReactor("list", "networkpolicies", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{"v1 Pod/a/p1"})
	assertErrors(t, snap.Errors, []string{
		"cluster: list networking.k8s.io/v1 networkpolicies in all namespaces: Forbidden: networkpolicies.networking.k8s.io is forbidden: RBAC: denied",
	})
	assertFailed(t, snap.Failed, []FailedRead{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}})
}

func TestReadForbiddenKindInNamespace(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		live("v1", "Namespace", "", "b"),
		live("v1", "Pod", "a", "p1"),
		live("v1", "Pod", "b", "p2"),
	)
	f.dyn.PrependReactor("list", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "b" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("RBAC: denied"))
	})
	f.dyn.PrependReactor("list", "replicasets", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "replicasets"}, "", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"b", "a"}})
	assertRefs(t, snap.Objects, []string{"v1 Namespace/a", "v1 Namespace/b", "v1 Pod/a/p1"})
	assertErrors(t, snap.Errors, []string{
		"cluster: list apps/v1 replicasets in a: Forbidden: replicasets.apps is forbidden: RBAC: denied",
		"cluster: list apps/v1 replicasets in b: Forbidden: replicasets.apps is forbidden: RBAC: denied",
		"cluster: list v1 pods in b: Forbidden: pods is forbidden: RBAC: denied",
	})
	assertFailed(t, snap.Failed, []FailedRead{
		{Version: "v1", Resource: "pods", Namespace: "b"},
		{Group: "apps", Version: "v1", Resource: "replicasets", Namespace: "a"},
		{Group: "apps", Version: "v1", Resource: "replicasets", Namespace: "b"},
	})
}

func TestReadForbiddenPrerequisiteList(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		live("apps/v1", "DaemonSet", "a", "agent"),
		labelled(live("apps/v1", "DaemonSet", "kube-system", "cilium"), map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"}),
	)
	f.dyn.PrependReactor("list", "daemonsets", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, "", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"a"}})
	assertRefs(t, snap.Objects, []string{"v1 Namespace/a", "apps/v1 DaemonSet/a/agent"})
	assertErrors(t, snap.Errors, []string{
		"cluster: list apps/v1 daemonsets in all namespaces: Forbidden: daemonsets.apps is forbidden: RBAC: denied",
	})
	assertFailed(t, snap.Failed, []FailedRead{{Group: "apps", Version: "v1", Resource: "daemonsets"}})
}

func TestReadPagingError(t *testing.T) {
	f := newFixture(t, testKinds, live("v1", "Service", "a", "s"))
	p := &pagedClient{Interface: f.dyn, failAt: "500"}
	for i := range 1201 {
		p.pods = append(p.pods, *live("v1", "Pod", "a", "p"+strconv.Itoa(10000+i)))
	}
	f.client.Dynamic = p
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{"v1 Service/a/s"})
	assertErrors(t, snap.Errors, []string{
		`cluster: list v1 pods in all namespaces: Expired: The provided continue parameter is too old to display a consistent list result.`,
	})
	assertFailed(t, snap.Failed, []FailedRead{{Version: "v1", Resource: "pods"}})
	if len(p.calls) != 2 {
		t.Fatalf("list calls %+v", p.calls)
	}
}

func TestReadNamespaces(t *testing.T) {
	cilium := map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"}
	tetragon := map[string]string{"app.kubernetes.io/name": "tetragon", "app.kubernetes.io/component": "agent"}
	kyverno := map[string]string{"app.kubernetes.io/component": "admission-controller", "app.kubernetes.io/part-of": "kyverno"}
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		live("v1", "Namespace", "", "b"),
		live("v1", "Namespace", "", "c"),
		live("v1", "Namespace", "", "kube-system"),
		live("v1", "Pod", "a", "p"),
		live("v1", "Pod", "b", "p"),
		live("v1", "Pod", "c", "p"),
		live("apps/v1", "Deployment", "c", "vllm"),
		live("apps/v1", "DaemonSet", "c", "agent"),
		labelled(live("apps/v1", "DaemonSet", "a", "tetragon"), tetragon),
		labelled(live("apps/v1", "DaemonSet", "kube-system", "cilium"), cilium),
		labelled(live("apps/v1", "DaemonSet", "kube-system", "tetragon"), tetragon),
		live("apps/v1", "DaemonSet", "kube-system", "kube-proxy"),
		labelled(live("apps/v1", "Deployment", "kyverno", "kyverno-admission-controller"), kyverno),
		live("v1", "ConfigMap", "kube-system", "cilium-config"),
		live("v1", "ConfigMap", "kube-system", "coredns"),
		live("v1", "ConfigMap", "c", "cilium-config"),
		live("kyverno.io/v1", "ClusterPolicy", "", "cp"),
		live("kyverno.io/v1", "Policy", "c", "pol"),
	)
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"b", "a", "b"}})
	assertRefs(t, snap.Objects, []string{
		"kyverno.io/v1 ClusterPolicy/cp",
		"v1 Namespace/a",
		"v1 Namespace/b",
		"apps/v1 DaemonSet/a/tetragon",
		"v1 Pod/a/p",
		"v1 Pod/b/p",
		"v1 ConfigMap/kube-system/cilium-config",
		"apps/v1 DaemonSet/kube-system/cilium",
		"apps/v1 DaemonSet/kube-system/tetragon",
		"apps/v1 Deployment/kyverno/kyverno-admission-controller",
	})
	assertErrors(t, snap.Errors, nil)
	for _, a := range f.dyn.Actions() {
		if a.GetVerb() != "list" || a.GetNamespace() != "" {
			continue
		}
		k := slices.IndexFunc(testKinds, func(k testKind) bool { return k.gvr() == a.GetResource() })
		if k < 0 {
			t.Fatalf("list of %v", a.GetResource())
		}
		r := testKinds[k].resource
		if testKinds[k].namespaced && r != "daemonsets" && r != "deployments" {
			t.Errorf("namespaced %s listed in all namespaces", r)
		}
		if r == "namespaces" {
			t.Errorf("namespaces listed with -n")
		}
	}
}

func TestReadMissingNamespace(t *testing.T) {
	f := newFixture(t, testKinds, live("v1", "Namespace", "", "a"))
	snap, err := Read(context.Background(), f.client, ReadOptions{Namespaces: []string{"a", "x"}})
	if err == nil || err.Error() != `namespace "x" not found` {
		t.Fatalf("err %v, snapshot %v", err, snap)
	}
	if snap != nil {
		t.Fatalf("snapshot %v", snap)
	}
}

func TestReadSkipsUnservedGroups(t *testing.T) {
	var kinds []testKind
	for _, k := range testKinds {
		if k.group != "ray.io" && k.resource != "tracingpoliciesnamespaced" {
			kinds = append(kinds, k)
		}
	}
	f := newFixture(t, kinds, live("v1", "Pod", "a", "p1"), live("ray.io/v1", "RayCluster", "a", "rc"))
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{"v1 Pod/a/p1"})
	assertErrors(t, snap.Errors, nil)
	for _, a := range f.dyn.Actions() {
		if a.GetResource().Group == "ray.io" || a.GetResource().Resource == "tracingpoliciesnamespaced" {
			t.Errorf("read of unserved %v", a.GetResource())
		}
	}
}

type failingDiscovery struct {
	*discoveryfake.FakeDiscovery
	fail map[string]error
}

func (d failingDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	if err := d.fail[gv]; err != nil {
		return nil, err
	}
	return d.FakeDiscovery.ServerResourcesForGroupVersion(gv)
}

func TestReadGroupDiscoveryFails(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Pod", "a", "p1"),
		live("cilium.io/v2", "CiliumNetworkPolicy", "a", "cnp"),
		live("cilium.io/v1alpha1", "TracingPolicy", "", "tp"),
	)
	f.client.Discovery = failingDiscovery{FakeDiscovery: f.disc, fail: map[string]error{
		"cilium.io/v2": apierrors.NewServiceUnavailable("the server is currently unable to handle the request"),
	}}
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{"cilium.io/v1alpha1 TracingPolicy/tp", "v1 Pod/a/p1"})
	assertErrors(t, snap.Errors, []string{
		"cluster: discover cilium.io/v2: ServiceUnavailable: the server is currently unable to handle the request",
	})
	assertFailed(t, snap.Failed, []FailedRead{{Group: "cilium.io", Version: "v2"}})
}

func TestReadCoreDiscoveryFails(t *testing.T) {
	f := newFixture(t, testKinds, live("v1", "Pod", "a", "p1"))
	f.client.Discovery = failingDiscovery{FakeDiscovery: f.disc, fail: map[string]error{"v1": errors.New("connection refused")}}
	if snap, err := Read(context.Background(), f.client, ReadOptions{}); err == nil {
		t.Fatalf("no error, snapshot %v", snap)
	}
	f.client.Discovery = f.disc
	f.disc.PrependReactor("get", "group", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	if snap, err := Read(context.Background(), f.client, ReadOptions{}); err == nil {
		t.Fatalf("no error, snapshot %v", snap)
	}
}

type pagedClient struct {
	dynamic.Interface
	pods   []unstructured.Unstructured
	calls  []metav1.ListOptions
	failAt string
}

type pagedPods struct {
	dynamic.NamespaceableResourceInterface
	p *pagedClient
}

func (p *pagedClient) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	if gvr.Resource == "pods" {
		return pagedPods{NamespaceableResourceInterface: p.Interface.Resource(gvr), p: p}
	}
	return p.Interface.Resource(gvr)
}

func (r pagedPods) List(_ context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	r.p.calls = append(r.p.calls, opts)
	if opts.Continue != "" && opts.Continue == r.p.failAt {
		return nil, apierrors.NewResourceExpired("The provided continue parameter is too old to display a consistent list result.")
	}
	start := 0
	if opts.Continue != "" {
		n, err := strconv.Atoi(opts.Continue)
		if err != nil {
			return nil, err
		}
		start = n
	}
	end := min(start+int(opts.Limit), len(r.p.pods))
	if opts.Limit == 0 {
		end = len(r.p.pods)
	}
	list := &unstructured.UnstructuredList{Items: slices.Clone(r.p.pods[start:end])}
	if end < len(r.p.pods) {
		list.SetContinue(strconv.Itoa(end))
	}
	return list, nil
}

func TestReadPaging(t *testing.T) {
	f := newFixture(t, testKinds)
	p := &pagedClient{Interface: f.dyn}
	for i := range 1201 {
		p.pods = append(p.pods, *live("v1", "Pod", "a", "p"+strconv.Itoa(10000+i)))
	}
	f.client.Dynamic = p
	snap := mustRead(t, f, ReadOptions{})
	if len(snap.Objects) != 1201 {
		t.Fatalf("got %d objects", len(snap.Objects))
	}
	if snap.Objects[0].Ref.Name != "p10000" || snap.Objects[1200].Ref.Name != "p11200" {
		t.Fatalf("order: %s .. %s", snap.Objects[0].Ref.Name, snap.Objects[1200].Ref.Name)
	}
	want := []metav1.ListOptions{{Limit: 500}, {Limit: 500, Continue: "500"}, {Limit: 500, Continue: "1000"}}
	if !slices.Equal(p.calls, want) {
		t.Fatalf("list calls %+v", p.calls)
	}
	assertErrors(t, snap.Errors, nil)
}

func secretPod() *unstructured.Unstructured {
	return withSpec(live("v1", "Pod", "a", "p"), map[string]any{
		"containers": []any{map[string]any{
			"name":    "app",
			"image":   "app:1",
			"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "s1"}}, map[string]any{"configMapRef": map[string]any{"name": "cm"}}},
		}},
		"initContainers": []any{map[string]any{
			"name":    "init",
			"image":   "init:1",
			"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "s4"}}},
		}},
		"volumes": []any{
			map[string]any{"name": "v", "secret": map[string]any{"secretName": "s2"}},
			map[string]any{"name": "c", "configMap": map[string]any{"name": "cm2"}},
		},
	})
}

func secretDeployment() *unstructured.Unstructured {
	return withSpec(live("apps/v1", "Deployment", "a", "d"), map[string]any{
		"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": "app:1"}},
			"volumes":    []any{map[string]any{"name": "v", "secret": map[string]any{"secretName": "s3"}}},
		}},
	})
}

func TestReadSecretsByName(t *testing.T) {
	f := newFixture(t, testKinds,
		secretPod(),
		secretDeployment(),
		live("v1", "Secret", "a", "s1"),
		live("v1", "Secret", "a", "s2"),
		live("v1", "Secret", "a", "s3"),
		live("v1", "Secret", "a", "unused"),
		live("v1", "Secret", "b", "s1"),
	)
	f.dyn.PrependReactor("get", "secrets", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.(clienttesting.GetAction).GetName() != "s3" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "s3", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{})
	assertRefs(t, snap.Objects, []string{
		"apps/v1 Deployment/a/d",
		"v1 Pod/a/p",
		"v1 Secret/a/s1",
		"v1 Secret/a/s2",
	})
	assertErrors(t, snap.Errors, nil)
	var gets []string
	for _, a := range f.dyn.Actions() {
		if a.GetResource().Resource != "secrets" {
			continue
		}
		if a.GetVerb() != "get" {
			t.Errorf("secrets %s", a.GetVerb())
			continue
		}
		gets = append(gets, a.GetNamespace()+"/"+a.(clienttesting.GetAction).GetName())
	}
	slices.Sort(gets)
	if want := []string{"a/s1", "a/s2", "a/s3", "a/s4"}; !slices.Equal(gets, want) {
		t.Fatalf("secret gets %q, want %q", gets, want)
	}
}

func TestReadSecretOtherErrorIsLine(t *testing.T) {
	f := newFixture(t, testKinds, secretPod(), live("v1", "Secret", "a", "s1"))
	f.dyn.PrependReactor("get", "secrets", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.(clienttesting.GetAction).GetName() != "s2" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewInternalError(errors.New("etcd timeout"))
	})
	snap := mustRead(t, f, ReadOptions{})
	assertErrors(t, snap.Errors, []string{
		"cluster: get v1 secrets s2 in a: InternalError: Internal error occurred: etcd timeout",
	})
	assertFailed(t, snap.Failed, nil)
}

func secretGets(f fixture) []string {
	var gets []string
	for _, a := range f.dyn.Actions() {
		if a.GetResource().Resource == "secrets" {
			gets = append(gets, a.GetVerb()+" "+a.GetNamespace()+"/"+a.(clienttesting.GetAction).GetName())
		}
	}
	slices.Sort(gets)
	return gets
}

func TestReadSecretsInScope(t *testing.T) {
	cilium := labelled(withSpec(live("apps/v1", "DaemonSet", "kube-system", "cilium"), map[string]any{
		"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "agent", "image": "cilium:1"}},
			"volumes":    []any{map[string]any{"name": "ca", "secret": map[string]any{"secretName": "cilium-ca"}}},
		}},
	}), map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"})
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		secretPod(),
		cilium,
		live("v1", "Secret", "a", "s1"),
		live("v1", "Secret", "kube-system", "cilium-ca"),
	)
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"a"}})
	assertRefs(t, snap.Objects, []string{
		"v1 Namespace/a",
		"v1 Pod/a/p",
		"v1 Secret/a/s1",
		"apps/v1 DaemonSet/kube-system/cilium",
	})
	if got, want := secretGets(f), []string{"get a/s1", "get a/s2", "get a/s4"}; !slices.Equal(got, want) {
		t.Fatalf("secret gets %q, want %q", got, want)
	}
	f = newFixture(t, testKinds, secretPod(), cilium, live("v1", "Secret", "kube-system", "cilium-ca"))
	snap = mustRead(t, f, ReadOptions{})
	if got, want := secretGets(f), []string{"get a/s1", "get a/s2", "get a/s4", "get kube-system/cilium-ca"}; !slices.Equal(got, want) {
		t.Fatalf("secret gets without -n %q, want %q", got, want)
	}
	assertErrors(t, snap.Errors, nil)
}

func TestReadSecretReferenceError(t *testing.T) {
	f := newFixture(t, testKinds, withSpec(live("v1", "Pod", "a", "bad"), map[string]any{"containers": "oops"}))
	snap := mustRead(t, f, ReadOptions{})
	if len(snap.Errors) != 1 || !strings.HasPrefix(snap.Errors[0], "cluster: read secret references of v1 Pod/a/bad: ") {
		t.Fatalf("errors %q", snap.Errors)
	}
	assertFailed(t, snap.Failed, nil)
}

func TestReadOnlyVerbs(t *testing.T) {
	cilium := map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"}
	objs := []*unstructured.Unstructured{
		live("v1", "Namespace", "", "a"),
		secretPod(),
		secretDeployment(),
		live("v1", "Secret", "a", "s1"),
		labelled(live("apps/v1", "DaemonSet", "kube-system", "cilium"), cilium),
		live("v1", "ConfigMap", "kube-system", "cilium-config"),
	}
	for _, opt := range []ReadOptions{{}, {Namespaces: []string{"a"}}} {
		f := newFixture(t, testKinds, objs...)
		mustRead(t, f, opt)
		verbs := map[string]bool{}
		for _, a := range slices.Concat(f.dyn.Actions(), f.disc.Actions()) {
			verbs[a.GetVerb()] = true
			if a.GetVerb() != "get" && a.GetVerb() != "list" {
				t.Errorf("%+v: verb %s on %v", opt, a.GetVerb(), a.GetResource())
			}
		}
		if !verbs["get"] || !verbs["list"] {
			t.Errorf("%+v: verbs %v", opt, verbs)
		}
	}
}

func TestReadCiliumConfigGet(t *testing.T) {
	cilium := map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"}
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		labelled(live("apps/v1", "DaemonSet", "kube-system", "cilium"), cilium),
		labelled(live("apps/v1", "DaemonSet", "cilium", "cilium"), cilium),
	)
	f.dyn.PrependReactor("get", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "cilium" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "cilium-config", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"a"}})
	assertRefs(t, snap.Objects, []string{
		"v1 Namespace/a",
		"apps/v1 DaemonSet/cilium/cilium",
		"apps/v1 DaemonSet/kube-system/cilium",
	})
	assertErrors(t, snap.Errors, []string{
		`cluster: get v1 configmaps cilium-config in cilium: Forbidden: configmaps "cilium-config" is forbidden: RBAC: denied`,
	})
	assertFailed(t, snap.Failed, []FailedRead{{Version: "v1", Resource: "configmaps", Namespace: "cilium"}})
}

func TestReadNamespaceGetForbidden(t *testing.T) {
	f := newFixture(t, testKinds,
		live("v1", "Namespace", "", "a"),
		live("v1", "Namespace", "", "b"),
		live("v1", "Pod", "a", "p1"),
		live("v1", "Pod", "b", "p2"),
	)
	f.dyn.PrependReactor("get", "namespaces", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.(clienttesting.GetAction).GetName() != "b" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "b", errors.New("RBAC: denied"))
	})
	snap := mustRead(t, f, ReadOptions{Namespaces: []string{"a", "b"}})
	assertRefs(t, snap.Objects, []string{"v1 Namespace/a", "v1 Pod/a/p1", "v1 Pod/b/p2"})
	assertErrors(t, snap.Errors, []string{
		`cluster: get v1 namespaces b: Forbidden: namespaces "b" is forbidden: RBAC: denied`,
	})
	assertFailed(t, snap.Failed, []FailedRead{{Version: "v1", Resource: "namespaces", Namespace: "b"}})
}

func TestFailedReadReason(t *testing.T) {
	errs := []string{
		`cluster: discover cilium.io/v2: ServiceUnavailable: down`,
		`cluster: get v1 configmaps cilium-config in kube-system: Forbidden: no`,
		`cluster: get v1 namespaces b: Forbidden: no ns`,
		`cluster: list apps/v1 daemonsets in all namespaces: Forbidden: no ds`,
		`cluster: list apps/v1 daemonsets in a: Forbidden: no ds a`,
		`cluster: list v1 configmaps in a: Forbidden: no cm`,
	}
	for _, tc := range []struct {
		f      FailedRead
		reason string
		ok     bool
	}{
		{FailedRead{Group: "cilium.io", Version: "v2"}, "ServiceUnavailable: down", true},
		{FailedRead{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}, "", false},
		{FailedRead{Group: "apps", Version: "v1", Resource: "daemonsets"}, "Forbidden: no ds", true},
		{FailedRead{Group: "apps", Version: "v1", Resource: "daemonsets", Namespace: "a"}, "Forbidden: no ds a", true},
		{FailedRead{Group: "apps", Version: "v1", Resource: "daemonsets", Namespace: "b"}, "", false},
		{FailedRead{Version: "v1", Resource: "namespaces", Namespace: "b"}, "Forbidden: no ns", true},
		{FailedRead{Version: "v1", Resource: "configmaps", Namespace: "kube-system"}, "Forbidden: no", true},
		{FailedRead{Version: "v1", Resource: "configmaps", Namespace: "a"}, "Forbidden: no cm", true},
		{FailedRead{Version: "v1", Resource: "pods"}, "", false},
	} {
		reason, ok := tc.f.Reason(errs)
		if reason != tc.reason || ok != tc.ok {
			t.Errorf("%+v: got %q %v, want %q %v", tc.f, reason, ok, tc.reason, tc.ok)
		}
	}
}

func TestFailedReadMatchVerb(t *testing.T) {
	errs := []string{
		`cluster: get v1 configmaps cilium-config in kube-system: Forbidden: no`,
		`cluster: get v1 namespaces b: Forbidden: no ns`,
		`cluster: list apps/v1 daemonsets in all namespaces: Forbidden: no ds`,
	}
	for _, tc := range []struct {
		f    FailedRead
		verb string
	}{
		{FailedRead{Version: "v1", Resource: "configmaps", Namespace: "kube-system"}, "get"},
		{FailedRead{Version: "v1", Resource: "namespaces", Namespace: "b"}, "get"},
		{FailedRead{Group: "apps", Version: "v1", Resource: "daemonsets"}, "list"},
		{FailedRead{Version: "v1", Resource: "pods"}, "list"},
	} {
		if verb, _, _ := tc.f.Match(errs); verb != tc.verb {
			t.Errorf("%+v: verb %q, want %q", tc.f, verb, tc.verb)
		}
	}
}

func TestReadSetCopy(t *testing.T) {
	got := ReadSet()
	if !slices.Equal(got, readSet) {
		t.Fatalf("ReadSet differs from the read set")
	}
	got[0].Resource = "changed"
	if readSet[0].Resource == "changed" {
		t.Fatal("ReadSet returns the internal slice")
	}
}

func TestReadSetMatchesTestKinds(t *testing.T) {
	var got, want []string
	for _, r := range readSet {
		got = append(got, r.Group+"/"+r.Resource)
	}
	for _, k := range testKinds {
		want = append(want, k.group+"/"+k.resource)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("read set %q, want %q", got, want)
	}
}

func TestReadSetNonWorkloadKinds(t *testing.T) {
	var got []string
	for _, k := range testKinds {
		if !model.WorkloadKind(k.apiVersion(), k.kind) {
			got = append(got, k.group+"/"+k.kind)
		}
	}
	want := []string{
		"/Service",
		"/ServiceAccount",
		"/ConfigMap",
		"/Namespace",
		"networking.k8s.io/Ingress",
		"networking.k8s.io/NetworkPolicy",
		"serving.knative.dev/Service",
		"serving.knative.dev/Configuration",
		"serving.knative.dev/Revision",
		"cilium.io/CiliumNetworkPolicy",
		"cilium.io/CiliumClusterwideNetworkPolicy",
		"cilium.io/TracingPolicy",
		"cilium.io/TracingPolicyNamespaced",
		"kyverno.io/Policy",
		"kyverno.io/ClusterPolicy",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("non-workload kinds in the read set changed (check that none owns the Cilium, Tetragon or Kyverno workloads):\n got %q\nwant %q", got, want)
	}
}

var _ discovery.DiscoveryInterface = failingDiscovery{}
