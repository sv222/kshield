package clustertest

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/kshield/internal/cluster"
)

const (
	Context = "test-ctx"
	Server  = "https://test.invalid:6443"
)

type Kind struct {
	Group, Version, Resource, Kind string
	Namespaced                     bool
}

var Kinds = []Kind{
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

var secrets = Kind{"", "v1", "secrets", "Secret", true}

func (k Kind) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: k.Group, Version: k.Version, Resource: k.Resource}
}

func (k Kind) APIVersion() string {
	return schema.GroupVersion{Group: k.Group, Version: k.Version}.String()
}

type Cluster struct {
	Client    *cluster.Client
	Dynamic   *dynamicfake.FakeDynamicClient
	Core      *fake.Clientset
	Discovery *discoveryfake.FakeDiscovery
}

func New(objs ...*unstructured.Unstructured) *Cluster {
	all := append([]Kind{secrets}, Kinds...)
	listKinds := map[schema.GroupVersionResource]string{}
	for _, k := range all {
		listKinds[k.GVR()] = k.Kind + "List"
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	for _, o := range objs {
		for _, k := range all {
			if k.APIVersion() == o.GetAPIVersion() && k.Kind == o.GetKind() {
				if err := dyn.Tracker().Create(k.GVR(), o, o.GetNamespace()); err != nil {
					panic(err)
				}
			}
		}
	}
	var lists []*metav1.APIResourceList
	for _, k := range Kinds {
		gv := k.APIVersion()
		i := -1
		for j, l := range lists {
			if l.GroupVersion == gv {
				i = j
			}
		}
		if i < 0 {
			lists = append(lists, &metav1.APIResourceList{GroupVersion: gv})
			i = len(lists) - 1
		}
		lists[i].APIResources = append(lists[i].APIResources, metav1.APIResource{
			Name: k.Resource, Kind: k.Kind, Namespaced: k.Namespaced, Verbs: metav1.Verbs{"get", "list"},
		})
	}
	disc := &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}
	core := fake.NewClientset()
	return &Cluster{
		Client:    &cluster.Client{Dynamic: dyn, Discovery: disc, Core: core, Context: Context, Server: Server},
		Dynamic:   dyn,
		Core:      core,
		Discovery: disc,
	}
}

func (c *Cluster) AddNode(name string) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/os": "linux"}}}
	if _, err := c.Core.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
		panic(err)
	}
	c.Core.ClearActions()
}

func Object(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name": name,
			"uid":  apiVersion + "/" + kind + "/" + ns + "/" + name,
		},
	}}
	if ns != "" {
		u.SetNamespace(ns)
	}
	return u
}

func WithSpec(u *unstructured.Unstructured, spec map[string]any) *unstructured.Unstructured {
	u.Object["spec"] = spec
	return u
}

func Labelled(u *unstructured.Unstructured, labels map[string]string) *unstructured.Unstructured {
	u.SetLabels(labels)
	return u
}

func RootVLLM(ns string) *unstructured.Unstructured {
	return WithSpec(Object("apps/v1", "Deployment", ns, "vllm"), map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{"app": "vllm"}},
		"template": map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"app": "vllm"}},
			"spec": map[string]any{
				"containers": []any{map[string]any{"name": "vllm", "image": "vllm/vllm-openai:v0.6.0"}},
			},
		},
	})
}
