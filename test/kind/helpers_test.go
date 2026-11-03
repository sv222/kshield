//go:build kind

package kind

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

const fieldManager = "kshield-kind-test"

func kubeconfig(t *testing.T) string {
	t.Helper()
	path := os.Getenv("KSHIELD_KIND_KUBECONFIG")
	if path == "" {
		t.Skip("KSHIELD_KIND_KUBECONFIG is empty: run bash scripts/kind-test.sh")
	}
	return path
}

func restConfig(t *testing.T) *rest.Config {
	t.Helper()
	path := kubeconfig(t)
	cluster := os.Getenv("KSHIELD_KIND_CLUSTER")
	if !strings.HasPrefix(cluster, "kshield-") {
		t.Fatalf("KSHIELD_KIND_CLUSTER %q does not start with kshield-", cluster)
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", path, err)
	}
	if want := "kind-" + cluster; raw.CurrentContext != want {
		t.Fatalf("kubeconfig %s: current context is %q, want %q", path, raw.CurrentContext, want)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatalf("kubeconfig %s: %v", path, err)
	}
	return cfg
}

func clients(t *testing.T) (dynamic.Interface, kubernetes.Interface) {
	t.Helper()
	cfg := restConfig(t)
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("typed client: %v", err)
	}
	return dyn, cs
}

func applyFile(t *testing.T, path string, mutate func(*unstructured.Unstructured)) {
	t.Helper()
	objs := readObjects(t, path)
	dyn, cs := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	for _, obj := range objs {
		if mutate != nil {
			mutate(obj)
		}
		gvk := obj.GroupVersionKind()
		mapping := restMapping(t, mapper, path, gvk)
		var ri dynamic.ResourceInterface = dyn.Resource(mapping.Resource)
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			ns := obj.GetNamespace()
			if ns == "" {
				t.Fatalf("%s: %s %s has no namespace", path, gvk.Kind, obj.GetName())
			}
			ri = dyn.Resource(mapping.Resource).Namespace(ns)
		}
		if _, err := ri.Apply(t.Context(), obj.GetName(), obj, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
			t.Fatalf("%s: apply %s %s/%s: %v", path, gvk.Kind, obj.GetNamespace(), obj.GetName(), err)
		}
		if gvk.Group == "apiextensions.k8s.io" && gvk.Kind == "CustomResourceDefinition" {
			waitEstablished(t, ri, obj.GetName())
			mapper.Reset()
		}
	}
}

func restMapping(t *testing.T, mapper *restmapper.DeferredDiscoveryRESTMapper, path string, gvk schema.GroupVersionKind) *meta.RESTMapping {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err == nil {
			return mapping
		}
		if !meta.IsNoMatchError(err) || time.Now().After(deadline) {
			t.Fatalf("%s: map %s: %v", path, gvk, err)
		}
		mapper.Reset()
		time.Sleep(time.Second)
	}
}

func waitEstablished(t *testing.T, ri dynamic.ResourceInterface, name string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		u, err := ri.Get(t.Context(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get CRD %s: %v", name, err)
		}
		conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
		for _, c := range conds {
			m, _ := c.(map[string]any)
			if m["type"] == "Established" && m["status"] == "True" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("CRD %s is not Established after 1 minute", name)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func readObjects(t *testing.T, path string) []*unstructured.Unstructured {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var objs []*unstructured.Unstructured
	for {
		doc, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		js, err := yaml.YAMLToJSON(doc)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if s := strings.TrimSpace(string(js)); s == "null" || s == "{}" || s == "" {
			continue
		}
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(js); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		t.Fatalf("%s: no objects", path)
	}
	return objs
}

func tempNamespace(t *testing.T, labels map[string]string) string {
	t.Helper()
	_, cs := clients(t)
	ns, err := cs.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "kshield-t-", Labels: labels},
	}, metav1.CreateOptions{FieldManager: fieldManager})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		policy := metav1.DeletePropagationBackground
		if err := cs.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{PropagationPolicy: &policy}); err != nil {
			t.Errorf("delete namespace %s: %v", ns.Name, err)
		}
	})
	return ns.Name
}
