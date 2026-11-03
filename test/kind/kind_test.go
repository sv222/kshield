//go:build kind

package kind

import (
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestKindSmoke(t *testing.T) {
	_, cs := clients(t)
	nodes, err := cs.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes.Items) != 1 {
		t.Fatalf("want exactly 1 node, got %d", len(nodes.Items))
	}
	n := nodes.Items[0]
	ready := false
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready {
		t.Fatalf("node %s is not Ready: %+v", n.Name, n.Status.Conditions)
	}
}

func TestKindHelpers(t *testing.T) {
	labels := map[string]string{"kshield.test/helpers": "yes"}
	ns := tempNamespace(t, labels)
	applyFile(t, filepath.Join("testdata", "smoke.yaml"), func(u *unstructured.Unstructured) {
		u.SetNamespace(ns)
	})
	_, cs := clients(t)
	got, err := cs.CoreV1().Namespaces().Get(t.Context(), ns, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get namespace %s: %v", ns, err)
	}
	if got.Labels["kshield.test/helpers"] != "yes" {
		t.Fatalf("namespace %s labels = %v", ns, got.Labels)
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(t.Context(), "kshield-smoke", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if cm.Data["probe"] != "ok" {
		t.Fatalf("configmap data = %v", cm.Data)
	}
}
