//go:build kind

package kind

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	"github.com/sv222/kshield/internal/corpus"
)

func waitFor(t *testing.T, limit time.Duration, what string, ok func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		done, state := ok()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout after %s waiting for %s; last state: %s", limit, what, state)
		}
		time.Sleep(time.Second)
	}
}

func TestKindToxic(t *testing.T) {
	fixedNamespace(t, toxicNS)
	applyToxic(t, toxicNS)
	res := runScan(t, kubeconfig(t), "-n", toxicNS, "--format", "json", "--deterministic")
	wantExit(t, res, 1)
	r := decodeReport(t, res)

	spec, err := corpus.LoadSpec("toxic/expected.yaml")
	if err != nil {
		t.Fatal(err)
	}
	missing, extra := corpus.Diff(spec.Expect, corpus.Actual(r, spec.Checks))
	for _, e := range missing {
		t.Errorf("missing: %s", e)
	}
	for _, e := range extra {
		t.Errorf("extra: %s", e)
	}
	for _, m := range corpus.NAMismatches(r, spec.NA) {
		t.Errorf("not N/A: %s", m)
	}
	if len(r.Errors) > 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	if r.Scan.Mode != "cluster" || r.Scan.Cluster == nil || len(r.Scan.Cluster.Namespaces) != 1 || r.Scan.Cluster.Namespaces[0] != toxicNS {
		t.Errorf("scan info: %+v cluster %+v", r.Scan, r.Scan.Cluster)
	}

	again := runScan(t, kubeconfig(t), "-n", toxicNS, "--format", "json", "--deterministic")
	wantExit(t, again, 1)
	if again.Stdout != res.Stdout {
		t.Error("two deterministic scans of the same cluster state differ")
	}
}

func rolloutPods(t *testing.T, cs kubernetes.Interface, ns string) (pods []corev1.Pod, ready map[string]bool) {
	t.Helper()
	list, err := cs.CoreV1().Pods(ns).List(t.Context(), metav1.ListOptions{LabelSelector: "app=vllm"})
	if err != nil {
		t.Fatalf("list pods: %v", err)
	}
	ready = map[string]bool{}
	for _, p := range list.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		pods = append(pods, p)
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready[p.Name] = true
			}
		}
	}
	return pods, ready
}

func TestKindDrift(t *testing.T) {
	ns := tempNamespace(t, nil)
	_, cs := clients(t)
	setNS := func(u *unstructured.Unstructured) { u.SetNamespace(ns) }

	applyFile(t, filepath.Join("testdata", "drift-root.yaml"), setNS)
	var oldPod string
	waitFor(t, 2*time.Minute, "the root pod to be Ready", func() (bool, string) {
		pods, ready := rolloutPods(t, cs, ns)
		if len(pods) == 1 && ready[pods[0].Name] {
			oldPod = pods[0].Name
			return true, ""
		}
		return false, fmt.Sprintf("%d pods, ready %v", len(pods), ready)
	})

	applyFile(t, filepath.Join("testdata", "drift-hardened.yaml"), setNS)
	stalled := func() (bool, string) {
		pods, ready := rolloutPods(t, cs, ns)
		d, err := cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get deployment: %v", err)
		}
		state := fmt.Sprintf("%d pods, ready %v, status %+v", len(pods), ready, d.Status)
		return len(pods) == 2 && len(ready) == 1 && ready[oldPod] &&
			d.Status.ObservedGeneration == d.Generation && d.Status.UpdatedReplicas == 1, state
	}
	waitFor(t, 2*time.Minute, "the rollout to stall with the old pod Ready and a new unready pod", stalled)
	time.Sleep(6 * time.Second)
	if ok, state := stalled(); !ok {
		t.Fatalf("the rollout did not stay stalled: %s", state)
	}

	res := runScan(t, kubeconfig(t), "-n", ns, "--format", "json", "--deterministic")
	wantExit(t, res, 1)
	r := decodeReport(t, res)
	got := findingsOf(r, "KS-WL-001")
	if len(got) != 1 {
		t.Fatalf("KS-WL-001 findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Object.Kind != "Deployment" || f.Object.Namespace != ns || f.Object.Name != "vllm" || f.Container != "vllm" {
		t.Errorf("finding object %s container %q, want Deployment/%s/vllm container vllm", f.Object, f.Container, ns)
	}
	if want := "live pod " + oldPod + ": "; !strings.HasPrefix(f.Message, want) {
		t.Errorf("message %q does not start with %q", f.Message, want)
	}
	if len(r.Errors) > 0 {
		t.Errorf("errors: %v", r.Errors)
	}
}
