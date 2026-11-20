//go:build kind

package kind

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"

	"github.com/sv222/kshield/internal/cli"
	"github.com/sv222/kshield/internal/remediate"
)

// TestKindRayEnforce proves that applying the enforce-mode remediation bundle
// of a namespace with a RayCluster does not kill the head pod.
//
// The bundle carries a Tetragon shell-exec guard (TracingPolicyNamespaced
// kshield-shell-exec, action Sigkill) that kills every shell started by a
// process that is neither a shell nor PID 1. Ray starts shells from its
// Python processes (the dashboard, the client server, the autoscaler v2
// monitor, multiprocessing spawn children and a ray start fork), so without
// a KubeRay exemption the guard kills the head.
//
// The test is RED on main until
// feat(remediate): exempt KubeRay pods from the shell-exec guard
// teaches the guard to skip KubeRay-managed pods; that commit and everything
// after it turn it green. The assertions are behavioral on purpose: they do
// not pin the shape of the generated TracingPolicyNamespaced, so the
// exemption commit may change the policy however it likes.
//
// Probes run as ephemeral containers that target the head container, so they
// share its PID namespace and the pod network namespace: they see the ray
// processes, reach the dashboard on loopback and can start a shell the way
// ray does. No exec subresource is involved, so the test needs no extra Go
// dependencies.
//
// Scope: Tetragon only. The CiliumNetworkPolicies of the bundle are inert
// without Cilium (kind ships kindnetd) and the Kyverno admission Policy
// needs Kyverno, so the test applies only the TracingPolicyNamespaced
// objects of infrastructure-policies.yaml, which carry the killing
// component. KSHIELD_KIND_FULL extends the observation window from 2 to 6
// minutes.
const (
	rayClusterName = "ray-enforce"
	rayHeadImage   = "rayproject/ray:2.52.0"
	rayHeadCName   = "ray-head"

	// startCanaryScript leaves a sleep 600 process behind after the shell
	// exits, the way ray leaves shell-started children behind.
	startCanaryScript = "nohup sleep 600 >/dev/null 2>&1 &"
	canaryProbeScript = `import sys
for p in os.listdir("/proc"):
    if not p.isdigit():
        continue
    try:
        argv = open("/proc/%s/cmdline" % p, "rb").read().split(b"\0")
    except OSError:
        continue
    if argv and argv[0].endswith(b"sleep") and b"600" in argv[1:]:
        print("CANARY_ALIVE")
        sys.exit(0)
print("CANARY_MISSING")
sys.exit(1)`
	dashboardProbeScript = `import socket
socket.create_connection(("127.0.0.1", 8265), timeout=3).close()
print("DASHBOARD_OK")`
	rayProcessProbeScript = `import os
comms = set()
for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            comms.add(open("/proc/%s/comm" % p).read().strip())
        except OSError:
            pass
print("RAY_OK" if {"raylet", "gcs_server"} <= comms else "RAY_MISSING")`
)

var probeSeq int

func nextProbeName(prefix string) string {
	probeSeq++
	return fmt.Sprintf("kshield-probe-%s-%d", prefix, probeSeq)
}

func TestKindRayEnforce(t *testing.T) {
	env := versionsEnv(t)
	helm := helmBin(t)
	_, cs := clients(t)
	ns := tempNamespace(t, nil)

	installTetragon(t, helm, env)
	installKubeRayOperator(t, helm, env)

	applyFile(t, filepath.Join("testdata", "ray-enforce.yaml"), func(u *unstructured.Unstructured) {
		u.SetNamespace(ns)
	})
	var head corev1.Pod
	waitFor(t, 12*time.Minute, "the Ray head pod to be Ready", func() (bool, string) {
		pods, err := cs.CoreV1().Pods(ns).List(t.Context(), metav1.ListOptions{
			LabelSelector: "ray.io/cluster=" + rayClusterName + ",ray.io/node-type=head",
		})
		if err != nil {
			return false, err.Error()
		}
		for _, p := range pods.Items {
			if p.DeletionTimestamp != nil {
				continue
			}
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					head = p
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%d head pods", len(pods.Items))
	})
	headName := head.Name

	// Baseline: before the guard exists, ray is up and the probes all pass.
	waitProbe(t, cs, ns, headName, "ray", rayProcessProbeScript, "RAY_OK", 3*time.Minute)
	waitProbe(t, cs, ns, headName, "dash", dashboardProbeScript, "DASHBOARD_OK", 2*time.Minute)

	// Sanity: a shell started inside the head pod works before the guard
	// exists. This sharpens the RED state below: the same shell dies once
	// the enforce policies are applied.
	if code, log := runInHeadShell(t, cs, ns, headName, "sanity", "echo SANITY_OK", time.Minute); code != 0 || !strings.Contains(log, "SANITY_OK") {
		t.Fatalf("the pre-guard shell probe into the head pod failed\nexit %d log %.200s\n%s", code, log, dumpHead(t, cs, ns, headName))
	}

	kc := kubeconfig(t)
	work := t.TempDir()
	scanPath := filepath.Join(work, "scan.json")
	wantExit(t, runScan(t, kc, "-n", ns, "--format", "json"), 1)

	bundle := filepath.Join(work, "bundle")
	var stdout, stderr strings.Builder
	if code := cli.Run([]string{"remediate", "--from", scanPath, "--kubeconfig", kc, "--mode", "enforce", "--out", bundle}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("remediate exit %d\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}

	policies := readObjects(t, filepath.Join(bundle, remediate.FilePolicies))
	var tracing []*unstructured.Unstructured
	for _, u := range policies {
		if u.GetKind() == "TracingPolicyNamespaced" {
			tracing = append(tracing, u)
		}
	}
	if len(tracing) == 0 {
		t.Fatalf("the enforce bundle has no TracingPolicyNamespaced objects, got %s", kindsOf(policies))
	}
	if !slices.ContainsFunc(tracing, hasSigkillAction) {
		t.Fatalf("no TracingPolicyNamespaced of the enforce bundle carries a Sigkill action: %s", kindsOf(tracing))
	}
	t.Logf("applied enforce policies: %s", strings.Join(applyObjects(t, tracing), ", "))

	// Give the Tetragon agent a moment to load the policies; a fresh
	// TracingPolicyNamespaced is live well within a second.
	time.Sleep(10 * time.Second)

	// Start a process from a shell in the head pod, the way ray does. Without
	// the KubeRay exemption the guard kills this shell before it can leave
	// the sleep behind; with the exemption the shell exits 0 and the sleep
	// keeps running.
	code, log := runInHeadShell(t, cs, ns, headName, "canary", startCanaryScript, time.Minute)
	if code != 0 {
		t.Fatalf("the guard killed a shell started inside the head pod: exit %d\nlog %.200s\n%s", code, log, dumpHead(t, cs, ns, headName))
	}

	window := 2 * time.Minute
	if os.Getenv("KSHIELD_KIND_FULL") != "" {
		window = 6 * time.Minute
		t.Log("KSHIELD_KIND_FULL is set: observing for 6 minutes")
	}
	deadline := time.Now().Add(window)
	next := time.Now().Add(10 * time.Second)
	for {
		time.Sleep(5 * time.Second)
		assertHeadRunning(t, cs, ns, headName)
		if time.Now().After(next) {
			next = time.Now().Add(15 * time.Second)
			assertProbe(t, cs, ns, headName, "canary", "the shell-started process is gone", canaryProbeScript, "CANARY_ALIVE")
			assertProbe(t, cs, ns, headName, "dash", "the Ray dashboard is not reachable", dashboardProbeScript, "DASHBOARD_OK")
		}
		if time.Now().After(deadline) {
			break
		}
	}
	t.Logf("the head pod survived %s of enforce mode: restarts=0, the shell-started process is alive, the dashboard answers", window)
}

func versionsEnv(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(string(readFileT(t, "../../versions.env")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

func helmBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH: the Ray enforce test installs Tetragon and the KubeRay operator with it")
	}
	return bin
}

func helmRun(t *testing.T, helm string, args ...string) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(helm, args...)
	cmd.Env = append(os.Environ(),
		"KUBECONFIG="+kubeconfig(t),
		"HELM_CACHE_HOME="+filepath.Join(home, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(home, "config"),
		"HELM_DATA_HOME="+filepath.Join(home, "data"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func installTetragon(t *testing.T, helm string, env map[string]string) {
	t.Helper()
	ver, ok := env["TETRAGON_CHART_VERSION"]
	if !ok {
		t.Skip("TETRAGON_CHART_VERSION missing in versions.env")
	}
	helmRun(t, helm, "upgrade", "--install", "tetragon", "tetragon",
		"--repo", "https://helm.cilium.io",
		"--version", ver,
		"--namespace", "tetragon", "--create-namespace",
		"--set", "tetragon.grpc.enabled=false",
		"--set", "tetragon.export.enabled=false",
		"--wait", "--timeout", "10m")
	_, cs := clients(t)
	waitFor(t, 5*time.Minute, "the Tetragon agent DaemonSet to be ready", func() (bool, string) {
		ds, err := cs.AppsV1().DaemonSets("tetragon").Get(t.Context(), "tetragon", metav1.GetOptions{})
		if err != nil {
			return false, err.Error()
		}
		return ds.Status.DesiredNumberScheduled > 0 && ds.Status.NumberReady >= ds.Status.DesiredNumberScheduled,
			fmt.Sprintf("ready %d/%d", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
	})
}

func installKubeRayOperator(t *testing.T, helm string, env map[string]string) {
	t.Helper()
	ver, ok := env["KUBERAY_CHART_VERSION"]
	if !ok {
		t.Skip("KUBERAY_CHART_VERSION missing in versions.env")
	}
	dyn, _ := clients(t)
	crds := dyn.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	// The vendored rayclusters CRD of the other tests would fight the chart
	// CRDs in helm's apply. This test runs before those tests created any
	// RayCluster, so deleting the vendored CRD is safe here.
	if err := crds.Delete(t.Context(), "rayclusters.ray.io", metav1.DeleteOptions{}); err == nil {
		t.Log("deleted the vendored rayclusters.ray.io CRD; the KubeRay chart installs its own")
		waitFor(t, time.Minute, "the old rayclusters CRD to be deleted", func() (bool, string) {
			_, err := crds.Get(t.Context(), "rayclusters.ray.io", metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, ""
			}
			if err != nil {
				return false, err.Error()
			}
			return false, "still present"
		})
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("delete the rayclusters.ray.io CRD: %v", err)
	}
	helmRun(t, helm, "upgrade", "--install", "kuberay-operator", "kuberay-operator",
		"--repo", "https://ray-project.github.io/kuberay-helm",
		"--version", ver,
		"--namespace", "kuberay-operator", "--create-namespace",
		"--wait", "--timeout", "8m")
}

// runInHead runs a python3 probe in the PID and network namespace of the
// head container and returns the exit code and the probe output. The probe
// is an ephemeral container, so the exec subresource stays out of the
// picture and the test needs no extra dependencies.
func runInHead(t *testing.T, cs kubernetes.Interface, ns, pod, prefix, script string, timeout time.Duration) (int32, string) {
	t.Helper()
	return runEphemeral(t, cs, ns, pod, prefix, []string{"python3", "-c", script}, timeout)
}

// runInHeadShell starts a plain sh in the head container, exactly what the
// shell-exec guard watches for.
func runInHeadShell(t *testing.T, cs kubernetes.Interface, ns, pod, prefix, script string, timeout time.Duration) (int32, string) {
	t.Helper()
	return runEphemeral(t, cs, ns, pod, prefix, []string{"sh", "-c", script}, timeout)
}

func runEphemeral(t *testing.T, cs kubernetes.Interface, ns, pod, prefix string, command []string, timeout time.Duration) (int32, string) {
	t.Helper()
	name := nextProbeName(prefix)
	getPod := func() *corev1.Pod {
		p, err := cs.CoreV1().Pods(ns).Get(t.Context(), pod, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get pod %s: %v", pod, err)
		}
		return p
	}
	p := getPod()
	p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            name,
			Image:           rayHeadImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         command,
		},
		TargetContainerName: rayHeadCName,
	})
	if _, err := cs.CoreV1().Pods(ns).UpdateEphemeralContainers(t.Context(), pod, p, metav1.UpdateOptions{FieldManager: fieldManager}); err != nil {
		t.Fatalf("add ephemeral container %s to %s: %v", name, pod, err)
	}
	var term *corev1.ContainerStateTerminated
	waitFor(t, timeout, name+" to terminate", func() (bool, string) {
		cur, err := cs.CoreV1().Pods(ns).Get(t.Context(), pod, metav1.GetOptions{})
		if err != nil {
			return false, err.Error()
		}
		for _, st := range cur.Status.EphemeralContainerStatuses {
			if st.Name == name && st.State.Terminated != nil {
				term = st.State.Terminated
				return true, ""
			}
		}
		return false, "still running or waiting"
	})
	logs, err := cs.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: name}).Stream(t.Context())
	if err != nil {
		t.Fatalf("logs of ephemeral container %s: %v", name, err)
	}
	out, err := io.ReadAll(logs)
	logs.Close()
	if err != nil {
		t.Fatalf("read logs of ephemeral container %s: %v", name, err)
	}
	return term.ExitCode, string(out)
}

func assertProbe(t *testing.T, cs kubernetes.Interface, ns, pod, prefix, what, script, want string) {
	t.Helper()
	code, log := runInHead(t, cs, ns, pod, prefix, script, time.Minute)
	if code != 0 || !strings.Contains(log, want) {
		t.Fatalf("%s: probe exit %d, log %.200s\n%s", what, code, log, dumpHead(t, cs, ns, pod))
	}
}

// waitProbe reruns one probe until it passes. Each attempt is an ephemeral
// container, so the retries keep a slow pace.
func waitProbe(t *testing.T, cs kubernetes.Interface, ns, pod, prefix, script, want string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	var code int32
	var log string
	for {
		code, log = runInHead(t, cs, ns, pod, prefix, script, time.Minute)
		if code == 0 && strings.Contains(log, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s in %s: probe exit %d, log %.200s\n%s", want, pod, code, log, dumpHead(t, cs, ns, pod))
		}
		time.Sleep(10 * time.Second)
	}
}

func assertHeadRunning(t *testing.T, cs kubernetes.Interface, ns, pod string) {
	t.Helper()
	p, err := cs.CoreV1().Pods(ns).Get(t.Context(), pod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		t.Fatalf("the head pod %s is gone\n%s", pod, dumpHead(t, cs, ns, pod))
	}
	if err != nil {
		t.Fatal(err)
	}
	if p.DeletionTimestamp != nil {
		t.Fatalf("the head pod %s is being deleted\n%s", pod, dumpHead(t, cs, ns, pod))
	}
	if p.Status.Phase != corev1.PodRunning {
		t.Fatalf("the head pod %s is %s, want Running\n%s", pod, p.Status.Phase, dumpHead(t, cs, ns, pod))
	}
	for _, st := range p.Status.ContainerStatuses {
		if st.RestartCount != 0 {
			t.Fatalf("container %s of the head pod restarted %d times: the guard killed it\n%s", st.Name, st.RestartCount, dumpHead(t, cs, ns, pod))
		}
	}
}

func applyObjects(t *testing.T, objs []*unstructured.Unstructured) []string {
	t.Helper()
	dyn, cs := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	var applied []string
	for _, obj := range objs {
		gvk := obj.GroupVersionKind()
		mapping := restMapping(t, mapper, obj.GetName(), gvk)
		var ri dynamic.ResourceInterface = dyn.Resource(mapping.Resource)
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			ri = dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace())
		}
		if _, err := ri.Apply(t.Context(), obj.GetName(), obj, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
			t.Fatalf("apply %s %s/%s: %v", gvk.Kind, obj.GetNamespace(), obj.GetName(), err)
		}
		applied = append(applied, gvk.Kind+"/"+obj.GetNamespace()+"/"+obj.GetName())
	}
	return applied
}

func kindsOf(objs []*unstructured.Unstructured) string {
	kinds := make([]string, 0, len(objs))
	for _, u := range objs {
		kinds = append(kinds, u.GetKind()+"/"+u.GetName())
	}
	slices.Sort(kinds)
	return strings.Join(kinds, ", ")
}

// hasSigkillAction reports whether any kprobe selector of the policy fires a
// Sigkill. It walks the object instead of comparing it to a fixed shape, so
// the exemption commit may restructure the policy freely.
func hasSigkillAction(u *unstructured.Unstructured) bool {
	kprobes, _, _ := unstructured.NestedSlice(u.Object, "kprobes")
	for _, kp := range kprobes {
		m, _ := kp.(map[string]any)
		selectors, _, _ := unstructured.NestedSlice(m, "selectors")
		for _, sel := range selectors {
			sm, _ := sel.(map[string]any)
			actions, _, _ := unstructured.NestedSlice(sm, "matchActions")
			for _, act := range actions {
				am, _ := act.(map[string]any)
				if am["action"] == "Sigkill" {
					return true
				}
			}
		}
	}
	return false
}

func totalRestarts(p *corev1.Pod) int32 {
	var n int32
	for _, st := range p.Status.ContainerStatuses {
		n += st.RestartCount
	}
	return n
}

func dumpHead(t *testing.T, cs kubernetes.Interface, ns, pod string) string {
	t.Helper()
	var b strings.Builder
	p, err := cs.CoreV1().Pods(ns).Get(t.Context(), pod, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintf(&b, "head pod %s get: %v", pod, err)
		return b.String()
	}
	fmt.Fprintf(&b, "head pod %s: phase=%s restarts=%d", pod, p.Status.Phase, totalRestarts(p))
	if p.DeletionTimestamp != nil {
		fmt.Fprintf(&b, " deleted=%s", p.DeletionTimestamp.Time.Format(time.RFC3339))
	}
	b.WriteString("\n")
	for _, st := range p.Status.ContainerStatuses {
		fmt.Fprintf(&b, "  container %s: ready=%v restarts=%d", st.Name, st.Ready, st.RestartCount)
		if t := st.LastTerminationState.Terminated; t != nil {
			fmt.Fprintf(&b, " lastExit: reason=%s code=%d message=%q finished=%s", t.Reason, t.ExitCode, t.Message, t.FinishedAt.Time.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}
	events, err := cs.CoreV1().Events(ns).List(t.Context(), metav1.ListOptions{})
	if err == nil {
		var mine []corev1.Event
		for _, e := range events.Items {
			if e.InvolvedObject.Name == pod {
				mine = append(mine, e)
			}
		}
		slices.SortFunc(mine, func(a, b corev1.Event) int {
			return a.LastTimestamp.Time.Compare(b.LastTimestamp.Time)
		})
		if len(mine) > 10 {
			mine = mine[len(mine)-10:]
		}
		for _, e := range mine {
			fmt.Fprintf(&b, "  event %s %s: %s\n", e.LastTimestamp.Time.Format(time.RFC3339), e.Reason, e.Message)
		}
	}
	return b.String()
}
