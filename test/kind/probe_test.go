//go:build kind

package kind

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/report"
)

const managedBySelector = "app.kubernetes.io/managed-by=kshield"

func TestKindProbe(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)
	res := runScan(t, kubeconfig(t), "-n", ns, "--node-probe", "--probe-timeout", "120s", "--format", "json")
	wantExit(t, res, 1)
	r := decodeReport(t, res)

	got := findingsOf(r, probeCheck)
	if len(got) != 1 {
		t.Fatalf("%s findings = %d, want 1: %+v", probeCheck, len(got), got)
	}
	f := got[0]
	if f.Object.Kind != "Node" || f.Object.Name != nodeName() || f.Verdict != report.VerdictWarn {
		t.Errorf("finding %s verdict %s, want Node/%s WARN", f.Object, f.Verdict, nodeName())
	}
	if f.Message != probeBPFMsg {
		t.Errorf("message %q, want %q", f.Message, probeBPFMsg)
	}
	if len(r.Errors) > 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	if r.Scan.Cluster == nil || !r.Scan.Cluster.NodeProbe || r.Scan.Cluster.ProbeNamespace != cluster.DefaultProbeNamespace {
		t.Errorf("scan cluster info: %+v", r.Scan.Cluster)
	}

	_, cs := clients(t)
	pods, err := cs.CoreV1().Pods(cluster.DefaultProbeNamespace).List(t.Context(), metav1.ListOptions{LabelSelector: managedBySelector})
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 0 {
		t.Errorf("%d probe pods left in %s", len(pods.Items), cluster.DefaultProbeNamespace)
	}
}

func TestKindProbeRestricted(t *testing.T) {
	for _, level := range []string{"restricted", "baseline"} {
		t.Run(level, func(t *testing.T) {
			scanNS := tempNamespace(t, nil)
			applyToxic(t, scanNS)
			probeNS := tempNamespace(t, map[string]string{"pod-security.kubernetes.io/enforce": level})
			res := runScan(t, kubeconfig(t), "-n", scanNS, "--node-probe", "--probe-namespace", probeNS, "--format", "json")
			wantExit(t, res, 3)
			r := decodeReport(t, res)

			got := findingsOf(r, probeCheck)
			if len(got) != 1 {
				t.Fatalf("%s findings = %d, want 1: %+v", probeCheck, len(got), got)
			}
			f := got[0]
			if f.Object.Kind != "Node" || f.Object.Name != nodeName() || f.Verdict != report.VerdictUnknown {
				t.Errorf("finding %s verdict %s, want Node/%s UNKNOWN", f.Object, f.Verdict, nodeName())
			}
			if !strings.Contains(f.Message, "PodSecurity") {
				t.Errorf("message %q does not name PodSecurity", f.Message)
			}
			line := cluster.ProbeErrorPrefix + nodeName() + ": "
			var found bool
			for _, e := range r.Errors {
				found = found || strings.HasPrefix(e, line)
			}
			if !found || !r.Summary.Incomplete {
				t.Errorf("errors %v, incomplete %v: want a line starting %q", r.Errors, r.Summary.Incomplete, line)
			}

			_, cs := clients(t)
			pods, err := cs.CoreV1().Pods(probeNS).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(pods.Items) != 0 {
				t.Errorf("%d pods in %s, want 0", len(pods.Items), probeNS)
			}
			events, err := cs.CoreV1().Events(probeNS).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range events.Items {
				if strings.HasPrefix(e.InvolvedObject.Name, "kshield-probe-") {
					t.Errorf("event for %s/%s: %s %s", e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Reason, e.Message)
				}
			}
		})
	}
}
