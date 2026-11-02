package cli

import (
	"encoding/json"
	"errors"
	"os"
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
	"github.com/sv222/kshield/internal/evidence"
	"github.com/sv222/kshield/internal/report"
)

type connectCall struct {
	kubeconfig, context string
}

func useCluster(t *testing.T, c *clustertest.Cluster) *[]connectCall {
	t.Helper()
	var calls []connectCall
	old := connect
	connect = func(kubeconfig, context string) (*cluster.Client, error) {
		calls = append(calls, connectCall{kubeconfig, context})
		return c.Client, nil
	}
	t.Cleanup(func() { connect = old })
	return &calls
}

func forbiddenList(resource string) clienttesting.ReactionFunc {
	return func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", errors.New("RBAC: denied"))
	}
}

func clusterJSON(t *testing.T, stdout string) report.Report {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, stdout)
	}
	return r
}

func TestScanClusterNoAIWorkloads(t *testing.T) {
	useCluster(t, clustertest.New(clustertest.Object("v1", "Namespace", "", "default")))
	code, out, errs := run(t, "", "scan", "cluster")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errs, out)
	}
	if !strings.Contains(out, "note: no AI workloads found; all checks are N/A") {
		t.Errorf("stdout lacks the no-AI note:\n%s", out)
	}
}

func TestScanClusterEmptyCluster(t *testing.T) {
	useCluster(t, clustertest.New())
	code, out, errs := run(t, "", "scan", "cluster", "--format", "json")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errs, out)
	}
	if r := clusterJSON(t, out); r.Scan.Objects != 0 || r.Summary.NA != len(r.Checks) {
		t.Errorf("scan %+v summary %+v", r.Scan, r.Summary)
	}
}

func TestScanClusterRootVLLM(t *testing.T) {
	useCluster(t, clustertest.New(clustertest.RootVLLM("ai")))
	code, out, errs := run(t, "", "scan", "cluster", "--format", "json", "--deterministic")
	if code != ExitFindings || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	r := clusterJSON(t, out)
	if r.Scan.Mode != report.ModeCluster || r.Summary.Fail == 0 || r.Summary.Incomplete || r.Scan.Cluster == nil {
		t.Fatalf("scan %+v summary %+v", r.Scan, r.Summary)
	}
	code, _, _ = run(t, "", "scan", "cluster", "--fail-on", "never")
	if code != ExitOK {
		t.Errorf("--fail-on never: code=%d", code)
	}
}

func TestScanClusterIncompleteBeatsThreshold(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.Dynamic.PrependReactor("list", "networkpolicies", forbiddenList("networkpolicies"))
	useCluster(t, c)
	for _, failOn := range []string{"never", "fail", "warn"} {
		code, out, errs := run(t, "", "scan", "cluster", "--fail-on", failOn, "--format", "json")
		if code != ExitIncomplete || errs != "" {
			t.Fatalf("--fail-on %s: code=%d stderr=%q", failOn, code, errs)
		}
		r := clusterJSON(t, out)
		if !r.Summary.Incomplete || r.Summary.Unknown != 2 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "list networking.k8s.io/v1 networkpolicies in all namespaces") {
			t.Fatalf("summary %+v errors %q", r.Summary, r.Errors)
		}
	}
}

func TestScanClusterNodeProbeDenied(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.AddNode("n1")
	c.Core.PrependReactor("create", "pods", forbiddenList("pods"))
	useCluster(t, c)
	code, out, errs := run(t, "", "scan", "cluster", "--node-probe", "--fail-on", "never", "--format", "json")
	if code != ExitIncomplete || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	r := clusterJSON(t, out)
	if !r.Scan.Cluster.NodeProbe || r.Scan.Cluster.ProbeNamespace != "kube-system" {
		t.Errorf("cluster info %+v", r.Scan.Cluster)
	}
	if len(r.Errors) != 1 || !strings.HasPrefix(r.Errors[0], "node probe n1: probe denied in namespace kube-system: ") {
		t.Errorf("errors %q", r.Errors)
	}
	if got := r.Summary.Unknown; got != 1 {
		t.Errorf("unknown checks %d, want 1 (KS-PRE-004)", got)
	}
}

func TestScanClusterProbeFlagsReachProbe(t *testing.T) {
	c := clustertest.New()
	c.AddNode("n1")
	c.Core.PrependReactor("create", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New(a.GetNamespace()))
	})
	useCluster(t, c)
	code, out, errs := run(t, "", "scan", "cluster", "--node-probe", "--probe-namespace", "kshield-probe", "--probe-timeout", "5s", "--probe-image", "example.invalid/probe@sha256:abc", "--format", "json")
	if code != ExitIncomplete || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	r := clusterJSON(t, out)
	if r.Scan.Cluster.ProbeNamespace != "kshield-probe" || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "namespace kshield-probe") {
		t.Errorf("cluster %+v errors %q", r.Scan.Cluster, r.Errors)
	}
}

func TestScanClusterPassesFlagsToConnect(t *testing.T) {
	c := clustertest.New(
		clustertest.Object("v1", "Namespace", "", "a"),
		clustertest.Object("v1", "Namespace", "", "b"),
		clustertest.Object("v1", "Namespace", "", "c"),
	)
	calls := useCluster(t, c)
	code, out, errs := run(t, "", "scan", "cluster", "--kubeconfig", "kc.yaml", "--context", "prod", "-n", "b", "-n", "a", "--namespace", "c", "--format", "json")
	if code != ExitOK || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if !slices.Equal(*calls, []connectCall{{"kc.yaml", "prod"}}) {
		t.Errorf("connect calls %v", *calls)
	}
	r := clusterJSON(t, out)
	if !slices.Equal(r.Scan.Cluster.Namespaces, []string{"a", "b", "c"}) {
		t.Errorf("namespaces %v", r.Scan.Cluster.Namespaces)
	}
}

func TestScanClusterUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"probe namespace without probe": {[]string{"--probe-namespace", "x"}, "--node-probe"},
		"probe timeout without probe":   {[]string{"--probe-timeout", "5s"}, "--node-probe"},
		"probe image without probe":     {[]string{"--probe-image", "x"}, "--node-probe"},
		"zero probe timeout":            {[]string{"--node-probe", "--probe-timeout", "0s"}, "--probe-timeout"},
		"unknown format":                {[]string{"--format", "xml"}, "unknown format"},
		"pdf without out":               {[]string{"--format", "pdf"}, "--format pdf needs --out"},
		"unknown fail-on":               {[]string{"--fail-on", "maybe"}, "unknown --fail-on"},
		"sign key without evidence":     {[]string{"--sign-key", "k"}, "--sign-key needs --evidence"},
		"out inside evidence":           {[]string{"--evidence", dir, "--out", filepath.Join(dir, "r.txt")}, "must not be inside"},
		"unexpected argument":           {[]string{"extra"}, "unexpected argument"},
		"empty namespace":               {[]string{"-n", ""}, "empty value"},
		"unknown flag":                  {[]string{"--frobnicate"}, "frobnicate"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := useCluster(t, clustertest.New())
			code, out, errs := run(t, "", append([]string{"scan", "cluster"}, tc.args...)...)
			if code != ExitUsage || out != "" || !strings.Contains(errs, tc.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q, want %q", code, out, errs, tc.want)
			}
			if len(*calls) != 0 {
				t.Errorf("connected despite a usage error: %v", *calls)
			}
		})
	}
}

func TestScanClusterMissingNamespace(t *testing.T) {
	useCluster(t, clustertest.New(clustertest.Object("v1", "Namespace", "", "a")))
	code, out, errs := run(t, "", "scan", "cluster", "-n", "a", "-n", "nope")
	if code != ExitUsage || out != "" || !strings.Contains(errs, `namespace "nope" not found`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanClusterConnectError(t *testing.T) {
	old := connect
	connect = func(string, string) (*cluster.Client, error) { return nil, errors.New("no such context") }
	t.Cleanup(func() { connect = old })
	code, out, errs := run(t, "", "scan", "cluster", "--context", "gone")
	if code != ExitUsage || out != "" || !strings.Contains(errs, "no such context") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanClusterUnreachableServer(t *testing.T) {
	c := clustertest.New()
	c.Discovery.PrependReactor("get", "group", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	})
	useCluster(t, c)
	code, out, errs := run(t, "", "scan", "cluster")
	if code != ExitUsage || out != "" || !strings.Contains(errs, "connection refused") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestScanClusterOutFile(t *testing.T) {
	useCluster(t, clustertest.New(clustertest.RootVLLM("ai")))
	path := filepath.Join(t.TempDir(), "report.json")
	code, out, errs := run(t, "", "scan", "cluster", "--format", "json", "--out", path)
	if code != ExitFindings || out != "" || errs != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := clusterJSON(t, string(raw)); r.Summary.Fail == 0 {
		t.Errorf("summary %+v", r.Summary)
	}
}

func TestScanClusterWritesReportWhenIncomplete(t *testing.T) {
	c := clustertest.New()
	c.Dynamic.PrependReactor("list", "services", forbiddenList("services"))
	useCluster(t, c)
	path := filepath.Join(t.TempDir(), "report.txt")
	code, out, errs := run(t, "", "scan", "cluster", "--out", path)
	if code != ExitIncomplete || out != "" || errs != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "list v1 services in all namespaces") {
		t.Fatalf("report %q err %v", raw, err)
	}
}

func TestScanClusterEvidenceSigned(t *testing.T) {
	useCluster(t, clustertest.New(clustertest.RootVLLM("ai")))
	prefix := keygen(t)
	dir := filepath.Join(t.TempDir(), "pack")
	code, _, errs := run(t, "", "scan", "cluster", "--deterministic", "--evidence", dir, "--sign-key", prefix+".key")
	if code != ExitFindings || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	pub, err := evidence.LoadPublicKey(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	res, err := evidence.Verify(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Signature != evidence.SignatureValid {
		t.Fatalf("verify %+v", res)
	}
	code, out := verifyOut(t, dir, "--pub-key", prefix+".pub")
	if code != ExitOK || out != "signature: valid\nevidence: OK\n" {
		t.Fatalf("code=%d stdout=%q", code, out)
	}
}

func TestScanClusterDeterministic(t *testing.T) {
	scan := func() string {
		c := clustertest.New(clustertest.Object("v1", "Namespace", "", "ai"), clustertest.RootVLLM("ai"))
		useCluster(t, c)
		code, out, errs := run(t, "", "scan", "cluster", "-n", "ai", "--format", "json", "--deterministic")
		if code != ExitFindings || errs != "" {
			t.Fatalf("code=%d stderr=%q", code, errs)
		}
		return out
	}
	if a, b := scan(), scan(); a != b {
		t.Fatal("two deterministic cluster scans differ")
	}
}

func TestScanClusterHelp(t *testing.T) {
	code, _, errs := run(t, "", "scan", "cluster", "-h")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{"--node-probe", "--probe-namespace", "--probe-timeout", "3 x timeout + 15 s", "--probe-image", "--kubeconfig", "--context"} {
		if !strings.Contains(errs, want) {
			t.Errorf("help lacks %q:\n%s", want, errs)
		}
	}
}

func TestUsageListsClusterFlags(t *testing.T) {
	code, out, _ := run(t, "", "help")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{"kshield scan cluster", "--node-probe", "--probe-namespace", "--evidence"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestScanClusterUnknownProfileDoesNotConnect(t *testing.T) {
	c := clustertest.New(clustertest.RootVLLM("ai"))
	c.AddNode("n1")
	calls := useCluster(t, c)
	code, out, errs := run(t, "", "scan", "cluster", "--profile", "bogus", "--node-probe")
	if code != ExitUsage || out != "" || !strings.Contains(errs, "bogus") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	if len(*calls) != 0 || len(c.Dynamic.Actions()) != 0 || len(c.Core.Actions()) != 0 {
		t.Errorf("connect calls %v, dynamic %d, core %d", *calls, len(c.Dynamic.Actions()), len(c.Core.Actions()))
	}
}
