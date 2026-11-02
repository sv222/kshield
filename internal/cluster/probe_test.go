package cluster

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

const (
	nodeLogs     = "lsm=lockdown,capability,landlock,yama,apparmor\nbpflsm=CONFIG_BPF_LSM=y\n"
	bpfActiveLog = "lsm=lockdown,capability,bpf\nbpflsm=CONFIG_BPF_LSM=y\n"
	probeTestNS  = "kube-system"
)

type probeSim struct {
	mu        sync.Mutex
	pods      map[string]*corev1.Pod
	seq       int
	active    int
	maxActive int
	dryRuns   int
	creates   int
	deleted   []string
	deleteOpt []metav1.DeleteOptions
	dryErr    error
	createErr map[string]error
	status    map[string]corev1.PodStatus
	logs      map[string]string
	logOut    string
	onGet     func()
	getDelay  time.Duration

	blockCreate  bool
	blockGet     bool
	swept        int
	cleanupCalls int
	deadCleanup  []string
}

func newProbeSim() *probeSim {
	return &probeSim{
		pods:      map[string]*corev1.Pod{},
		createErr: map[string]error{},
		status:    map[string]corev1.PodStatus{},
		logs:      map[string]string{},
		logOut:    nodeLogs,
	}
}

func testNode(name, os string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/os": os}}}
}

func (s *probeSim) client(nodes ...string) (*Client, *fake.Clientset) {
	objs := make([]runtime.Object, 0, len(nodes))
	for _, n := range nodes {
		objs = append(objs, testNode(n, "linux"))
	}
	return s.clientWith(objs...)
}

func (s *probeSim) clientWith(objs ...runtime.Object) (*Client, *fake.Clientset) {
	cs := fake.NewClientset(objs...)
	cs.PrependReactor("create", "pods", s.create)
	cs.PrependReactor("get", "pods", s.get)
	cs.PrependReactor("list", "pods", s.list)
	cs.PrependReactor("delete", "pods", s.delete)
	return &Client{Core: recordingClient{cs, s}}, cs
}

type recordingClient struct {
	kubernetes.Interface
	sim *probeSim
}

func (r recordingClient) CoreV1() typedcorev1.CoreV1Interface {
	return recordingCore{r.Interface.CoreV1(), r.sim}
}

type recordingCore struct {
	typedcorev1.CoreV1Interface
	sim *probeSim
}

func (r recordingCore) Pods(ns string) typedcorev1.PodInterface {
	return recordingPods{r.CoreV1Interface.Pods(ns), r.sim}
}

type recordingPods struct {
	typedcorev1.PodInterface
	sim *probeSim
}

func (p recordingPods) Create(ctx context.Context, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error) {
	if p.sim.blockCreate && len(opts.DryRun) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return p.PodInterface.Create(ctx, pod, opts)
}

func (p recordingPods) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Pod, error) {
	if p.sim.blockGet {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return p.PodInterface.Get(ctx, name, opts)
}

func (p recordingPods) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	p.sim.noteCleanupCall(ctx, "delete")
	return p.PodInterface.Delete(ctx, name, opts)
}

func (p recordingPods) List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	p.sim.noteCleanupCall(ctx, "list")
	return p.PodInterface.List(ctx, opts)
}

func (s *probeSim) noteCleanupCall(ctx context.Context, op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupCalls++
	if ctx.Err() != nil {
		s.deadCleanup = append(s.deadCleanup, op)
	}
}

func (s *probeSim) assertCleanup(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.swept != 0 {
		t.Errorf("sweep found %d pods the per-node delete missed", s.swept)
	}
	if len(s.deadCleanup) != 0 {
		t.Errorf("cleanup calls with a done context: %v", s.deadCleanup)
	}
}

func (s *probeSim) create(action clienttesting.Action) (bool, runtime.Object, error) {
	ca := action.(clienttesting.CreateActionImpl)
	pod := ca.GetObject().(*corev1.Pod).DeepCopy()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(ca.CreateOptions.DryRun) > 0 {
		s.dryRuns++
		if s.dryErr != nil {
			return true, nil, s.dryErr
		}
		return true, pod, nil
	}
	if err := s.createErr[pod.Spec.NodeName]; err != nil {
		return true, nil, err
	}
	s.creates++
	s.seq++
	pod.Name = fmt.Sprintf("%s%d", pod.GenerateName, s.seq)
	pod.Namespace = ca.GetNamespace()
	pod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded}
	if st, ok := s.status[pod.Spec.NodeName]; ok {
		pod.Status = st
	}
	s.pods[pod.Name] = pod
	s.active++
	s.maxActive = max(s.maxActive, s.active)
	return true, pod.DeepCopy(), nil
}

func (s *probeSim) get(action clienttesting.Action) (bool, runtime.Object, error) {
	if action.GetSubresource() == "log" {
		s.mu.Lock()
		defer s.mu.Unlock()
		return true, &runtime.Unknown{Raw: []byte(s.logOut)}, nil
	}
	ga := action.(clienttesting.GetAction)
	if s.onGet != nil {
		s.onGet()
	}
	if s.getDelay > 0 {
		time.Sleep(s.getDelay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pod, ok := s.pods[ga.GetName()]
	if !ok {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, ga.GetName())
	}
	return true, pod.DeepCopy(), nil
}

func (s *probeSim) useNodeLogs(t *testing.T) {
	t.Helper()
	old := readPodLogs
	readPodLogs = func(ctx context.Context, c *Client, ns, name string) (string, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		pod, ok := s.pods[name]
		if !ok {
			return "", fmt.Errorf("pod %s not found", name)
		}
		return s.logs[pod.Spec.NodeName], nil
	}
	t.Cleanup(func() { readPodLogs = old })
}

func (s *probeSim) list(action clienttesting.Action) (bool, runtime.Object, error) {
	la := action.(clienttesting.ListAction)
	sel := la.GetListRestrictions().Labels
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &corev1.PodList{}
	for _, name := range sortedKeys(s.pods) {
		pod := s.pods[name]
		if sel.Matches(labels.Set(pod.Labels)) {
			out.Items = append(out.Items, *pod.DeepCopy())
		}
	}
	s.swept += len(out.Items)
	return true, out, nil
}

func (s *probeSim) delete(action clienttesting.Action) (bool, runtime.Object, error) {
	da := action.(clienttesting.DeleteActionImpl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, da.GetName())
	s.deleteOpt = append(s.deleteOpt, da.DeleteOptions)
	if _, ok := s.pods[da.GetName()]; ok {
		delete(s.pods, da.GetName())
		s.active--
	}
	return true, nil, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func fastProbe(t *testing.T) {
	t.Helper()
	old := pollInterval
	pollInterval = time.Millisecond
	t.Cleanup(func() { pollInterval = old })
}

func testOptions() ProbeOptions {
	return ProbeOptions{Namespace: probeTestNS, Timeout: 2 * time.Second, Parallel: 4, RunID: "run1"}
}

func TestProbePodSpec(t *testing.T) {
	opt := ProbeOptions{Namespace: "probe-ns", Image: "example.test/busybox:1@sha256:abc", Timeout: 90 * time.Second, RunID: "r-42"}
	p := ProbePod("worker-1", opt)
	if p.GenerateName != "kshield-probe-" || p.Name != "" || p.Namespace != "probe-ns" {
		t.Errorf("meta %q %q %q", p.GenerateName, p.Name, p.Namespace)
	}
	if got := p.Labels; len(got) != 2 || got["app.kubernetes.io/managed-by"] != "kshield" || got["kshield.io/probe-run"] != "r-42" {
		t.Errorf("labels %v", got)
	}
	s := p.Spec
	if s.NodeName != "worker-1" || s.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("node %q restart %q", s.NodeName, s.RestartPolicy)
	}
	if len(s.Tolerations) != 1 || s.Tolerations[0] != (corev1.Toleration{Operator: corev1.TolerationOpExists}) {
		t.Errorf("tolerations %+v", s.Tolerations)
	}
	if s.ActiveDeadlineSeconds == nil || *s.ActiveDeadlineSeconds != 90 {
		t.Errorf("activeDeadlineSeconds %v", s.ActiveDeadlineSeconds)
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken || s.EnableServiceLinks == nil || *s.EnableServiceLinks {
		t.Errorf("automount %v serviceLinks %v", s.AutomountServiceAccountToken, s.EnableServiceLinks)
	}
	psc := s.SecurityContext
	if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.RunAsUser == nil || *psc.RunAsUser != 65534 || psc.RunAsGroup == nil || *psc.RunAsGroup != 65534 {
		t.Fatalf("pod securityContext %+v", psc)
	}
	if psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("seccomp %+v", psc.SeccompProfile)
	}
	if len(s.Containers) != 1 || len(s.InitContainers) != 0 {
		t.Fatalf("containers %d init %d", len(s.Containers), len(s.InitContainers))
	}
	c := s.Containers[0]
	if c.Name != "probe" || c.Image != "example.test/busybox:1@sha256:abc" {
		t.Errorf("container %q image %q", c.Name, c.Image)
	}
	if !slices.Equal(c.Command, []string{"sh", "-c", probeScript}) {
		t.Errorf("command %q", c.Command)
	}
	sc := c.SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("container securityContext %+v", sc)
	}
	if sc.Privileged != nil {
		t.Errorf("privileged must be unset, got %v", *sc.Privileged)
	}
	if sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 {
		t.Errorf("capabilities %+v", sc.Capabilities)
	}
	for name, rl := range map[string]corev1.ResourceList{"requests": c.Resources.Requests, "limits": c.Resources.Limits} {
		if rl.Cpu().String() != "10m" || rl.Memory().String() != "16Mi" || len(rl) != 2 {
			t.Errorf("%s %v", name, rl)
		}
	}
	wantVol := map[string]string{"/sys/kernel/security": "/host/security", "/boot": "/host/boot"}
	if len(s.Volumes) != 2 {
		t.Fatalf("volumes %+v", s.Volumes)
	}
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m
	}
	for _, v := range s.Volumes {
		hp := v.HostPath
		if hp == nil || hp.Type == nil || *hp.Type != corev1.HostPathDirectory {
			t.Errorf("volume %s: hostPath %+v", v.Name, hp)
			continue
		}
		m, ok := mounts[v.Name]
		if !ok || m.MountPath != wantVol[hp.Path] || !m.ReadOnly {
			t.Errorf("volume %s (%s): mount %+v", v.Name, hp.Path, m)
		}
		delete(wantVol, hp.Path)
	}
	if len(wantVol) != 0 || len(c.VolumeMounts) != 2 {
		t.Errorf("host paths not mounted: %v, mounts %+v", wantVol, c.VolumeMounts)
	}
}

func TestProbePodDefaults(t *testing.T) {
	p := ProbePod("n", ProbeOptions{RunID: "r"})
	c := p.Spec.Containers[0]
	if p.Namespace != "kube-system" || c.Image != ProbeImage || *p.Spec.ActiveDeadlineSeconds != 60 {
		t.Errorf("namespace %q image %q deadline %d", p.Namespace, c.Image, *p.Spec.ActiveDeadlineSeconds)
	}
	if !strings.Contains(ProbeImage, "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e") {
		t.Errorf("ProbeImage %q is not the pinned image", ProbeImage)
	}
}

func TestProbeScript(t *testing.T) {
	for _, want := range []string{
		`printf 'lsm=%s\n' "$(cat /host/security/lsm)"`,
		`c="/host/boot/config-$(uname -r)"`,
		`grep -E '^(CONFIG_BPF_LSM=|# CONFIG_BPF_LSM is not set)' "$c" || echo absent`,
		`else echo bpflsm=unreadable; fi`,
	} {
		if !strings.Contains(probeScript, want) {
			t.Errorf("script lacks %q", want)
		}
	}
}

func TestParseProbe(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		lsm     []string
		cfg     string
		wantErr bool
	}{
		{"apparmor node", nodeLogs, []string{"lockdown", "capability", "landlock", "yama", "apparmor"}, "y", false},
		{"bpf active", bpfActiveLog, []string{"lockdown", "capability", "bpf"}, "y", false},
		{"not set", "lsm=capability\nbpflsm=# CONFIG_BPF_LSM is not set\n", []string{"capability"}, "n", false},
		{"absent", "lsm=capability\nbpflsm=absent\n", []string{"capability"}, "n", false},
		{"explicit n", "lsm=capability\nbpflsm=CONFIG_BPF_LSM=n\n", []string{"capability"}, "n", false},
		{"unreadable", "lsm=capability\nbpflsm=unreadable\n", []string{"capability"}, "", false},
		{"spaces and crlf", "lsm= lockdown , yama \r\nbpflsm=CONFIG_BPF_LSM=y\r\n", []string{"lockdown", "yama"}, "y", false},
		{"empty lsm", "lsm=\nbpflsm=unreadable\n", nil, "", true},
		{"no bpflsm line", "lsm=capability\n", []string{"capability"}, "", false},
		{"no lsm line", "bpflsm=CONFIG_BPF_LSM=y\n", nil, "", true},
		{"garbage", "cat: can't open '/host/security/lsm'\nsomething else\n", nil, "", true},
		{"empty", "", nil, "", true},
		{"unknown bpflsm value", "lsm=capability\nbpflsm=CONFIG_BPF_LSM=m\n", nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lsm, cfg, err := ParseProbe(tc.out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if !slices.Equal(lsm, tc.lsm) || cfg != tc.cfg {
				t.Errorf("got %q %q, want %q %q", lsm, cfg, tc.lsm, tc.cfg)
			}
		})
	}
}

func TestProbeSuccess(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.logs["n1"] = bpfActiveLog
	sim.logs["n2"] = nodeLogs
	sim.useNodeLogs(t)
	c, _ := sim.client("n2", "n1")
	facts, errs := Probe(context.Background(), c, testOptions())
	if !facts.ProbeRan || len(errs) != 0 {
		t.Fatalf("ran %v errors %v", facts.ProbeRan, errs)
	}
	if len(facts.Nodes) != 2 || facts.Nodes[0].Node != nodeRef("n1") || facts.Nodes[1].Node != nodeRef("n2") {
		t.Fatalf("nodes %+v", facts.Nodes)
	}
	n1, n2 := facts.Nodes[0], facts.Nodes[1]
	if !slices.Equal(n1.LSM, []string{"lockdown", "capability", "bpf"}) || n1.BPFLSMConfig != "y" || n1.Unknown != "" {
		t.Errorf("n1 %+v", n1)
	}
	if !slices.Equal(n2.LSM, []string{"lockdown", "capability", "landlock", "yama", "apparmor"}) || n2.BPFLSMConfig != "y" || n2.Unknown != "" {
		t.Errorf("n2 %+v", n2)
	}
	if sim.dryRuns != 1 || sim.creates != 2 || len(sim.pods) != 0 {
		t.Errorf("dryRuns %d creates %d left %d", sim.dryRuns, sim.creates, len(sim.pods))
	}
	for _, o := range sim.deleteOpt {
		if o.GracePeriodSeconds == nil || *o.GracePeriodSeconds != 0 {
			t.Errorf("delete options %+v", o)
		}
	}
	sim.assertCleanup(t)
}

func TestProbeDryRunDenied(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.dryErr = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "kshield-probe-", errors.New(`violates PodSecurity "restricted:latest": restricted volume types (volumes "security", "boot")`))
	c, _ := sim.client("n1", "n2")
	facts, errs := Probe(context.Background(), c, testOptions())
	want := `probe denied in namespace kube-system: pods "kshield-probe-" is forbidden: violates PodSecurity "restricted:latest": restricted volume types (volumes "security", "boot")`
	if !facts.ProbeRan || len(facts.Nodes) != 2 {
		t.Fatalf("facts %+v", facts)
	}
	for i, n := range facts.Nodes {
		if n.Unknown != want || len(n.LSM) != 0 || n.BPFLSMConfig != "" {
			t.Errorf("node %d %+v", i, n)
		}
	}
	if !slices.Equal(errs, []string{"node probe n1: " + want, "node probe n2: " + want}) {
		t.Errorf("errors %q", errs)
	}
	if sim.creates != 0 || sim.dryRuns != 1 || len(sim.deleted) != 0 {
		t.Errorf("creates %d dryRuns %d deleted %v", sim.creates, sim.dryRuns, sim.deleted)
	}
}

func TestProbeDryRunOtherError(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.dryErr = apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "kube-system")
	c, _ := sim.client("n1")
	facts, errs := Probe(context.Background(), c, testOptions())
	want := `probe dry-run failed in namespace kube-system: namespaces "kube-system" not found`
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != want || len(errs) != 1 || sim.creates != 0 {
		t.Fatalf("nodes %+v errors %q creates %d", facts.Nodes, errs, sim.creates)
	}
}

func TestProbeCreateDeniedAfterDryRun(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.createErr["n1"] = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "kshield-probe-", errors.New("quota exceeded"))
	c, _ := sim.client("n1", "n2")
	facts, errs := Probe(context.Background(), c, testOptions())
	if len(facts.Nodes) != 2 {
		t.Fatalf("nodes %+v", facts.Nodes)
	}
	wantReason := `create probe pod: pods "kshield-probe-" is forbidden: quota exceeded`
	if facts.Nodes[0].Unknown != wantReason {
		t.Errorf("n1 %+v", facts.Nodes[0])
	}
	if facts.Nodes[1].Unknown != "" || facts.Nodes[1].BPFLSMConfig != "y" {
		t.Errorf("n2 %+v", facts.Nodes[1])
	}
	if !slices.Equal(errs, []string{"node probe n1: " + wantReason}) {
		t.Errorf("errors %q", errs)
	}
	if len(sim.pods) != 0 {
		t.Errorf("pods left %v", sortedKeys(sim.pods))
	}
}

func TestProbeReasonsHoldNoPodName(t *testing.T) {
	fastProbe(t)
	t.Run("dry run", func(t *testing.T) {
		sim := newProbeSim()
		sim.dryErr = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "kshield-probe-x7k2p", errors.New("denied"))
		c, _ := sim.client("n1")
		facts, _ := Probe(context.Background(), c, testOptions())
		if want := `probe denied in namespace kube-system: pods "kshield-probe-" is forbidden: denied`; facts.Nodes[0].Unknown != want {
			t.Errorf("got %q, want %q", facts.Nodes[0].Unknown, want)
		}
	})
	t.Run("create", func(t *testing.T) {
		sim := newProbeSim()
		sim.createErr["n1"] = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "kshield-probe-x7k2p", errors.New("quota exceeded"))
		c, _ := sim.client("n1")
		facts, _ := Probe(context.Background(), c, testOptions())
		if want := `create probe pod: pods "kshield-probe-" is forbidden: quota exceeded`; facts.Nodes[0].Unknown != want {
			t.Errorf("got %q, want %q", facts.Nodes[0].Unknown, want)
		}
	})
	t.Run("get", func(t *testing.T) {
		sim := newProbeSim()
		sim.onGet = func() {
			sim.mu.Lock()
			defer sim.mu.Unlock()
			clear(sim.pods)
		}
		c, _ := sim.client("n1")
		facts, errs := Probe(context.Background(), c, testOptions())
		want := `get probe pod: pods "kshield-probe-" not found`
		if facts.Nodes[0].Unknown != want || !slices.Contains(errs, "node probe n1: "+want) {
			t.Errorf("got %q errors %q, want %q", facts.Nodes[0].Unknown, errs, want)
		}
	})
	t.Run("namespace kept", func(t *testing.T) {
		sim := newProbeSim()
		sim.dryErr = apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "kshield-probe-ns")
		c, _ := sim.client("n1")
		opt := testOptions()
		opt.Namespace = "kshield-probe-ns"
		facts, _ := Probe(context.Background(), c, opt)
		if want := `probe dry-run failed in namespace kshield-probe-ns: namespaces "kshield-probe-ns" not found`; facts.Nodes[0].Unknown != want {
			t.Errorf("got %q, want %q", facts.Nodes[0].Unknown, want)
		}
	})
}

func TestProbeTimeout(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.status["n1"] = corev1.PodStatus{
		Phase: corev1.PodPending,
		ContainerStatuses: []corev1.ContainerStatus{{
			Name:  "probe",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "secret detail"}},
		}},
	}
	sim.status["n3"] = corev1.PodStatus{Phase: corev1.PodPending}
	sim.status["n4"] = corev1.PodStatus{
		Phase:             corev1.PodPending,
		ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}},
	}
	c, _ := sim.client("n1", "n2", "n3", "n4")
	opt := testOptions()
	opt.Timeout = 40 * time.Millisecond
	facts, errs := Probe(context.Background(), c, opt)
	if len(facts.Nodes) != 4 {
		t.Fatalf("nodes %+v", facts.Nodes)
	}
	if got := facts.Nodes[0].Unknown; got != "probe pod Pending: ImagePullBackOff" {
		t.Errorf("n1 %q", got)
	}
	if facts.Nodes[1].Unknown != "" {
		t.Errorf("n2 %+v", facts.Nodes[1])
	}
	if got := facts.Nodes[2].Unknown; got != "probe pod Pending: timed out after 40ms" {
		t.Errorf("n3 %q", got)
	}
	hint := "probe pod Pending: ContainerCreating (a hostPath may be missing on the node)"
	if got := facts.Nodes[3].Unknown; got != hint {
		t.Errorf("n4 %q", got)
	}
	wantErrs := []string{
		"node probe n1: probe pod Pending: ImagePullBackOff",
		"node probe n3: probe pod Pending: timed out after 40ms",
		"node probe n4: " + hint,
	}
	if !slices.Equal(errs, wantErrs) {
		t.Errorf("errors %q", errs)
	}
	if len(sim.pods) != 0 || len(sim.deleted) != 4 {
		t.Errorf("pods left %v, deleted %v", sortedKeys(sim.pods), sim.deleted)
	}
	sim.assertCleanup(t)
}

func TestProbeTimeoutNothingObserved(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.blockGet = true
	c, _ := sim.client("n1")
	opt := testOptions()
	opt.Timeout = 30 * time.Millisecond
	facts, errs := Probe(context.Background(), c, opt)
	want := "probe pod: timed out after 30ms"
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != want || !slices.Equal(errs, []string{"node probe n1: " + want}) {
		t.Errorf("nodes %+v errors %q", facts.Nodes, errs)
	}
	sim.assertCleanup(t)
}

func TestProbeCreateBoundedByTimeout(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.blockCreate = true
	c, _ := sim.client("n1")
	opt := testOptions()
	opt.Timeout = 30 * time.Millisecond
	start := time.Now()
	facts, errs := Probe(context.Background(), c, opt)
	want := "create probe pod: context deadline exceeded"
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != want || !slices.Equal(errs, []string{"node probe n1: " + want}) {
		t.Errorf("nodes %+v errors %q", facts.Nodes, errs)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("create was not bounded: %v", time.Since(start))
	}
}

func TestProbeLogReadBoundedByTimeout(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	old := readPodLogs
	readPodLogs = func(ctx context.Context, _ *Client, _, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	t.Cleanup(func() { readPodLogs = old })
	c, _ := sim.client("n1")
	opt := testOptions()
	opt.Timeout = 30 * time.Millisecond
	facts, errs := Probe(context.Background(), c, opt)
	want := "read probe logs: context deadline exceeded"
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != want || !slices.Equal(errs, []string{"node probe n1: " + want}) {
		t.Errorf("nodes %+v errors %q", facts.Nodes, errs)
	}
	sim.assertCleanup(t)
}

func TestProbeFailedPod(t *testing.T) {
	fastProbe(t)
	cases := []struct {
		name   string
		status corev1.PodStatus
		want   string
	}{
		{"terminated reason", corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1}}}}}, "probe pod Failed: Error"},
		{"exit code only", corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 126}}}}}, "probe pod Failed: exit code 126"},
		{"pod reason", corev1.PodStatus{Phase: corev1.PodFailed, Reason: "DeadlineExceeded"}, "probe pod Failed: DeadlineExceeded"},
		{"no reason", corev1.PodStatus{Phase: corev1.PodFailed}, "probe pod Failed"},
		{"first waiting wins", corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{
			{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CreateContainerError"}}},
			{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error"}}},
		}}, "probe pod Failed: CreateContainerError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := newProbeSim()
			sim.status["n1"] = tc.status
			c, _ := sim.client("n1")
			facts, errs := Probe(context.Background(), c, testOptions())
			if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != tc.want || !slices.Equal(errs, []string{"node probe n1: " + tc.want}) {
				t.Errorf("nodes %+v errors %q", facts.Nodes, errs)
			}
			if len(sim.pods) != 0 {
				t.Errorf("pods left %v", sortedKeys(sim.pods))
			}
			sim.assertCleanup(t)
		})
	}
}

func TestProbeBadOutput(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.logOut = "lsm=\n"
	c, _ := sim.client("n1")
	facts, errs := Probe(context.Background(), c, testOptions())
	want := "parse probe output: empty lsm list in probe output"
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != want || !slices.Equal(errs, []string{"node probe n1: " + want}) {
		t.Fatalf("nodes %+v errors %q", facts.Nodes, errs)
	}
	if len(sim.pods) != 0 {
		t.Errorf("pods left %v", sortedKeys(sim.pods))
	}
}

func TestProbeDeletesOnCancel(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	sim.status["n1"] = corev1.PodStatus{Phase: corev1.PodRunning}
	c, _ := sim.client("n1")
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	sim.onGet = func() { once.Do(cancel) }
	opt := testOptions()
	opt.Timeout = time.Minute
	facts, errs := Probe(ctx, c, opt)
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != "probe cancelled" || !slices.Equal(errs, []string{"node probe n1: probe cancelled"}) {
		t.Fatalf("nodes %+v errors %q", facts.Nodes, errs)
	}
	if len(sim.deleted) == 0 || len(sim.pods) != 0 {
		t.Errorf("deleted %v, left %v", sim.deleted, sortedKeys(sim.pods))
	}
	if o := sim.deleteOpt[0]; o.GracePeriodSeconds == nil || *o.GracePeriodSeconds != 0 {
		t.Errorf("delete options %+v", o)
	}
	if sim.cleanupCalls < 2 {
		t.Errorf("expected the per-node delete and the sweep list, saw %d cleanup calls", sim.cleanupCalls)
	}
	sim.assertCleanup(t)
}

func TestProbeCancelDuringListNodes(t *testing.T) {
	sim := newProbeSim()
	c, cs := sim.client("n1")
	ctx, cancel := context.WithCancel(context.Background())
	cs.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, errors.New("context canceled")
	})
	facts, errs := Probe(ctx, c, testOptions())
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != "probe cancelled" || !slices.Equal(errs, []string{"node probe *: probe cancelled"}) {
		t.Errorf("nodes %+v errors %q", facts.Nodes, errs)
	}
}

func TestProbeCancelDuringDryRun(t *testing.T) {
	sim := newProbeSim()
	c, cs := sim.client("n1", "n2")
	ctx, cancel := context.WithCancel(context.Background())
	cs.PrependReactor("create", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if len(a.(clienttesting.CreateActionImpl).CreateOptions.DryRun) == 0 {
			return false, nil, nil
		}
		cancel()
		return true, nil, errors.New("context canceled")
	})
	facts, errs := Probe(ctx, c, testOptions())
	if len(facts.Nodes) != 2 || len(errs) != 2 || sim.creates != 0 {
		t.Fatalf("nodes %+v errors %q creates %d", facts.Nodes, errs, sim.creates)
	}
	for _, n := range facts.Nodes {
		if n.Unknown != "probe cancelled" {
			t.Errorf("node %s: %q", n.Node.Name, n.Unknown)
		}
	}
}

func TestProbeOnlyLinuxNodes(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	c, cs := sim.clientWith(testNode("lin-b", "linux"), testNode("win-a", "windows"), testNode("lin-a", "linux"), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "unlabelled"}})
	facts, errs := Probe(context.Background(), c, testOptions())
	if len(errs) != 0 || len(facts.Nodes) != 2 || facts.Nodes[0].Node.Name != "lin-a" || facts.Nodes[1].Node.Name != "lin-b" {
		t.Fatalf("nodes %+v errors %q", facts.Nodes, errs)
	}
	if sim.creates != 2 {
		t.Errorf("creates %d", sim.creates)
	}
	for _, a := range cs.Actions() {
		if la, ok := a.(clienttesting.ListAction); ok && a.GetResource().Resource == "nodes" {
			if got := la.GetListRestrictions().Labels.String(); got != "kubernetes.io/os=linux" {
				t.Errorf("node selector %q", got)
			}
		}
	}
}

func TestProbeCancelledBeforeStart(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	c, _ := sim.client("n1", "n2")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	facts, errs := Probe(ctx, c, testOptions())
	if len(facts.Nodes) != 2 || len(errs) != 2 || sim.creates != 0 {
		t.Fatalf("nodes %+v errors %q creates %d", facts.Nodes, errs, sim.creates)
	}
	for _, n := range facts.Nodes {
		if n.Unknown == "" {
			t.Errorf("node %s has no reason", n.Node.Name)
		}
	}
}

func TestCleanupContextSurvivesCancel(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, stop := cleanupContext(parent)
	defer stop()
	if err := ctx.Err(); err != nil {
		t.Fatalf("cleanup context is already done: %v", err)
	}
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > cleanupTimeout || time.Until(dl) < cleanupTimeout-5*time.Second {
		t.Errorf("deadline %v ok %v", dl, ok)
	}
	if cleanupTimeout != 15*time.Second {
		t.Errorf("cleanup timeout %v", cleanupTimeout)
	}
}

func TestProbeNodeListFailure(t *testing.T) {
	sim := newProbeSim()
	c, cs := sim.client("n1")
	cs.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	facts, errs := Probe(context.Background(), c, testOptions())
	if !facts.ProbeRan || len(facts.Nodes) != 1 {
		t.Fatalf("facts %+v", facts)
	}
	want := "list nodes: connection refused"
	if n := facts.Nodes[0]; n.Node != nodeRef("*") || n.Unknown != want {
		t.Errorf("node %+v", n)
	}
	if !slices.Equal(errs, []string{"node probe *: " + want}) {
		t.Errorf("errors %q", errs)
	}
	if sim.dryRuns != 0 || sim.creates != 0 {
		t.Errorf("dryRuns %d creates %d", sim.dryRuns, sim.creates)
	}
}

func TestProbeNoNodes(t *testing.T) {
	sim := newProbeSim()
	c, _ := sim.client()
	facts, errs := Probe(context.Background(), c, testOptions())
	if !facts.ProbeRan || len(facts.Nodes) != 0 || len(errs) != 0 || sim.dryRuns != 0 || sim.creates != 0 {
		t.Errorf("facts %+v errors %q dryRuns %d creates %d", facts, errs, sim.dryRuns, sim.creates)
	}
}

func TestProbeSweepsLeftovers(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	mine := map[string]string{"app.kubernetes.io/managed-by": "kshield", "kshield.io/probe-run": "run1"}
	other := map[string]string{"app.kubernetes.io/managed-by": "kshield", "kshield.io/probe-run": "run2"}
	sim.pods["leftover"] = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "leftover", Namespace: probeTestNS, Labels: mine}}
	sim.pods["other-run"] = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other-run", Namespace: probeTestNS, Labels: other}}
	c, _ := sim.client("n1")
	Probe(context.Background(), c, testOptions())
	if !slices.Contains(sim.deleted, "leftover") {
		t.Errorf("leftover not deleted: %v", sim.deleted)
	}
	if _, ok := sim.pods["other-run"]; !ok || slices.Contains(sim.deleted, "other-run") {
		t.Errorf("pod of another run was touched: %v", sim.deleted)
	}
}

func TestProbeCleanupFailure(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	c, cs := sim.client("n1")
	cs.PrependReactor("delete", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "kshield-probe-1", errors.New("no delete right"))
	})
	facts, errs := Probe(context.Background(), c, testOptions())
	if len(facts.Nodes) != 1 || facts.Nodes[0].Unknown != "" {
		t.Fatalf("nodes %+v", facts.Nodes)
	}
	want := `probe cleanup: delete pod kshield-probe-1 in namespace kube-system: pods "kshield-probe-1" is forbidden: no delete right`
	if !slices.Equal(errs, []string{want}) {
		t.Errorf("errors %q", errs)
	}
}

func TestProbeParallelLimit(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	c, _ := sim.client("n1", "n2", "n3", "n4", "n5")
	var overlapped atomic.Bool
	old := readPodLogs
	readPodLogs = func(ctx context.Context, c *Client, ns, name string) (string, error) {
		deadline := time.Now().Add(time.Second)
		for !overlapped.Load() && time.Now().Before(deadline) {
			sim.mu.Lock()
			overlapped.Store(sim.active >= 2)
			sim.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
		return old(ctx, c, ns, name)
	}
	t.Cleanup(func() { readPodLogs = old })
	opt := testOptions()
	opt.Parallel = 2
	facts, errs := Probe(context.Background(), c, opt)
	if len(facts.Nodes) != 5 || len(errs) != 0 {
		t.Fatalf("nodes %d errors %q", len(facts.Nodes), errs)
	}
	if sim.maxActive != 2 {
		t.Errorf("max pods at once %d, want 2", sim.maxActive)
	}
}

func TestProbeRunIDDefault(t *testing.T) {
	fastProbe(t)
	sim := newProbeSim()
	c, cs := sim.client("n1")
	opt := testOptions()
	opt.RunID = ""
	Probe(context.Background(), c, opt)
	var ids []string
	for _, a := range cs.Actions() {
		if ca, ok := a.(clienttesting.CreateActionImpl); ok && a.GetResource().Resource == "pods" {
			ids = append(ids, ca.GetObject().(*corev1.Pod).Labels["kshield.io/probe-run"])
		}
	}
	if len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] {
		t.Errorf("run ids %q", ids)
	}
}

func TestProbeVerbs(t *testing.T) {
	fastProbe(t)
	allowed := map[string]bool{
		"create/pods/": true,
		"get/pods/":    true,
		"list/pods/":   true,
		"delete/pods/": true,
		"get/pods/log": true,
		"list/nodes/":  true,
	}
	cases := map[string]func(*probeSim){
		"success": func(*probeSim) {},
		"denied": func(s *probeSim) {
			s.dryErr = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "p", errors.New("no"))
		},
		"pending": func(s *probeSim) { s.status["n1"] = corev1.PodStatus{Phase: corev1.PodPending} },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			sim := newProbeSim()
			setup(sim)
			c, cs := sim.client("n1", "n2")
			opt := testOptions()
			opt.Timeout = 30 * time.Millisecond
			Probe(context.Background(), c, opt)
			seen := map[string]bool{}
			for _, a := range cs.Actions() {
				key := a.GetVerb() + "/" + a.GetResource().Resource + "/" + a.GetSubresource()
				seen[key] = true
				if !allowed[key] {
					t.Errorf("verb not allowed: %s", key)
				}
				switch a.GetResource().Resource {
				case "pods":
					if a.GetNamespace() != probeTestNS {
						t.Errorf("%s in namespace %q", key, a.GetNamespace())
					}
				case "nodes":
					if a.GetNamespace() != "" {
						t.Errorf("%s in namespace %q", key, a.GetNamespace())
					}
				default:
					t.Errorf("resource %s", a.GetResource().Resource)
				}
			}
			if name == "success" {
				for _, k := range []string{"create/pods/", "get/pods/", "list/pods/", "delete/pods/", "get/pods/log", "list/nodes/"} {
					if !seen[k] {
						t.Errorf("expected %s", k)
					}
				}
			}
		})
	}
}
