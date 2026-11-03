package cluster

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
)

const (
	ProbeImage = "docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

	DefaultProbeNamespace = "kube-system"
	DefaultProbeTimeout   = 60 * time.Second
	defaultProbeParallel  = 8
	cleanupTimeout        = 15 * time.Second
	logLimitBytes         = 64 * 1024
	runIDLength           = 12

	probeGenerateName = "kshield-probe-"
	probeContainer    = "probe"
	probeUser         = int64(65534)
	probeCPU          = "10m"
	probeMemory       = "16Mi"
	labelManagedBy    = "app.kubernetes.io/managed-by"
	labelProbeRun     = "kshield.io/probe-run"
	managedByKshield  = "kshield"
	hostSecurityPath  = "/sys/kernel/security"
	hostBootPath      = "/boot"
	mountSecurityPath = "/host/security"
	mountBootPath     = "/host/boot"
	volumeSecurity    = "security"
	volumeBoot        = "boot"

	ProbeErrorPrefix  = "node probe "
	cleanupErrorLabel = "probe cleanup: "
	allNodes          = "*"
	reasonCancelled   = "probe cancelled"

	reasonContainerCreating = "ContainerCreating"
	hintHostPath            = " (a hostPath may be missing on the node)"
	labelOS                 = "kubernetes.io/os"
	osLinux                 = "linux"

	linePrefixLSM    = "lsm="
	linePrefixBPFLSM = "bpflsm="
	bpfLSMYes        = "CONFIG_BPF_LSM=y"
	bpfLSMNo         = "CONFIG_BPF_LSM=n"
	bpfLSMNotSet     = "# CONFIG_BPF_LSM is not set"
	bpfLSMAbsent     = "absent"
	bpfLSMUnreadable = "unreadable"

	probeScript = `printf 'lsm=%s\n' "$(cat /host/security/lsm)"
c="/host/boot/config-$(uname -r)"
if [ -r "$c" ]; then printf 'bpflsm=%s\n' "$(grep -E '^(CONFIG_BPF_LSM=|# CONFIG_BPF_LSM is not set)' "$c" || echo absent)"; else echo bpflsm=unreadable; fi
`
)

var (
	pollInterval = time.Second
	readPodLogs  = podLogs

	errProbeCancelled = errors.New(reasonCancelled)
	errProbeTimedOut  = errors.New("probe timed out")
)

type ProbeOptions struct {
	Namespace string
	Image     string
	Timeout   time.Duration
	Parallel  int
	RunID     string
}

func (o ProbeOptions) withDefaults() ProbeOptions {
	if o.Namespace == "" {
		o.Namespace = DefaultProbeNamespace
	}
	if o.Image == "" {
		o.Image = ProbeImage
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultProbeTimeout
	}
	if o.Parallel <= 0 {
		o.Parallel = defaultProbeParallel
	}
	return o
}

func ptr[T any](v T) *T { return &v }

func nodeRef(name string) load.ObjectRef {
	return load.ObjectRef{APIVersion: "v1", Kind: "Node", Name: name}
}

func ProbePod(node string, opt ProbeOptions) *corev1.Pod {
	opt = opt.withDefaults()
	deadline := max(int64(1), int64(math.Ceil(opt.Timeout.Seconds())))
	resources := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(probeCPU),
		corev1.ResourceMemory: resource.MustParse(probeMemory),
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: probeGenerateName,
			Namespace:    opt.Namespace,
			Labels: map[string]string{
				labelManagedBy: managedByKshield,
				labelProbeRun:  opt.RunID,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                     node,
			Tolerations:                  []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			RestartPolicy:                corev1.RestartPolicyNever,
			ActiveDeadlineSeconds:        &deadline,
			AutomountServiceAccountToken: ptr(false),
			EnableServiceLinks:           ptr(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				RunAsUser:      ptr(probeUser),
				RunAsGroup:     ptr(probeUser),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:    probeContainer,
				Image:   opt.Image,
				Command: []string{"sh", "-c", probeScript},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr(false),
					ReadOnlyRootFilesystem:   ptr(true),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				Resources: corev1.ResourceRequirements{Requests: resources.DeepCopy(), Limits: resources.DeepCopy()},
				VolumeMounts: []corev1.VolumeMount{
					{Name: volumeSecurity, MountPath: mountSecurityPath, ReadOnly: true},
					{Name: volumeBoot, MountPath: mountBootPath, ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				hostDirVolume(volumeSecurity, hostSecurityPath),
				hostDirVolume(volumeBoot, hostBootPath),
			},
		},
	}
}

func hostDirVolume(name, path string) corev1.Volume {
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: path, Type: ptr(corev1.HostPathDirectory)},
		},
	}
}

func ParseProbe(out string) (lsm []string, bpfLSMConfig string, err error) {
	var haveLSM, haveConfig bool
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, linePrefixLSM) && !haveLSM:
			haveLSM = true
			for _, name := range strings.Split(strings.TrimPrefix(line, linePrefixLSM), ",") {
				if name = strings.TrimSpace(name); name != "" {
					lsm = append(lsm, name)
				}
			}
		case strings.HasPrefix(line, linePrefixBPFLSM) && !haveConfig:
			haveConfig = true
			value := strings.TrimSpace(strings.TrimPrefix(line, linePrefixBPFLSM))
			switch value {
			case bpfLSMYes:
				bpfLSMConfig = "y"
			case bpfLSMNo, bpfLSMNotSet, bpfLSMAbsent:
				bpfLSMConfig = "n"
			case bpfLSMUnreadable:
			default:
				return nil, "", fmt.Errorf("unexpected %s value %q", strings.TrimSuffix(linePrefixBPFLSM, "="), value)
			}
		}
	}
	if !haveLSM {
		return nil, "", fmt.Errorf("no %s line in probe output", linePrefixLSM)
	}
	if len(lsm) == 0 {
		return nil, "", fmt.Errorf("empty %s list in probe output", strings.TrimSuffix(linePrefixLSM, "="))
	}
	return lsm, bpfLSMConfig, nil
}

type prober struct {
	c   *Client
	opt ProbeOptions
}

func Probe(ctx context.Context, c *Client, opt ProbeOptions) (check.ClusterFacts, []string) {
	opt = opt.withDefaults()
	if opt.RunID == "" {
		opt.RunID = strings.ToLower(rand.Text()[:runIDLength])
	}
	p := &prober{c: c, opt: opt}
	facts := check.ClusterFacts{ProbeRan: true}
	list, err := c.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: labelOS + "=" + osLinux})
	if err != nil {
		reason := "list nodes: " + err.Error()
		if ctx.Err() != nil {
			reason = reasonCancelled
		}
		facts.Nodes = []check.NodeFacts{{Node: nodeRef(allNodes), Unknown: reason}}
		return facts, unknownLines(facts.Nodes)
	}
	names := make([]string, 0, len(list.Items))
	for _, n := range list.Items {
		names = append(names, n.Name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return facts, nil
	}
	if reason := p.dryRun(ctx, names[0]); reason != "" {
		for _, name := range names {
			facts.Nodes = append(facts.Nodes, check.NodeFacts{Node: nodeRef(name), Unknown: reason})
		}
		return facts, unknownLines(facts.Nodes)
	}
	facts.Nodes = make([]check.NodeFacts, len(names))
	sem := make(chan struct{}, opt.Parallel)
	var wg sync.WaitGroup
	for i, name := range names {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			facts.Nodes[i] = p.node(ctx, name)
		})
	}
	wg.Wait()
	return facts, append(unknownLines(facts.Nodes), p.sweep(ctx)...)
}

func unknownLines(nodes []check.NodeFacts) []string {
	var out []string
	for _, n := range nodes {
		if n.Unknown != "" {
			out = append(out, ProbeErrorPrefix+n.Node.Name+": "+n.Unknown)
		}
	}
	return out
}

var quotedProbePodName = regexp.MustCompile(`"` + probeGenerateName + `[a-z0-9]+"`)

func (p *prober) scrub(reason string) string {
	return quotedProbePodName.ReplaceAllStringFunc(reason, func(quoted string) string {
		if quoted == `"`+p.opt.Namespace+`"` {
			return quoted
		}
		return `"` + probeGenerateName + `"`
	})
}

func (p *prober) dryRun(ctx context.Context, node string) string {
	_, err := p.c.Core.CoreV1().Pods(p.opt.Namespace).Create(ctx, ProbePod(node, p.opt), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	switch {
	case err == nil:
		return ""
	case ctx.Err() != nil:
		return reasonCancelled
	case apierrors.IsForbidden(err):
		return p.scrub(fmt.Sprintf("probe denied in namespace %s: %s", p.opt.Namespace, err))
	}
	return p.scrub(fmt.Sprintf("probe dry-run failed in namespace %s: %s", p.opt.Namespace, err))
}

func (p *prober) node(ctx context.Context, name string) check.NodeFacts {
	res := check.NodeFacts{Node: nodeRef(name)}
	fail := func(reason string) check.NodeFacts {
		res.Unknown = p.scrub(reason)
		return res
	}
	if ctx.Err() != nil {
		return fail(reasonCancelled)
	}
	createCtx, stopCreate := context.WithTimeout(ctx, p.opt.Timeout)
	created, err := p.c.Core.CoreV1().Pods(p.opt.Namespace).Create(createCtx, ProbePod(name, p.opt), metav1.CreateOptions{})
	stopCreate()
	if err != nil {
		if ctx.Err() != nil {
			return fail(reasonCancelled)
		}
		return fail("create probe pod: " + err.Error())
	}
	defer p.remove(ctx, created.Name)
	pod, err := p.wait(ctx, created.Name)
	switch {
	case errors.Is(err, errProbeCancelled):
		return fail(reasonCancelled)
	case errors.Is(err, errProbeTimedOut):
		return fail(p.describe(pod, true))
	case err != nil:
		return fail(err.Error())
	case pod.Status.Phase != corev1.PodSucceeded:
		return fail(p.describe(pod, false))
	}
	logCtx, stopLogs := context.WithTimeout(ctx, p.opt.Timeout)
	out, err := readPodLogs(logCtx, p.c, p.opt.Namespace, created.Name)
	stopLogs()
	if err != nil {
		if ctx.Err() != nil {
			return fail(reasonCancelled)
		}
		return fail("read probe logs: " + err.Error())
	}
	res.LSM, res.BPFLSMConfig, err = ParseProbe(out)
	if err != nil {
		return fail("parse probe output: " + err.Error())
	}
	return res
}

func (p *prober) wait(ctx context.Context, name string) (*corev1.Pod, error) {
	tctx, stop := context.WithTimeout(ctx, p.opt.Timeout)
	defer stop()
	stopped := func(last *corev1.Pod) (*corev1.Pod, error) {
		if ctx.Err() != nil {
			return last, errProbeCancelled
		}
		return last, errProbeTimedOut
	}
	var last *corev1.Pod
	for {
		pod, err := p.c.Core.CoreV1().Pods(p.opt.Namespace).Get(tctx, name, metav1.GetOptions{})
		if err != nil {
			if tctx.Err() != nil {
				return stopped(last)
			}
			return last, fmt.Errorf("get probe pod: %w", err)
		}
		last = pod
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			return pod, nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-tctx.Done():
			timer.Stop()
			return stopped(last)
		case <-timer.C:
		}
	}
}

func (p *prober) describe(pod *corev1.Pod, timedOut bool) string {
	if pod == nil {
		return "probe pod: timed out after " + p.opt.Timeout.String()
	}
	phase := pod.Status.Phase
	if phase == "" {
		phase = corev1.PodPending
	}
	reason := podReason(pod)
	msg := "probe pod " + string(phase)
	switch {
	case reason == reasonContainerCreating && timedOut:
		msg += ": " + reason + hintHostPath
	case reason != "":
		msg += ": " + reason
	case timedOut:
		msg += ": timed out after " + p.opt.Timeout.String()
	}
	return msg
}

func podReason(pod *corev1.Pod) string {
	for _, cs := range pod.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && w.Reason != "" {
			return w.Reason
		}
		if t := cs.State.Terminated; t != nil {
			if t.Reason != "" {
				return t.Reason
			}
			if t.ExitCode != 0 {
				return fmt.Sprintf("exit code %d", t.ExitCode)
			}
		}
	}
	return pod.Status.Reason
}

func podLogs(ctx context.Context, c *Client, namespace, name string) (string, error) {
	raw, err := c.Core.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
		Container:  probeContainer,
		LimitBytes: ptr(int64(logLimitBytes)),
	}).DoRaw(ctx)
	return string(raw), err
}

func cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), cleanupTimeout)
}

func deleteNow() metav1.DeleteOptions {
	return metav1.DeleteOptions{GracePeriodSeconds: ptr(int64(0))}
}

func (p *prober) remove(parent context.Context, name string) {
	ctx, stop := cleanupContext(parent)
	defer stop()
	_ = p.c.Core.CoreV1().Pods(p.opt.Namespace).Delete(ctx, name, deleteNow())
}

func (p *prober) sweep(parent context.Context) []string {
	ctx, stop := cleanupContext(parent)
	defer stop()
	pods := p.c.Core.CoreV1().Pods(p.opt.Namespace)
	selector := labelManagedBy + "=" + managedByKshield + "," + labelProbeRun + "=" + p.opt.RunID
	list, err := pods.List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return []string{cleanupErrorLabel + "list pods in namespace " + p.opt.Namespace + ": " + err.Error()}
	}
	var out []string
	for _, pod := range list.Items {
		if err := pods.Delete(ctx, pod.Name, deleteNow()); err != nil && !apierrors.IsNotFound(err) {
			out = append(out, fmt.Sprintf("%sdelete pod %s in namespace %s: %s", cleanupErrorLabel, pod.Name, p.opt.Namespace, err))
		}
	}
	return out
}
