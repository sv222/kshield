package check

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
)

const (
	appsAPIVersion  = "apps/v1"
	kindDaemonSet   = "DaemonSet"
	kindDeployment  = "Deployment"
	labelK8sApp     = "k8s-app"
	labelAppName    = "app.kubernetes.io/name"
	labelComponent  = "app.kubernetes.io/component"
	labelPartOf     = "app.kubernetes.io/part-of"
	lsmBPF          = "bpf"
	bpfLSMConfigYes = "y"
	bpfLSMConfigNo  = "n"
	valueTrue       = "true"

	// source: https://github.com/cilium/cilium/blob/v1.20.3/install/kubernetes/cilium/templates/cilium-configmap.yaml@v1.20.3
	CiliumConfigName      = "cilium-config"
	ciliumEnableWireGuard = "enable-wireguard"
	ciliumEnableIPsec     = "enable-ipsec"

	// source: https://github.com/kyverno/kyverno/blob/v1.19.1/charts/kyverno/templates/_helpers/_labels.tpl@v1.19.1
	// source: https://github.com/kyverno/kyverno/blob/v1.19.1/charts/kyverno/templates/_helpers/_names.tpl@v1.19.1
	kyvernoPartOfWord = "kyverno"

	daemonSetReadyPath  = "/status/numberReady"
	deploymentReadyPath = "/status/readyReplicas"
	configDataPath      = "/data"

	tetragonNotReadyFormat = "Tetragon DaemonSet not ready: %d/%d pods ready"
	tetragonNotFoundMsg    = "Tetragon not found in the cluster; no runtime guard can run"
	ciliumNotReadyFormat   = "Cilium DaemonSet not ready: %d/%d pods ready"
	ciliumNotFoundMsg      = "CNI is not Cilium; L7 and FQDN egress policies cannot be enforced"
	kyvernoNotReadyFormat  = "Kyverno admission controller not ready: %d/%d"
	kyvernoNotFoundMsg     = "Kyverno not found in the cluster; no admission guard can run"
	bpfLSMMissingFormat    = "bpf is not in the active LSM list (%s); %s"
	bpfLSMConfigYesMsg     = "kernel has CONFIG_BPF_LSM=y, add bpf to the lsm= boot parameter"
	bpfLSMConfigNoMsg      = "kernel was built without CONFIG_BPF_LSM"
	bpfLSMConfigUnreadMsg  = "kernel config unreadable"
	encryptionOffMsg       = "Cilium pod-to-pod encryption is off (enable-wireguard and enable-ipsec are not true)"
	ciliumConfigMissingMsg = "cilium-config not found; encryption state unknown"
	encryptionNoCiliumMsg  = "CNI is not Cilium; kshield cannot read pod-to-pod encryption"
)

var (
	// source: https://github.com/cilium/tetragon/blob/v1.7.1/install/kubernetes/tetragon/templates/_helpers.tpl@v1.7.1
	tetragonAgentLabels = map[string]string{labelAppName: "tetragon", labelComponent: "agent"}
	// source: https://github.com/cilium/cilium/blob/v1.20.3/install/kubernetes/cilium/templates/cilium-agent/daemonset.yaml@v1.20.3
	ciliumAgentLabels = map[string]string{labelK8sApp: "cilium", labelAppName: "cilium-agent"}
	// source: https://github.com/kyverno/kyverno/blob/v1.19.1/charts/kyverno/templates/admission-controller/_helpers.tpl@v1.19.1
	kyvernoAdmissionLabels = map[string]string{labelComponent: "admission-controller"}
)

type component struct {
	kind      string
	match     func(labels map[string]string) bool
	notReady  string
	unhealthy Strength
	notFound  string
}

var (
	tetragonComponent = component{
		kind:      kindDaemonSet,
		match:     labelsMatch(tetragonAgentLabels),
		notReady:  tetragonNotReadyFormat,
		unhealthy: Violation,
		notFound:  tetragonNotFoundMsg,
	}
	ciliumComponent = component{
		kind:      kindDaemonSet,
		match:     labelsMatch(ciliumAgentLabels),
		notReady:  ciliumNotReadyFormat,
		unhealthy: Suspect,
		notFound:  ciliumNotFoundMsg,
	}
	kyvernoComponent = component{
		kind:      kindDeployment,
		match:     isKyvernoAdmission,
		notReady:  kyvernoNotReadyFormat,
		unhealthy: Violation,
		notFound:  kyvernoNotFoundMsg,
	}
)

func labelsMatch(want map[string]string) func(map[string]string) bool {
	return func(labels map[string]string) bool {
		for k, v := range want {
			if labels[k] != v {
				return false
			}
		}
		return true
	}
}

func isKyvernoAdmission(labels map[string]string) bool {
	return labelsMatch(kyvernoAdmissionLabels)(labels) && strings.Contains(labels[labelPartOf], kyvernoPartOfWord)
}

func IsCiliumAgent(o load.Object) bool {
	return isApps(o, kindDaemonSet) && ciliumComponent.match(objectLabels(o))
}

func IsPrerequisite(o load.Object) bool {
	for _, c := range []component{tetragonComponent, ciliumComponent, kyvernoComponent} {
		if isApps(o, c.kind) && c.match(objectLabels(o)) {
			return true
		}
	}
	return false
}

func isApps(o load.Object, kind string) bool {
	return o.U != nil && o.Ref.APIVersion == appsAPIVersion && o.Ref.Kind == kind
}

func objectLabels(o load.Object) map[string]string {
	return stringMapOf(dig(o.U.Object, "metadata", "labels"))
}

func appsObjects(in *Input, kind string, match func(map[string]string) bool) []load.Object {
	var out []load.Object
	for _, o := range in.Objects {
		if isApps(o, kind) && match(objectLabels(o)) {
			out = append(out, o)
		}
	}
	return out
}

func countOf(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		if t != math.Trunc(t) {
			return 0, false
		}
		return int64(t), true
	}
	return 0, false
}

func daemonSetHealth(o load.Object) (ready, desired int64, healthy bool) {
	desired, _ = countOf(dig(o.U.Object, "status", "desiredNumberScheduled"))
	ready, _ = countOf(dig(o.U.Object, "status", "numberReady"))
	return ready, desired, desired > 0 && ready == desired
}

func deploymentHealth(o load.Object) (ready, replicas int64, healthy bool) {
	replicas = 1
	if n, ok := countOf(dig(o.U.Object, "spec", "replicas")); ok {
		replicas = n
	}
	ready, _ = countOf(dig(o.U.Object, "status", "readyReplicas"))
	return ready, replicas, ready >= 1 && ready == replicas
}

func aiNamespaces(in *Input) []string {
	var out []string
	for _, w := range namespacedAIWorkloads(in) {
		out = append(out, w.Owner.Namespace)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func namespaceFindings(in *Input, msg string, s Strength) []Finding {
	var out []Finding
	for _, ns := range aiNamespaces(in) {
		out = append(out, Finding{
			Object:   load.ObjectRef{APIVersion: coreAPIVersion, Kind: kindNamespace, Name: ns},
			Message:  msg,
			Strength: s,
		})
	}
	return out
}

func (c component) run(in *Input) Result {
	if len(AIWorkloads(in)) == 0 {
		return Result{}
	}
	found := appsObjects(in, c.kind, c.match)
	if len(found) == 0 {
		return Result{Applicable: true, Findings: namespaceFindings(in, c.notFound, Violation)}
	}
	res := Result{Applicable: true}
	for _, o := range found {
		health, path := daemonSetHealth, daemonSetReadyPath
		if c.kind == kindDeployment {
			health, path = deploymentHealth, deploymentReadyPath
		}
		ready, want, ok := health(o)
		if ok {
			continue
		}
		res.Findings = append(res.Findings, Finding{
			Object:   o.Ref,
			Path:     path,
			Message:  fmt.Sprintf(c.notReady, ready, want),
			Strength: c.unhealthy,
		})
	}
	return res
}

func prePresenceTetragon(in *Input) Result {
	return tetragonComponent.run(in)
}

func prePresenceCilium(in *Input) Result {
	return ciliumComponent.run(in)
}

func prePresenceKyverno(in *Input) Result {
	return kyvernoComponent.run(in)
}

func bpfLSMMessage(n NodeFacts) string {
	reason := bpfLSMConfigUnreadMsg
	switch n.BPFLSMConfig {
	case bpfLSMConfigYes:
		reason = bpfLSMConfigYesMsg
	case bpfLSMConfigNo:
		reason = bpfLSMConfigNoMsg
	}
	return fmt.Sprintf(bpfLSMMissingFormat, strings.Join(n.LSM, ","), reason)
}

func preBPFLSM(in *Input) Result {
	if in.Cluster == nil || !in.Cluster.ProbeRan || len(in.Cluster.Nodes) == 0 || len(AIWorkloads(in)) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	for _, n := range in.Cluster.Nodes {
		switch {
		case n.Unknown != "":
			res.Findings = append(res.Findings, Finding{Object: n.Node, Message: n.Unknown, Strength: Unknown})
		case !slices.Contains(n.LSM, lsmBPF):
			res.Findings = append(res.Findings, Finding{Object: n.Node, Message: bpfLSMMessage(n), Strength: Violation})
		}
	}
	return res
}

func ciliumEncryptionOn(cm load.Object) bool {
	for _, key := range []string{ciliumEnableWireGuard, ciliumEnableIPsec} {
		if s, ok := scalarString(dig(cm.U.Object, "data", key)); ok && s == valueTrue {
			return true
		}
	}
	return false
}

func netEncryption(in *Input) Result {
	if len(AIWorkloads(in)) == 0 {
		return Result{}
	}
	agents := appsObjects(in, kindDaemonSet, ciliumComponent.match)
	if len(agents) == 0 {
		return Result{Applicable: true, Findings: namespaceFindings(in, encryptionNoCiliumMsg, Suspect)}
	}
	res := Result{Applicable: true}
	judged := map[string]bool{}
	for _, ds := range agents {
		cms := coreObjects(in, kindConfigMap, ds.Ref.Namespace, CiliumConfigName)
		if len(cms) == 0 {
			res.Findings = append(res.Findings, Finding{Object: ds.Ref, Message: ciliumConfigMissingMsg, Strength: Suspect})
			continue
		}
		if judged[ds.Ref.Namespace] {
			continue
		}
		judged[ds.Ref.Namespace] = true
		if !ciliumEncryptionOn(cms[0]) {
			res.Findings = append(res.Findings, Finding{Object: cms[0].Ref, Path: configDataPath, Message: encryptionOffMsg, Strength: Violation})
		}
	}
	return res
}
