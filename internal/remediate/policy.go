package remediate

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/sv222/kshield/internal/check"
)

const (
	modeAudit = "audit"

	ciliumAPIVersion   = "cilium.io/v2"
	tetragonAPIVersion = "cilium.io/v1alpha1"
	kyvernoAPIVersion  = "kyverno.io/v1"
	kindCNP            = "CiliumNetworkPolicy"
	kindTracingNS      = "TracingPolicyNamespaced"
	kindKyvernoPolicy  = "Policy"

	egressPolicyName    = "kshield-egress"
	apiServerPolicyName = "kshield-egress-apiserver"
	shellExecPolicyName = "kshield-shell-exec"
	connectPolicyName   = "kshield-egress-connect"
	admissionPolicyName = "kshield-admission"
	podSecurityRuleName = "kshield-pod-security"
	pickleRuleName      = "kshield-no-pickle-load"

	actionPost      = "Post"
	actionSigkill   = "Sigkill"
	actionOverride  = "Override"
	overrideEPERM   = -1
	kyvernoAudit    = "Audit"
	kyvernoEnforce  = "Enforce"
	maxFQDNLength   = 255
	ciliumNSLabel   = "k8s:io.kubernetes.pod.namespace"
	entityAPIServer = "kube-apiserver"
	rayHeadLabel    = "ray.io/node-type"
	rayHeadValue    = "head"
	shellExecMsg    = "kshield shell-exec guard: a shell started by a process that is not a shell and not PID 1"
	connectMsg      = "kshield egress-connect guard: TCP connect to an address outside the private ranges and --allow-cidr"
	pickleMsgFormat = "kshield: a container starts vLLM with --trust-remote-code or a pickle --load-format (%s)"
	pickleKeyFormat = "{{ regex_match('%s', join(' ', [element.command || `[]`, element.args || `[]`][])) }}"
	containersList  = "request.object.spec.[ephemeralContainers, initContainers, containers][]"
)

var (
	policyChecks  = []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003"}
	shellSuffixes = []string{"/sh", "/bash", "/dash", "/ash", "/zsh", "/ksh", "/busybox"}
	privateCIDRs  = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/32", "::/128"}
	// source: https://github.com/cilium/cilium/blob/v1.20.3/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml@v1.20.3
	fqdnPattern        = regexp.MustCompile(`^([-a-zA-Z0-9_]+[.]?)+$`)
	clusterDNSSuffixes = []string{".svc", ".cluster.local"}
)

type PolicyOptions struct {
	Mode                string
	AllowFQDN           []string
	AllowCIDR           []string
	PeerNamespaces      map[string][]string
	APIServerNamespaces []string
}

type egressPeers struct {
	fqdns, cidrs, namespaces []string
}

func PolicyPeers(in *check.Input) (map[string][]string, []string) {
	ai, apiServer := []string{}, []string{}
	for _, w := range check.AIWorkloads(in) {
		ns := w.Owner.Namespace
		if ns == "" {
			continue
		}
		if !slices.Contains(ai, ns) {
			ai = append(ai, ns)
		}
		if w.Object != nil && w.Object.U != nil && rayAutoscaling(w) && !slices.Contains(apiServer, ns) {
			apiServer = append(apiServer, ns)
		}
	}
	slices.Sort(ai)
	slices.Sort(apiServer)
	peers := make(map[string][]string, len(ai))
	for _, ns := range ai {
		peers[ns] = slices.DeleteFunc(slices.Clone(ai), func(p string) bool { return p == ns })
	}
	return peers, apiServer
}

func PolicyNamespaces(in *check.Input) []string {
	out := []string{}
	for _, id := range policyChecks {
		c, ok := check.ByID(id)
		if !ok {
			continue
		}
		for _, f := range check.Evaluate(c, in).Findings {
			if ns := f.Object.Namespace; ns != "" && !slices.Contains(out, ns) {
				out = append(out, ns)
			}
		}
	}
	slices.Sort(out)
	return out
}

func Policies(namespaces []string, opt PolicyOptions) ([]map[string]any, error) {
	enforce, err := policyMode(opt.Mode)
	if err != nil {
		return nil, err
	}
	fqdns, err := allowFQDNs(opt.AllowFQDN)
	if err != nil {
		return nil, err
	}
	cidrs, err := allowCIDRs(opt.AllowCIDR)
	if err != nil {
		return nil, err
	}
	nss, err := policyNamespaceList(namespaces)
	if err != nil {
		return nil, err
	}
	peers, err := peerNamespaces(opt.PeerNamespaces)
	if err != nil {
		return nil, err
	}
	apiServer, err := policyNamespaceList(opt.APIServerNamespaces)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, 4*len(nss))
	for _, ns := range nss {
		ep := egressPeers{
			fqdns:      fqdns,
			cidrs:      cidrs,
			namespaces: slices.DeleteFunc(slices.Clone(peers[ns]), func(p string) bool { return p == ns }),
		}
		out = append(out, egressPolicy(ns, enforce, ep))
		if slices.Contains(apiServer, ns) {
			out = append(out, apiServerPolicy(ns, enforce))
		}
		out = append(out,
			shellExecPolicy(ns, enforce),
			egressConnectPolicy(ns, enforce, cidrs),
			admissionPolicy(ns, enforce),
		)
	}
	return out, nil
}

func policyMode(mode string) (bool, error) {
	switch mode {
	case "", modeAudit:
		return false, nil
	case modeEnforce:
		return true, nil
	}
	return false, fmt.Errorf("mode %q: want %s or %s", mode, modeAudit, modeEnforce)
}

func allowFQDNs(names []string) ([]string, error) {
	out := []string{}
	for _, n := range names {
		if len(n) > maxFQDNLength || !fqdnPattern.MatchString(n) {
			return nil, fmt.Errorf("--allow-fqdn %q is not a DNS name", n)
		}
		name := "." + strings.ToLower(strings.TrimSuffix(n, "."))
		if slices.ContainsFunc(clusterDNSSuffixes, func(s string) bool { return strings.HasSuffix(name, s) }) {
			return nil, fmt.Errorf("--allow-fqdn %q is an in-cluster Service name; Cilium toFQDNs does not match in-cluster addresses", n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

func allowCIDRs(cidrs []string) ([]string, error) {
	out := []string{}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("--allow-cidr %q is not a CIDR: %w", c, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("--allow-cidr %q allows every address; KS-NET-002 fails on it", c)
		}
		if s := p.Masked().String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out, nil
}

func policyNamespaceList(namespaces []string) ([]string, error) {
	out := []string{}
	for _, ns := range namespaces {
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return nil, fmt.Errorf("namespace %q: %s", ns, strings.Join(errs, "; "))
		}
		if !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	slices.Sort(out)
	return out, nil
}

func peerNamespaces(peers map[string][]string) (map[string][]string, error) {
	out := make(map[string][]string, len(peers))
	for _, ns := range slices.Sorted(maps.Keys(peers)) {
		if _, err := policyNamespaceList([]string{ns}); err != nil {
			return nil, err
		}
		list, err := policyNamespaceList(peers[ns])
		if err != nil {
			return nil, err
		}
		out[ns] = list
	}
	return out, nil
}

func strs(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func policyObject(apiVersion, kind, ns, name, guard string, spec map[string]any) map[string]any {
	meta := map[string]any{"name": name, "namespace": ns}
	if guard != "" {
		meta["labels"] = map[string]any{check.GuardLabel: guard}
	}
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": meta, "spec": spec}
}

func egressPolicy(ns string, enforce bool, ep egressPeers) map[string]any {
	rules := []any{
		map[string]any{
			"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{
				ciliumNSLabel: "kube-system",
				"k8s:k8s-app": "kube-dns",
			}}},
			"toPorts": []any{map[string]any{
				"ports": []any{
					map[string]any{"port": "53", "protocol": "UDP"},
					map[string]any{"port": "53", "protocol": "TCP"},
				},
				"rules": map[string]any{"dns": []any{map[string]any{"matchPattern": "*"}}},
			}},
		},
		map[string]any{"toEndpoints": []any{map[string]any{}}},
	}
	if len(ep.namespaces) > 0 {
		selectors := make([]any, len(ep.namespaces))
		for i, p := range ep.namespaces {
			selectors[i] = map[string]any{"matchLabels": map[string]any{ciliumNSLabel: p}}
		}
		rules = append(rules, map[string]any{"toEndpoints": selectors})
	}
	if len(ep.fqdns) > 0 {
		names := make([]any, len(ep.fqdns))
		for i, n := range ep.fqdns {
			names[i] = map[string]any{"matchName": n}
		}
		rules = append(rules, map[string]any{"toFQDNs": names})
	}
	if len(ep.cidrs) > 0 {
		rules = append(rules, map[string]any{"toCIDR": strs(ep.cidrs)})
	}
	return policyObject(ciliumAPIVersion, kindCNP, ns, egressPolicyName, "", map[string]any{
		"endpointSelector":  map[string]any{},
		"enableDefaultDeny": map[string]any{"egress": enforce, "ingress": false},
		"egress":            rules,
	})
}

func apiServerPolicy(ns string, enforce bool) map[string]any {
	return policyObject(ciliumAPIVersion, kindCNP, ns, apiServerPolicyName, "", map[string]any{
		"endpointSelector":  map[string]any{"matchLabels": map[string]any{rayHeadLabel: rayHeadValue}},
		"enableDefaultDeny": map[string]any{"egress": enforce, "ingress": false},
		"egress":            []any{map[string]any{"toEntities": []any{entityAPIServer}}},
	})
}

func tetragonAction(enforce bool) []any {
	if enforce {
		return []any{map[string]any{"action": actionSigkill}}
	}
	return []any{map[string]any{"action": actionPost}}
}

// source: https://github.com/cilium/tetragon/blob/v1.7.1/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml@v1.7.1
func shellExecPolicy(ns string, enforce bool) map[string]any {
	selector := map[string]any{
		"matchArgs":     []any{map[string]any{"index": int64(0), "operator": "Postfix", "values": strs(shellSuffixes)}},
		"matchBinaries": []any{map[string]any{"operator": "NotPostfix", "values": strs(shellSuffixes)}},
		"matchPIDs":     []any{map[string]any{"operator": "NotIn", "values": []any{int64(1)}, "isNamespacePID": true}},
		"matchActions":  tetragonAction(enforce),
	}
	return policyObject(tetragonAPIVersion, kindTracingNS, ns, shellExecPolicyName, check.GuardShellExec, map[string]any{
		"kprobes": []any{map[string]any{
			"call":      "security_bprm_check",
			"syscall":   false,
			"message":   shellExecMsg,
			"args":      []any{map[string]any{"index": int64(0), "type": "linux_binprm"}},
			"selectors": []any{selector},
		}},
	})
}

// source: https://github.com/cilium/tetragon/blob/v1.7.1/docs/content/en/docs/concepts/tracing-policy/hooks.md@v1.7.1
// source: https://github.com/cilium/tetragon/blob/v1.7.1/bpf/process/types/basic.h@v1.7.1
// source: https://github.com/cilium/tetragon/blob/v1.7.1/docs/content/en/docs/concepts/tracing-policy/selectors.md@v1.7.1
// source: https://github.com/cilium/tetragon/blob/v1.7.1/docs/content/en/docs/concepts/tracing-policy/options.md@v1.7.1
// source: https://github.com/cilium/tetragon/blob/v1.7.1/pkg/sensors/tracing/generickprobe.go@v1.7.1
// source: https://github.com/cilium/tetragon/blob/v1.7.1/pkg/selectors/kernel.go@v1.7.1
func egressConnectPolicy(ns string, enforce bool, cidrs []string) map[string]any {
	allowed := slices.Clone(privateCIDRs)
	for _, c := range cidrs {
		if !slices.Contains(allowed, c) {
			allowed = append(allowed, c)
		}
	}
	allowed = withMappedIPv4(allowed)
	action := map[string]any{"action": actionPost}
	if enforce {
		action = map[string]any{"action": actionOverride, "argError": int64(overrideEPERM)}
	}
	selector := map[string]any{
		"matchArgs": []any{
			map[string]any{"index": int64(0), "operator": "Protocol", "values": []any{"IPPROTO_TCP"}},
			map[string]any{"index": int64(1), "operator": "NotSAddr", "values": strs(allowed)},
		},
		"matchActions": []any{action},
	}
	return policyObject(tetragonAPIVersion, kindTracingNS, ns, connectPolicyName, check.GuardEgressConnect, map[string]any{
		"options": []any{map[string]any{"name": "disable-kprobe-multi", "value": "1"}},
		"kprobes": []any{map[string]any{
			"call":    "security_socket_connect",
			"syscall": false,
			"message": connectMsg,
			"args": []any{
				map[string]any{"index": int64(0), "type": "socket"},
				map[string]any{"index": int64(1), "type": "sockaddr"},
			},
			"selectors": []any{selector},
		}},
	})
}

// source: https://github.com/cilium/tetragon/blob/v1.7.1/pkg/selectors/kernel.go@v1.7.1
func withMappedIPv4(cidrs []string) []string {
	out := slices.Clone(cidrs)
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		mapped := netip.PrefixFrom(netip.AddrFrom16(p.Addr().As16()), p.Bits()+96).String()
		if !slices.Contains(out, mapped) {
			out = append(out, mapped)
		}
	}
	return out
}

func pickleDenyPattern() string {
	formats := make([]string, len(check.PickleFormats))
	for i, f := range check.PickleFormats {
		formats[i] = regexp.QuoteMeta(f)
	}
	return `(^|[^-_[:alnum:]])--trust[-_]remote[-_]code([^-_[:alnum:]]|$)` +
		`|(^|[^-_[:alnum:]])--load[-_]format([[:space:]]+|=)[[:punct:]]?(?i:` + strings.Join(formats, "|") + `)([^-_.[:alnum:]]|$)`
}

func podRule(name string, validate map[string]any) map[string]any {
	return map[string]any{
		"name":     name,
		"match":    map[string]any{"any": []any{map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}}}},
		"validate": validate,
	}
}

// source: https://github.com/kyverno/kyverno/blob/v1.19.1/config/crds/kyverno/kyverno.io_policies.yaml@v1.19.1
func admissionPolicy(ns string, enforce bool) map[string]any {
	action := kyvernoAudit
	if enforce {
		action = kyvernoEnforce
	}
	pickle := map[string]any{
		"failureAction": action,
		"message":       fmt.Sprintf(pickleMsgFormat, strings.Join(check.PickleFormats, ", ")),
		"foreach": []any{map[string]any{
			"list": containersList,
			"deny": map[string]any{"conditions": map[string]any{"any": []any{map[string]any{
				"key":      fmt.Sprintf(pickleKeyFormat, pickleDenyPattern()),
				"operator": "Equals",
				"value":    true,
			}}}},
		}},
	}
	return policyObject(kyvernoAPIVersion, kindKyvernoPolicy, ns, admissionPolicyName, check.GuardAdmission, map[string]any{
		"background": true,
		"rules": []any{
			podRule(podSecurityRuleName, map[string]any{
				"failureAction": action,
				"podSecurity":   map[string]any{"level": "restricted", "version": "latest"},
			}),
			podRule(pickleRuleName, pickle),
		},
	})
}
