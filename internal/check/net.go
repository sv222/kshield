package check

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	kindNetworkPolicy         = "NetworkPolicy"
	kindCiliumPolicy          = "CiliumNetworkPolicy"
	kindCiliumClusterPolicy   = "CiliumClusterwideNetworkPolicy"
	networkPolicyAPIVersion   = "networking.k8s.io/v1"
	groupCilium               = "cilium.io"
	ciliumNamespaceKey        = "io.kubernetes.pod.namespace"
	policyTypeEgress          = "Egress"
	netpolEgressPath          = "/spec/egress/"
	ciliumSpecPath            = "/spec"
	ciliumSpecsPath           = "/specs/"
	ciliumEgressSegment       = "/egress/"
	ciliumEntityWorld         = "world"
	ciliumEntityWorldIPv4     = "world-ipv4"
	ciliumEntityWorldIPv6     = "world-ipv6"
	ciliumEntityAll           = "all"
	ciliumEgressDenyKey       = "egressDeny"
	egressKey                 = "egress"
	ciliumEndpointSelector    = "endpointSelector"
	ciliumEnableDefaultDeny   = "enableDefaultDeny"
	ciliumToEntities          = "toEntities"
	ciliumToCIDR              = "toCIDR"
	ciliumToCIDRSet           = "toCIDRSet"
	netpolNoDefaultDenyMsg    = "no NetworkPolicy or Cilium policy puts this workload under egress default-deny"
	netpolAuditOnlyMsg        = "only a Cilium policy with enableDefaultDeny.egress: false covers this workload (audit form, egress is not denied by default)"
	netpolOpenToMsg           = "NetworkPolicy egress rule has no `to`, so it allows every destination"
	netpolOpenCIDRMsgPrefix   = "NetworkPolicy egress rule allows ipBlock "
	ciliumOpenEntityMsgPrefix = "Cilium egress rule allows entity "
	ciliumOpenCIDRMsgPrefix   = "Cilium egress rule allows CIDR "
)

var (
	ciliumKeyPrefixes = []string{"k8s:", "any:"}
	// source: https://github.com/cilium/cilium/blob/v1.20.3/pkg/policy/api/entity.go@v1.20.3
	ciliumBroadEntities = []string{ciliumEntityWorld, ciliumEntityWorldIPv4, ciliumEntityWorldIPv6, ciliumEntityAll}
	openCIDRs           = []string{"0.0.0.0/0", "::/0"}
)

type ciliumRule struct {
	path string
	body map[string]any
}

func isNetworkPolicy(o load.Object) bool {
	return o.U != nil && o.Ref.Kind == kindNetworkPolicy && o.Ref.APIVersion == networkPolicyAPIVersion
}

func netpolSelects(o load.Object, w model.Workload) bool {
	if o.Ref.Namespace != w.Owner.Namespace {
		return false
	}
	sel := mapOf(dig(o.U.Object, "spec", "podSelector"))
	if sel == nil {
		sel = map[string]any{}
	}
	return selectorMatches(sel, w.Labels)
}

func netpolEgress(o load.Object) bool {
	types := listOf(dig(o.U.Object, "spec", "policyTypes"))
	if len(types) == 0 {
		return len(listOf(dig(o.U.Object, "spec", egressKey))) > 0
	}
	return slices.ContainsFunc(types, func(t any) bool { return stringOf(t) == policyTypeEgress })
}

func ciliumRules(o load.Object) []ciliumRule {
	var out []ciliumRule
	if m := mapOf(dig(o.U.Object, "spec")); m != nil {
		out = append(out, ciliumRule{path: ciliumSpecPath, body: m})
	}
	for j, r := range listOf(dig(o.U.Object, "specs")) {
		if m := mapOf(r); m != nil {
			out = append(out, ciliumRule{path: ciliumSpecsPath + strconv.Itoa(j), body: m})
		}
	}
	return out
}

func ciliumRuleSelects(o load.Object, r ciliumRule, w model.Workload) bool {
	if o.Ref.Kind == kindCiliumPolicy && o.Ref.Namespace != w.Owner.Namespace {
		return false
	}
	return ciliumSelects(mapOf(r.body[ciliumEndpointSelector]), w.Owner.Namespace, w.Labels)
}

func ciliumSelects(sel map[string]any, ns string, labels map[string]string) bool {
	ls, ok := labelSelectorOf(sel)
	if !ok {
		return false
	}
	matchLabels := make(map[string]string, len(ls.MatchLabels))
	for k, v := range ls.MatchLabels {
		matchLabels[stripCiliumPrefix(k)] = v
	}
	ls.MatchLabels = matchLabels
	for i := range ls.MatchExpressions {
		ls.MatchExpressions[i].Key = stripCiliumPrefix(ls.MatchExpressions[i].Key)
	}
	set := maps.Clone(labels)
	if set == nil {
		set = map[string]string{}
	}
	set[ciliumNamespaceKey] = ns
	match, err := model.Selects(ls, set)
	return err == nil && match
}

func stripCiliumPrefix(k string) string {
	for _, p := range ciliumKeyPrefixes {
		if rest, ok := strings.CutPrefix(k, p); ok {
			return rest
		}
	}
	return k
}

func ciliumEgressDefaultDeny(rule map[string]any) (deny, audit bool) {
	if len(listOf(rule[egressKey])) == 0 && len(listOf(rule[ciliumEgressDenyKey])) == 0 {
		return false, false
	}
	if on, ok := dig(rule, ciliumEnableDefaultDeny, egressKey).(bool); ok && !on {
		return false, true
	}
	return true, false
}

func egressDefaultDeny(in *Input, w model.Workload) (covered, auditOnly bool) {
	x := in.idx()
	for _, o := range x.netpols[w.Owner.Namespace] {
		if netpolSelects(o, w) && netpolEgress(o) {
			return true, false
		}
	}
	for _, o := range x.ciliumFor(w.Owner.Namespace) {
		for _, r := range ciliumRules(o) {
			if !ciliumRuleSelects(o, r, w) {
				continue
			}
			deny, audit := ciliumEgressDefaultDeny(r.body)
			if deny {
				return true, false
			}
			auditOnly = auditOnly || audit
		}
	}
	return false, auditOnly
}

func netEgressDefaultDeny(in *Input) Result {
	return forNamespacedWorkloads(in, func(w model.Workload) []Finding {
		covered, audit := egressDefaultDeny(in, w)
		switch {
		case covered:
			return nil
		case audit:
			return []Finding{suspect(violation(w, "", namespacePath, netpolAuditOnlyMsg))}
		}
		return []Finding{violation(w, "", namespacePath, netpolNoDefaultDenyMsg)}
	})
}

func netBroadEgress(in *Input) Result {
	ws := AIWorkloads(in)
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	x := in.idx()
	byNamespace := map[string][]model.Workload{}
	for _, w := range ws {
		byNamespace[w.Owner.Namespace] = append(byNamespace[w.Owner.Namespace], w)
	}
	for _, ns := range slices.Sorted(maps.Keys(byNamespace)) {
		nsWorkloads := byNamespace[ns]
		for _, o := range x.netpols[ns] {
			res.Findings = append(res.Findings, netpolBroadFindings(o, nsWorkloads)...)
		}
		for _, o := range x.ciliumPolicies[ns] {
			res.Findings = append(res.Findings, ciliumBroadFindings(o, nsWorkloads)...)
		}
	}
	for _, o := range x.ciliumCluster {
		res.Findings = append(res.Findings, ciliumBroadFindings(o, ws)...)
	}
	return res
}

func netpolBroadFindings(o load.Object, ws []model.Workload) []Finding {
	if !netpolEgress(o) || !slices.ContainsFunc(ws, func(w model.Workload) bool { return netpolSelects(o, w) }) {
		return nil
	}
	var out []Finding
	for i, r := range listOf(dig(o.U.Object, "spec", egressKey)) {
		if msg := netpolBroad(r); msg != "" {
			out = append(out, policyFinding(o, netpolEgressPath+strconv.Itoa(i), msg))
		}
	}
	return out
}

func ciliumBroadFindings(o load.Object, ws []model.Workload) []Finding {
	var out []Finding
	for _, r := range ciliumRules(o) {
		if !slices.ContainsFunc(ws, func(w model.Workload) bool { return ciliumRuleSelects(o, r, w) }) {
			continue
		}
		for i, e := range listOf(r.body[egressKey]) {
			if msg := ciliumBroad(e); msg != "" {
				out = append(out, policyFinding(o, r.path+ciliumEgressSegment+strconv.Itoa(i), msg))
			}
		}
	}
	return out
}

func policyFinding(o load.Object, path, msg string) Finding {
	return Finding{Object: o.Ref, Path: path, Message: msg, Strength: Violation}
}

func netpolBroad(rule any) string {
	to := listOf(dig(rule, "to"))
	if len(to) == 0 {
		return netpolOpenToMsg
	}
	for _, peer := range to {
		if cidr := stringOf(dig(peer, "ipBlock", "cidr")); slices.Contains(openCIDRs, cidr) {
			return netpolOpenCIDRMsgPrefix + cidr
		}
	}
	return ""
}

func ciliumBroad(rule any) string {
	for _, e := range listOf(dig(rule, ciliumToEntities)) {
		s := stringOf(e)
		if slices.ContainsFunc(ciliumBroadEntities, func(b string) bool { return strings.EqualFold(s, b) }) {
			return ciliumOpenEntityMsgPrefix + s
		}
	}
	for _, c := range listOf(dig(rule, ciliumToCIDR)) {
		if s := stringOf(c); slices.Contains(openCIDRs, s) {
			return ciliumOpenCIDRMsgPrefix + s
		}
	}
	for _, c := range listOf(dig(rule, ciliumToCIDRSet)) {
		if s := stringOf(dig(c, "cidr")); slices.Contains(openCIDRs, s) {
			return ciliumOpenCIDRMsgPrefix + s
		}
	}
	return ""
}

const (
	policyTypeIngress    = "Ingress"
	ciliumIngressKey     = "ingress"
	ciliumFromEntities   = "fromEntities"
	ciliumFromCIDR       = "fromCIDR"
	ciliumFromCIDRSet    = "fromCIDRSet"
	netpolNoIngressMsg   = "no NetworkPolicy or Cilium policy restricts ingress to this workload"
	netpolIngressAuditFm = "only a Cilium policy with enableDefaultDeny.ingress: false covers this workload (audit form, ingress is not denied by default)"
)

func netpolIngress(o load.Object) bool {
	types := listOf(dig(o.U.Object, "spec", "policyTypes"))
	if len(types) == 0 {
		return true
	}
	return slices.ContainsFunc(types, func(t any) bool { return stringOf(t) == policyTypeIngress })
}

func selectsEverything(sel any) bool {
	m := mapOf(sel)
	return len(mapOf(m["matchLabels"])) == 0 && len(listOf(m["matchExpressions"])) == 0
}

func netpolOpenPeer(peer any) bool {
	if block := mapOf(dig(peer, "ipBlock")); block != nil {
		return len(listOf(block["except"])) == 0 && slices.Contains(openCIDRs, stringOf(block["cidr"]))
	}
	ns, pod := dig(peer, "namespaceSelector"), dig(peer, "podSelector")
	if ns == nil && pod == nil {
		return true
	}
	return ns != nil && selectsEverything(ns) && (pod == nil || selectsEverything(pod))
}

func netpolOpenIngressRule(rule any) bool {
	from := listOf(dig(rule, "from"))
	return len(from) == 0 || slices.ContainsFunc(from, netpolOpenPeer)
}

func ciliumOpenIngressRule(rule any) bool {
	for _, e := range listOf(dig(rule, ciliumFromEntities)) {
		s := stringOf(e)
		if slices.ContainsFunc(ciliumBroadEntities, func(b string) bool { return strings.EqualFold(s, b) }) {
			return true
		}
	}
	for _, c := range listOf(dig(rule, ciliumFromCIDR)) {
		if slices.Contains(openCIDRs, stringOf(c)) {
			return true
		}
	}
	for _, c := range listOf(dig(rule, ciliumFromCIDRSet)) {
		if slices.Contains(openCIDRs, stringOf(dig(c, "cidr"))) {
			return true
		}
	}
	return false
}

func ciliumIngressDefaultDeny(rule map[string]any) (deny, audit bool) {
	if len(listOf(rule[ciliumIngressKey])) == 0 {
		return false, false
	}
	if on, ok := dig(rule, ciliumEnableDefaultDeny, ciliumIngressKey).(bool); ok && !on {
		return false, true
	}
	return true, false
}

type ingressVerdict struct {
	isolated bool
	audit    bool
	msg      string
}

func ingressIsolation(in *Input, w model.Workload) ingressVerdict {
	x := in.idx()
	var selecting, noIngress, open []string
	restricted, audit := false, false
	for _, o := range x.netpols[w.Owner.Namespace] {
		if !netpolSelects(o, w) {
			continue
		}
		selecting = append(selecting, o.Ref.Name)
		if !netpolIngress(o) {
			noIngress = append(noIngress, o.Ref.Name)
			continue
		}
		restricted = true
		if slices.ContainsFunc(listOf(dig(o.U.Object, "spec", "ingress")), netpolOpenIngressRule) {
			open = append(open, "NetworkPolicy "+o.Ref.Name)
		}
	}
	for _, o := range x.ciliumFor(w.Owner.Namespace) {
		for _, r := range ciliumRules(o) {
			if !ciliumRuleSelects(o, r, w) {
				continue
			}
			selecting = append(selecting, o.Ref.Name)
			deny, auditForm := ciliumIngressDefaultDeny(r.body)
			audit = audit || auditForm
			if !deny {
				continue
			}
			restricted = true
			if slices.ContainsFunc(listOf(r.body[ciliumIngressKey]), ciliumOpenIngressRule) {
				open = append(open, "Cilium policy "+o.Ref.Name)
			}
		}
	}
	switch {
	case len(open) > 0:
		return ingressVerdict{msg: strings.Join(slices.Compact(open), ", ") + " has an ingress rule that allows traffic from every source"}
	case restricted:
		return ingressVerdict{isolated: true}
	case audit:
		return ingressVerdict{audit: true, msg: netpolIngressAuditFm}
	case len(noIngress) > 0:
		return ingressVerdict{msg: "NetworkPolicy " + strings.Join(noIngress, ", ") + " selects this workload but has no Ingress policyType, so ingress traffic is not restricted"}
	}
	return ingressVerdict{msg: netpolNoIngressMsg}
}

func netIngressIsolation(in *Input) Result {
	return forNamespacedWorkloads(in, func(w model.Workload) []Finding {
		v := ingressIsolation(in, w)
		switch {
		case v.isolated:
			return nil
		case v.audit:
			return []Finding{suspect(violation(w, "", namespacePath, v.msg))}
		}
		return []Finding{violation(w, "", namespacePath, v.msg)}
	})
}
