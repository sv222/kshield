package check

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	kindTracingPolicy           = "TracingPolicy"
	kindTracingPolicyNamespaced = "TracingPolicyNamespaced"
	actionSigkill               = "Sigkill"
	actionOverride              = "Override"

	groupKyverno            = "kyverno.io"
	kindKyvernoPolicy       = "Policy"
	kindKyvernoClusterPol   = "ClusterPolicy"
	kindNamespace           = "Namespace"
	failureActionEnforce    = "Enforce"
	psaEnforceLabel         = "pod-security.kubernetes.io/enforce"
	psaRestricted           = "restricted"
	rtGuardObserveMsgFormat = "kshield %s guard covers this workload but has no %s action, so it only observes"
	rtNoGuardMsgFormat      = "no Tetragon %s guard covers this workload"
	rtExecThirdPartyMsg     = "unverified third-party exec policy: a TracingPolicy hooks execve or bprm, but it is not a kshield shell-exec guard"
	rtConnectThirdPartyMsg  = "unverified third-party connect policy: a TracingPolicy hooks connect, but it is not a kshield egress-connect guard"
	admissionApproxMsg      = "guard scope or action not fully evaluated: the kshield admission guard (Kyverno) uses validationFailureActionOverrides, exclude or a match namespaceSelector"
	admissionAuditMsg       = "kshield admission guard (Kyverno) covers this namespace in Audit mode only"
	admissionPSAMsg         = "partial: PSA does not cover shm hostPath or pickle loading (namespace enforces pod-security restricted, no kshield admission guard)"
	admissionNoneMsg        = "no kshield admission guard (Kyverno) covers this namespace"
)

var tracingHookFields = []struct{ list, name string }{
	{"kprobes", "call"},
	{"tracepoints", "event"},
	{"lsmhooks", "hook"},
}

type runtimeGuard struct {
	guard      string
	enforce    []string
	hookWords  []string
	thirdParty string
}

var (
	shellExecGuard = runtimeGuard{
		guard:      GuardShellExec,
		enforce:    []string{actionSigkill},
		hookWords:  []string{"execve", "bprm"},
		thirdParty: rtExecThirdPartyMsg,
	}
	egressConnectGuard = runtimeGuard{
		guard:      GuardEgressConnect,
		enforce:    []string{actionSigkill, actionOverride},
		hookWords:  []string{"tcp_connect", "connect"},
		thirdParty: rtConnectThirdPartyMsg,
	}
)

func tracingCovers(o load.Object, w model.Workload) bool {
	if !isKind(o, groupCilium, kindTracingPolicy, kindTracingPolicyNamespaced) {
		return false
	}
	if o.Ref.Kind == kindTracingPolicyNamespaced && o.Ref.Namespace != w.Owner.Namespace {
		return false
	}
	sel, present := mapOf(o.U.Object["spec"])["podSelector"]
	if !present || sel == nil {
		return true
	}
	return selectorMatches(mapOf(sel), w.Labels)
}

func tracingHooks(o load.Object) (hooks, actions []string) {
	spec := mapOf(o.U.Object["spec"])
	for _, f := range tracingHookFields {
		for _, h := range listOf(spec[f.list]) {
			hooks = append(hooks, stringOf(dig(h, f.name)))
			for _, s := range listOf(dig(h, "selectors")) {
				for _, a := range listOf(dig(s, "matchActions")) {
					actions = append(actions, stringOf(dig(a, "action")))
				}
			}
		}
	}
	return hooks, actions
}

func (g runtimeGuard) run(in *Input) Result {
	x := in.idx()
	return forNamespacedWorkloads(in, func(w model.Workload) []Finding {
		guarded, thirdParty := false, false
		for _, o := range x.tracingFor(w.Owner.Namespace) {
			if !tracingCovers(o, w) {
				continue
			}
			hooks, actions := tracingHooks(o)
			if guardLabelled(o, g.guard) {
				if slices.ContainsFunc(actions, func(a string) bool { return containsFold(g.enforce, a) }) {
					return nil
				}
				guarded = true
				continue
			}
			if slices.ContainsFunc(hooks, func(h string) bool { return hookMatches(h, g.hookWords) }) {
				thirdParty = true
			}
		}
		switch {
		case guarded:
			return []Finding{suspect(violation(w, "", namespacePath, fmt.Sprintf(rtGuardObserveMsgFormat, g.guard, strings.Join(g.enforce, " or "))))}
		case thirdParty:
			return []Finding{suspect(violation(w, "", namespacePath, g.thirdParty))}
		}
		return []Finding{violation(w, "", namespacePath, fmt.Sprintf(rtNoGuardMsgFormat, g.guard))}
	})
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}

func hookMatches(hook string, words []string) bool {
	h := strings.ToLower(hook)
	return slices.ContainsFunc(words, func(w string) bool { return strings.Contains(h, w) })
}

func rtShellExecGuard(in *Input) Result {
	return shellExecGuard.run(in)
}

func rtEgressConnectGuard(in *Input) Result {
	return egressConnectGuard.run(in)
}

func kyvernoCovers(o load.Object, ns string) bool {
	switch {
	case !isKind(o, groupKyverno, kindKyvernoPolicy, kindKyvernoClusterPol):
		return false
	case o.Ref.Kind == kindKyvernoPolicy:
		return o.Ref.Namespace == ns
	}
	return slices.ContainsFunc(listOf(dig(o.U.Object, "spec", "rules")), func(r any) bool { return kyvernoRuleCovers(r, ns) })
}

func kyvernoRuleCovers(rule any, ns string) bool {
	match := dig(rule, "match")
	if !namespacesCover(dig(match, "resources", "namespaces"), ns) {
		return false
	}
	filterCovers := func(f any) bool { return namespacesCover(dig(f, "resources", "namespaces"), ns) }
	if anyOf := listOf(dig(match, "any")); len(anyOf) > 0 && !slices.ContainsFunc(anyOf, filterCovers) {
		return false
	}
	for _, f := range listOf(dig(match, "all")) {
		if !filterCovers(f) {
			return false
		}
	}
	return true
}

func namespacesCover(v any, ns string) bool {
	list := listOf(v)
	if len(list) == 0 {
		return true
	}
	return slices.ContainsFunc(list, func(n any) bool {
		ok, err := path.Match(stringOf(n), ns)
		return err == nil && ok
	})
}

// source: https://github.com/kyverno/kyverno/blob/v1.19.1/pkg/engine/api/engineresponse.go@v1.19.1
func kyvernoEnforce(o load.Object) bool {
	specAction := stringOf(dig(o.U.Object, "spec", "validationFailureAction"))
	validating := 0
	for _, r := range listOf(dig(o.U.Object, "spec", "rules")) {
		v := dig(r, "validate")
		if v == nil {
			continue
		}
		validating++
		action := stringOf(dig(v, "failureAction"))
		if action == "" {
			action = specAction
		}
		if !strings.EqualFold(action, failureActionEnforce) {
			return false
		}
	}
	return validating > 0
}

func kyvernoApproximated(o load.Object) bool {
	if dig(o.U.Object, "spec", "validationFailureActionOverrides") != nil {
		return true
	}
	return slices.ContainsFunc(listOf(dig(o.U.Object, "spec", "rules")), func(r any) bool {
		return dig(r, "validate", "failureActionOverrides") != nil ||
			dig(r, "exclude") != nil ||
			hasKey(dig(r, "match"), "namespaceSelector")
	})
}

func hasKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[key]; ok {
			return true
		}
		for _, child := range t {
			if hasKey(child, key) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(t, func(child any) bool { return hasKey(child, key) })
	}
	return false
}

func rtAdmissionGuard(in *Input) Result {
	x := in.idx()
	return forNamespacedWorkloads(in, func(w model.Workload) []Finding {
		ns := w.Owner.Namespace
		audit, approximated := false, false
		for _, o := range x.kyvernoFor(ns) {
			if !kyvernoCovers(o, ns) || !guardLabelled(o, GuardAdmission) {
				continue
			}
			switch {
			case !kyvernoEnforce(o):
				audit = true
			case kyvernoApproximated(o):
				approximated = true
			default:
				return nil
			}
		}
		switch {
		case approximated:
			return []Finding{suspect(violation(w, "", namespacePath, admissionApproxMsg))}
		case audit:
			return []Finding{suspect(violation(w, "", namespacePath, admissionAuditMsg))}
		case x.psaRestricted[ns]:
			return []Finding{suspect(violation(w, "", namespacePath, admissionPSAMsg))}
		}
		return []Finding{violation(w, "", namespacePath, admissionNoneMsg)}
	})
}
