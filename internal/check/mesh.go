package check

import (
	"slices"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	groupIstioSecurity        = "security.istio.io"
	groupGatewayAPI           = "gateway.networking.k8s.io"
	kindAuthorizationPolicy   = "AuthorizationPolicy"
	kindRequestAuthentication = "RequestAuthentication"
	kindGateway               = "Gateway"

	istioActionDeny   = "DENY"
	istioActionCustom = "CUSTOM"
	anyPrincipal      = "*"
)

type meshPolicy struct {
	obj      load.Object
	selector map[string]string
	targets  []string
	jwt      bool
	detail   string
}

func targetKey(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}

func refIs(ref any, defGroup, group, kind string) bool {
	g, k := defGroup, kind
	if s, ok := dig(ref, "group").(string); ok {
		g = s
	}
	if s, ok := dig(ref, "kind").(string); ok {
		k = s
	}
	return g == group && k == kind
}

func stringsOf(v any) []string {
	var out []string
	for _, item := range listOf(v) {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func policyTargets(spec any, namespace string) []string {
	refs := slices.Clone(listOf(dig(spec, "targetRefs")))
	if r := dig(spec, "targetRef"); r != nil {
		refs = append(refs, r)
	}
	var out []string
	for _, r := range refs {
		name := stringOf(dig(r, "name"))
		switch {
		case refIs(r, "", groupGatewayAPI, kindGateway):
			out = append(out, targetKey(kindGateway, namespace, name))
		case refIs(r, "", "", kindService):
			out = append(out, targetKey(kindService, namespace, name))
		}
	}
	return out
}

func parseMeshPolicy(o load.Object) (meshPolicy, bool) {
	spec := dig(o.U.Object, "spec")
	p := meshPolicy{
		obj:      o,
		selector: stringMapOf(dig(spec, "selector", "matchLabels")),
		targets:  policyTargets(spec, o.Ref.Namespace),
	}
	if o.Ref.Kind == kindRequestAuthentication {
		p.detail = "validates request JWTs"
		return p, len(listOf(dig(spec, "jwtRules"))) > 0
	}
	rules := listOf(dig(spec, "rules"))
	switch stringOf(dig(spec, "action")) {
	case istioActionCustom:
		p.detail = "delegates the decision to an external authorization provider"
		return p, dig(spec, "provider") != nil
	case istioActionDeny:
		p.detail = "denies requests without an authenticated principal"
		return p, denyAnonymous(&p, rules)
	}
	p.detail = "allows only requests with an authenticated principal"
	return p, allowAuthenticated(&p, rules)
}

func denyAnonymous(p *meshPolicy, rules []any) bool {
	for _, r := range rules {
		if len(listOf(dig(r, "to"))) > 0 || len(listOf(dig(r, "when"))) > 0 {
			continue
		}
		for _, f := range listOf(dig(r, "from")) {
			src := dig(f, "source")
			if slices.Contains(stringsOf(dig(src, "notRequestPrincipals")), anyPrincipal) {
				p.jwt = true
			}
			if p.jwt || slices.Contains(stringsOf(dig(src, "notPrincipals")), anyPrincipal) {
				return true
			}
		}
	}
	return false
}

func allowAuthenticated(p *meshPolicy, rules []any) bool {
	if len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		ident := false
		for _, f := range listOf(dig(r, "from")) {
			src := dig(f, "source")
			if len(stringsOf(dig(src, "principals"))) > 0 {
				ident = true
				break
			}
			if len(stringsOf(dig(src, "requestPrincipals"))) > 0 {
				ident, p.jwt = true, true
			}
		}
		if !ident {
			return false
		}
	}
	return true
}

func meshApplies(p meshPolicy, w model.Workload, svc string, gateways []string) bool {
	if len(p.targets) == 0 {
		return p.obj.Ref.Namespace == w.Owner.Namespace && (len(p.selector) == 0 || model.MapSelects(p.selector, w.Labels))
	}
	for _, t := range p.targets {
		if svc != "" && t == targetKey(kindService, w.Owner.Namespace, svc) {
			return true
		}
		if slices.ContainsFunc(gateways, func(g string) bool { return t == kindGateway+"/"+g }) {
			return true
		}
	}
	return false
}

func meshAuth(in *Input, w model.Workload, svc string, gateways []string) (AuthEvidence, bool) {
	x := in.idx()
	var requestAuth *meshPolicy
	for i := range x.requestAuth {
		if meshApplies(x.requestAuth[i], w, svc, gateways) {
			requestAuth = &x.requestAuth[i]
			break
		}
	}
	for _, p := range x.authz {
		if (requestAuth != nil || !p.jwt) && meshApplies(p, w, svc, gateways) {
			detail := p.detail
			if p.jwt {
				detail += " (JWT, with RequestAuthentication " + requestAuth.obj.Ref.Namespace + "/" + requestAuth.obj.Ref.Name + ")"
			}
			return AuthEvidence{Source: AuthIstio, Ref: p.obj.Ref, Detail: detail}, true
		}
	}
	return AuthEvidence{}, false
}
