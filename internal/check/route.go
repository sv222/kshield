package check

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/model"
)

const (
	ExposureHTTPRoute = "httproute"

	routeRulesPath = "/spec/rules"
)

func routeServer(in *Input, w model.Workload) (string, Strength, bool) {
	if w.HasStack(model.Ollama) {
		return "Ollama has no authentication of its own", Violation, true
	}
	return unauthenticatedServer(in, w)
}

func routeEnvoyAuth(in *Input, r indexedRoute) (AuthEvidence, bool) {
	own := targetKey(kindHTTPRoute, r.obj.Ref.Namespace, r.obj.Ref.Name)
	for _, p := range in.idx().envoy {
		for _, t := range p.targets {
			if t == own || slices.ContainsFunc(r.gateways, func(g string) bool { return t == kindGateway+"/"+g }) {
				return AuthEvidence{Source: AuthEnvoyGateway, Ref: p.obj.Ref, Detail: "enforces " + p.mechanism + " on the HTTPRoute or its Gateway"}, true
			}
		}
	}
	return AuthEvidence{}, false
}

func routeAuth(in *Input, w model.Workload, r indexedRoute, svc indexedService) (AuthEvidence, string) {
	ns := r.obj.Ref.Namespace
	if a, ok := annotationAuth(r.obj, AuthRouteAnnotation); ok {
		return a, ""
	}
	if a, ok := routeEnvoyAuth(in, r); ok {
		return a, ""
	}
	if a, ok := kongAuth(in, ns, annotationsOf(r.obj), r.plugins); ok {
		return a, ""
	}
	if a, ok := kongAuth(in, svc.obj.Ref.Namespace, annotationsOf(svc.obj), nil); ok {
		return a, ""
	}
	if r.authFilter != "" {
		return AuthEvidence{Source: AuthRouteFilter, Ref: r.obj.Ref, Detail: "has the ExtensionRef filter " + r.authFilter + " (the name suggests authentication)"}, ""
	}
	if a, ok := meshAuth(in, w, svc.obj.Ref.Name, r.gateways); ok {
		return a, ""
	}
	return AuthEvidence{}, routeDoubt(in, r, svc)
}

func routeDoubt(in *Input, r indexedRoute, svc indexedService) string {
	x := in.idx()
	names := slices.Concat(
		kongPluginNames(annotationsOf(r.obj), r.plugins),
		kongPluginNames(annotationsOf(svc.obj), nil),
	)
	for _, n := range names {
		if !slices.ContainsFunc(x.kong, func(p kongPlugin) bool { return p.name == n && p.visibleFrom(r.obj.Ref.Namespace) }) {
			return fmt.Sprintf("the Kong plugin %s is not in the input, so the scanner cannot tell if it authenticates", n)
		}
	}
	if in.Cluster == nil || len(in.Cluster.Namespaces) == 0 {
		return ""
	}
	for _, g := range r.gateways {
		ns, _, _ := strings.Cut(g, "/")
		if !x.gateways[g] && !slices.Contains(in.Cluster.Namespaces, ns) {
			return fmt.Sprintf("the parent Gateway %s is outside the scanned namespaces, so its policies were not read", g)
		}
	}
	return ""
}

func routeExposures(in *Input, w model.Workload) []Exposure {
	x := in.idx()
	var svcs []indexedService
	for _, s := range x.services[w.Owner.Namespace] {
		if model.MapSelects(s.selector, w.Labels) {
			svcs = append(svcs, s)
		}
	}
	var out []Exposure
	for _, r := range x.routes {
		if len(r.gateways) == 0 {
			continue
		}
		i := slices.IndexFunc(svcs, func(s indexedService) bool {
			return slices.Contains(r.services, routeBackend{namespace: w.Owner.Namespace, name: s.obj.Ref.Name})
		})
		if i < 0 {
			continue
		}
		auth, doubt := routeAuth(in, w, r, svcs[i])
		out = append(out, Exposure{Object: r.obj, Kind: ExposureHTTPRoute, Auth: auth, Doubt: doubt, Path: routeRulesPath})
	}
	return out
}

func aiRouteExposed(in *Input) Result {
	ws := AIWorkloads(in)
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	seen := map[string]int{}
	for _, w := range ws {
		reason, strength, ok := routeServer(in, w)
		if !ok {
			continue
		}
		auth, declared := workloadAuth(in, w)
		if declared {
			strength = Declared
		}
		res.Findings = appendExposures(res.Findings, seen, routeExposures(in, w), true, strength, func(e Exposure) string {
			msg := fmt.Sprintf("HTTPRoute %s reaches %s through a Gateway with no authentication evidence: %s", e.Object.Ref.Name, w.Owner, reason)
			if declared {
				msg = fmt.Sprintf("HTTPRoute %s reaches %s through a Gateway: %s%s", e.Object.Ref.Name, w.Owner, reason, auth.Suffix())
			}
			return msg
		})
	}
	return res
}
