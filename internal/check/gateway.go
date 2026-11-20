package check

import (
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
)

const (
	kindHTTPRoute      = "HTTPRoute"
	kindSecurityPolicy = "SecurityPolicy"

	groupEnvoyGateway = "gateway.envoyproxy.io"

	filterExtensionRef = "ExtensionRef"
)

var envoyAuthMechanisms = []string{"basicAuth", "apiKeyAuth", "jwt", "oidc", "extAuth"}

var filterAuthHints = []string{"auth", "jwt", "oidc"}

type routeBackend struct {
	namespace, name string
}

type indexedRoute struct {
	obj        load.Object
	gateways   []string
	services   []routeBackend
	plugins    []string
	authFilter string
}

type envoyPolicy struct {
	obj       load.Object
	mechanism string
	targets   []string
}

func refNamespace(ref any, namespace string) string {
	if s := stringOf(dig(ref, "namespace")); s != "" {
		return s
	}
	return namespace
}

func refKey(ref any, namespace string) string {
	return refNamespace(ref, namespace) + "/" + stringOf(dig(ref, "name"))
}

func parseHTTPRoute(o load.Object) indexedRoute {
	ns := o.Ref.Namespace
	r := indexedRoute{obj: o}
	for _, p := range listOf(dig(o.U.Object, "spec", "parentRefs")) {
		if refIs(p, groupGatewayAPI, groupGatewayAPI, kindGateway) {
			r.gateways = append(r.gateways, refKey(p, ns))
		}
	}
	for _, rule := range listOf(dig(o.U.Object, "spec", "rules")) {
		r.addFilters(listOf(dig(rule, "filters")))
		for _, b := range listOf(dig(rule, "backendRefs")) {
			r.addFilters(listOf(dig(b, "filters")))
			if !refIs(b, "", "", kindService) {
				continue
			}
			rb := routeBackend{namespace: refNamespace(b, ns), name: stringOf(dig(b, "name"))}
			if !slices.Contains(r.services, rb) {
				r.services = append(r.services, rb)
			}
		}
	}
	return r
}

func (r *indexedRoute) addFilters(filters []any) {
	for _, f := range filters {
		ext := dig(f, "extensionRef")
		if stringOf(dig(f, "type")) != filterExtensionRef || ext == nil {
			continue
		}
		name := stringOf(dig(ext, "name"))
		if refIs(ext, "", groupKong, kindKongPlugin) {
			r.plugins = append(r.plugins, name)
			continue
		}
		kind := stringOf(dig(ext, "kind"))
		lower := strings.ToLower(kind + "/" + name)
		if r.authFilter == "" && slices.ContainsFunc(filterAuthHints, func(h string) bool { return strings.Contains(lower, h) }) {
			r.authFilter = kind + "/" + name
		}
	}
}

func parseEnvoyPolicy(o load.Object) (envoyPolicy, bool) {
	spec := dig(o.U.Object, "spec")
	i := slices.IndexFunc(envoyAuthMechanisms, func(m string) bool { return dig(spec, m) != nil })
	if i < 0 {
		return envoyPolicy{}, false
	}
	p := envoyPolicy{obj: o, mechanism: envoyAuthMechanisms[i]}
	refs := slices.Clone(listOf(dig(spec, "targetRefs")))
	if r := dig(spec, "targetRef"); r != nil {
		refs = append(refs, r)
	}
	for _, r := range refs {
		for _, kind := range []string{kindGateway, kindHTTPRoute} {
			if refIs(r, "", groupGatewayAPI, kind) {
				p.targets = append(p.targets, targetKey(kind, o.Ref.Namespace, stringOf(dig(r, "name"))))
			}
		}
	}
	return p, true
}
