package check

import (
	"maps"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

type AuthSource string

const (
	AuthEngineKey         AuthSource = "engine-key"
	AuthGatewayDeclared   AuthSource = "gateway-auth"
	AuthIngressAnnotation AuthSource = "ingress-annotation"
	AuthIstio             AuthSource = "istio"
	AuthKong              AuthSource = "kong"
	AuthEnvoyGateway      AuthSource = "envoy-gateway"
	AuthRouteAnnotation   AuthSource = "route-annotation"
	AuthRouteFilter       AuthSource = "route-filter"
)

type AuthEvidence struct {
	Source AuthSource
	Ref    load.ObjectRef
	Detail string
}

func (a AuthEvidence) Present() bool {
	return a.Source != ""
}

func (a AuthEvidence) Text() string {
	if a.Ref.Name == "" {
		return a.Detail
	}
	name := a.Ref.Name
	if a.Ref.Namespace != "" {
		name = a.Ref.Namespace + "/" + name
	}
	return strings.TrimSpace(a.Ref.Kind + " " + name + " " + a.Detail)
}

func (a AuthEvidence) Suffix() string {
	if a.Source == AuthGatewayDeclared {
		return declaredSuffix
	}
	return "; authentication is in front of it: " + a.Text() + " (the scanner reads the object, it cannot check that the gateway or mesh enforces it)"
}

func declaredAuth(w model.Workload) (AuthEvidence, bool) {
	ws := []map[string]string{w.Labels, w.Annotations}
	if w.Object != nil && w.Object.U != nil {
		ws = append(ws, w.Object.U.GetLabels(), w.Object.U.GetAnnotations())
	}
	if !slices.ContainsFunc(ws, func(m map[string]string) bool { return m[GatewayAuthKey] == gatewayAuthValue }) {
		return AuthEvidence{}, false
	}
	return AuthEvidence{Source: AuthGatewayDeclared, Detail: GatewayAuthKey + ": \"" + gatewayAuthValue + "\""}, true
}

var ingressAuthHints = []string{"auth-url", "auth-type", "auth-signin", "auth-secret", "oauth2"}

func annotationAuth(o load.Object, source AuthSource) (AuthEvidence, bool) {
	annotations := mapOf(dig(o.U.Object, "metadata", "annotations"))
	for _, k := range slices.Sorted(maps.Keys(annotations)) {
		s, ok := scalarString(annotations[k])
		if !ok || s == "" {
			continue
		}
		if k == GatewayAuthKey {
			if s == gatewayAuthValue {
				return annotationEvidence(o, source, k), true
			}
			continue
		}
		lk := strings.ToLower(k)
		if slices.ContainsFunc(ingressAuthHints, func(h string) bool { return strings.Contains(lk, h) }) {
			return annotationEvidence(o, source, k), true
		}
	}
	return AuthEvidence{}, false
}

func annotationEvidence(o load.Object, source AuthSource, annotation string) AuthEvidence {
	return AuthEvidence{Source: source, Ref: o.Ref, Detail: "has the annotation " + annotation}
}

type serverVerdict struct {
	reason   string
	strength Strength
	open     bool
	keyed    AuthEvidence
}

func keyEvidence(c model.Container, how string) AuthEvidence {
	return AuthEvidence{Source: AuthEngineKey, Detail: "container " + c.Spec.Name + " sets " + how}
}

func workloadAuth(in *Input, w model.Workload) (AuthEvidence, bool) {
	if a, ok := declaredAuth(w); ok {
		return a, true
	}
	return meshAuth(in, w, "", nil)
}

func (a AuthEvidence) Silent() bool {
	return a.Source == AuthIngressAnnotation
}
