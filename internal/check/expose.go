package check

import (
	"math"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	ExposureServiceNodePort     = "service-nodeport"
	ExposureServiceLoadBalancer = "service-loadbalancer"
	ExposureIngress             = "ingress"

	kindService       = "Service"
	kindIngress       = "Ingress"
	ingressAPIVersion = "networking.k8s.io/v1"

	serviceTypePath    = "/spec/type"
	ingressRulesPath   = "/spec/rules"
	ingressDefaultPath = "/spec/defaultBackend"

	authURLAnnotation  = "nginx.ingress.kubernetes.io/auth-url"
	authTypeAnnotation = "nginx.ingress.kubernetes.io/auth-type"
)

type Exposure struct {
	Object        load.Object
	Kind          string
	Authenticated bool
	Path          string
}

type servicePort struct {
	name          string
	port          int32
	portUnknown   bool
	target        int32
	targetName    string
	targetUnknown bool
}

type indexedService struct {
	obj      load.Object
	kind     string
	selector map[string]string
	ports    []servicePort
}

type ingressBackend struct {
	service    string
	portNumber int32
	portName   string
	portKnown  bool
}

type indexedIngress struct {
	obj            load.Object
	rules          []ingressBackend
	defaultBackend *ingressBackend
	authenticated  bool
}

func parseService(o load.Object) indexedService {
	s := indexedService{
		obj:      o,
		kind:     serviceExposureKind(stringOf(dig(o.U.Object, "spec", "type"))),
		selector: stringMapOf(dig(o.U.Object, "spec", "selector")),
	}
	items, _ := dig(o.U.Object, "spec", "ports").([]any)
	for _, item := range items {
		s.ports = append(s.ports, parseServicePort(item))
	}
	return s
}

func parseServicePort(item any) servicePort {
	p := servicePort{name: stringOf(dig(item, "name"))}
	port, ok := portNumber(dig(item, "port"))
	p.port, p.portUnknown = port, !ok
	switch target := dig(item, "targetPort").(type) {
	case nil:
	case string:
		if n, ok := portNumber(target); ok {
			p.target = n
		} else {
			p.targetName = target
		}
	default:
		if n, ok := portNumber(target); ok {
			p.target = n
		} else {
			p.targetUnknown = true
		}
	}
	return p
}

func parseIngress(o load.Object) indexedIngress {
	ing := indexedIngress{
		obj:           o,
		authenticated: annotationSet(o, authURLAnnotation) || annotationSet(o, authTypeAnnotation),
	}
	if b, ok := parseBackend(dig(o.U.Object, "spec", "defaultBackend")); ok {
		ing.defaultBackend = &b
	}
	rules, _ := dig(o.U.Object, "spec", "rules").([]any)
	for _, r := range rules {
		paths, _ := dig(r, "http", "paths").([]any)
		for _, p := range paths {
			if b, ok := parseBackend(dig(p, "backend")); ok {
				ing.rules = append(ing.rules, b)
			}
		}
	}
	return ing
}

func parseBackend(v any) (ingressBackend, bool) {
	b := ingressBackend{service: stringOf(dig(v, "service", "name"))}
	if b.service == "" {
		return b, false
	}
	port := dig(v, "service", "port")
	if n, ok := portNumber(dig(port, "number")); ok {
		b.portNumber, b.portKnown = n, true
	} else if name := stringOf(dig(port, "name")); name != "" {
		b.portName, b.portKnown = name, true
	}
	return b, true
}

func annotationSet(o load.Object, key string) bool {
	s, ok := scalarString(dig(o.U.Object, "metadata", "annotations", key))
	return ok && s != ""
}

func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	}
	return "", false
}

func stringMapOf(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := make(map[string]string, len(m))
	for k, raw := range m {
		s, ok := scalarString(raw)
		if !ok {
			return nil
		}
		out[k] = s
	}
	return out
}

func portNumber(v any) (int32, bool) {
	var n int64
	switch t := v.(type) {
	case int:
		n = int64(t)
	case int64:
		n = t
	case float64:
		if t != math.Trunc(t) {
			return 0, false
		}
		n = int64(t)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		n = parsed
	default:
		return 0, false
	}
	if n < 0 || n > math.MaxInt32 {
		return 0, false
	}
	return int32(n), true
}

func Exposures(in *Input, w model.Workload, ports []int32) []Exposure {
	x := in.idx()
	var out []Exposure
	selecting := map[string]indexedService{}
	for _, s := range x.services[w.Owner.Namespace] {
		if !model.MapSelects(s.selector, w.Labels) {
			continue
		}
		selecting[s.obj.Ref.Name] = s
		if s.kind == "" || !servicePortMatches(s, w, ports) {
			continue
		}
		out = append(out, Exposure{Object: s.obj, Kind: s.kind, Path: serviceTypePath})
	}
	for _, i := range x.ingresses[w.Owner.Namespace] {
		if e, ok := ingressExposure(i, selecting, w, ports); ok {
			out = append(out, e)
		}
	}
	return out
}

func serviceExposureKind(t string) string {
	switch corev1.ServiceType(t) {
	case corev1.ServiceTypeNodePort:
		return ExposureServiceNodePort
	case corev1.ServiceTypeLoadBalancer:
		return ExposureServiceLoadBalancer
	}
	return ""
}

func servicePortMatches(s indexedService, w model.Workload, ports []int32) bool {
	if ports == nil {
		return true
	}
	return slices.ContainsFunc(s.ports, func(p servicePort) bool { return p.matches(w, ports) })
}

func (p servicePort) matches(w model.Workload, ports []int32) bool {
	switch {
	case p.portUnknown, p.targetUnknown, slices.Contains(ports, p.port), p.target != 0 && slices.Contains(ports, p.target):
		return true
	}
	return p.targetName != "" && namedPortMatches(w, p.targetName, ports)
}

func (p servicePort) referencedBy(b ingressBackend) bool {
	switch {
	case b.portName != "":
		return p.name == b.portName
	case p.portUnknown:
		return true
	}
	return p.port == b.portNumber
}

func backendMatches(s indexedService, b ingressBackend, w model.Workload, ports []int32) bool {
	if ports == nil {
		return true
	}
	if !b.portKnown {
		return servicePortMatches(s, w, ports)
	}
	return slices.ContainsFunc(s.ports, func(p servicePort) bool { return p.referencedBy(b) && p.matches(w, ports) })
}

func namedPortMatches(w model.Workload, name string, ports []int32) bool {
	for _, c := range w.Containers {
		for _, p := range c.Spec.Ports {
			if p.Name == name && slices.Contains(ports, p.ContainerPort) {
				return true
			}
		}
	}
	return false
}

func exposureWhat(e Exposure) string {
	switch e.Kind {
	case ExposureServiceNodePort:
		return "Service type NodePort"
	case ExposureServiceLoadBalancer:
		return "Service type LoadBalancer"
	}
	return "Ingress"
}

func appendExposures(out []Finding, seen map[string]int, es []Exposure, skipAuthenticated bool, strength Strength, msg func(Exposure) string) []Finding {
	for _, e := range es {
		if skipAuthenticated && e.Authenticated {
			continue
		}
		key := e.Object.Ref.String()
		if i, dup := seen[key]; dup {
			if e.Path == ingressRulesPath {
				out[i].Path = e.Path
			}
			if strength < out[i].Strength {
				out[i].Message, out[i].Strength = msg(e), strength
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, Finding{Object: e.Object.Ref, Path: e.Path, Message: msg(e), Strength: strength})
	}
	return out
}

func ingressExposure(i indexedIngress, selecting map[string]indexedService, w model.Workload, ports []int32) (Exposure, bool) {
	hits := func(b ingressBackend) bool {
		s, ok := selecting[b.service]
		return ok && backendMatches(s, b, w, ports)
	}
	path := ""
	switch {
	case slices.ContainsFunc(i.rules, hits):
		path = ingressRulesPath
	case i.defaultBackend != nil && hits(*i.defaultBackend):
		path = ingressDefaultPath
	default:
		return Exposure{}, false
	}
	return Exposure{Object: i.obj, Kind: ExposureIngress, Authenticated: i.authenticated, Path: path}, true
}
