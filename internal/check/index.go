package check

import (
	"slices"

	"github.com/sv222/kshield/internal/load"
)

type coreKey struct {
	kind, namespace, name string
}

type inputIndex struct {
	services       map[string][]indexedService
	ingresses      map[string][]indexedIngress
	netpols        map[string][]load.Object
	ciliumPolicies map[string][]load.Object
	ciliumCluster  []load.Object
	tracing        []load.Object
	tracingNS      map[string][]load.Object
	kyverno        map[string][]load.Object
	kyvernoCluster []load.Object
	psaRestricted  map[string]bool
	tokenless      map[string]bool
	core           map[coreKey][]load.Object
}

func buildIndex(objs []load.Object) *inputIndex {
	x := &inputIndex{
		services:       map[string][]indexedService{},
		ingresses:      map[string][]indexedIngress{},
		netpols:        map[string][]load.Object{},
		ciliumPolicies: map[string][]load.Object{},
		tracingNS:      map[string][]load.Object{},
		kyverno:        map[string][]load.Object{},
		psaRestricted:  map[string]bool{},
		tokenless:      tokenlessServiceAccounts(objs),
		core:           map[coreKey][]load.Object{},
	}
	for _, o := range objs {
		if o.U == nil {
			continue
		}
		ns := o.Ref.Namespace
		switch {
		case o.Ref.APIVersion == coreAPIVersion:
			x.addCore(o)
		case o.Ref.Kind == kindIngress && o.Ref.APIVersion == ingressAPIVersion:
			x.ingresses[ns] = append(x.ingresses[ns], parseIngress(o))
		case isNetworkPolicy(o):
			x.netpols[ns] = append(x.netpols[ns], o)
		case isKind(o, groupCilium, kindCiliumPolicy):
			x.ciliumPolicies[ns] = append(x.ciliumPolicies[ns], o)
		case isKind(o, groupCilium, kindCiliumClusterPolicy):
			x.ciliumCluster = append(x.ciliumCluster, o)
		case isKind(o, groupCilium, kindTracingPolicy):
			x.tracing = append(x.tracing, o)
		case isKind(o, groupCilium, kindTracingPolicyNamespaced):
			x.tracingNS[ns] = append(x.tracingNS[ns], o)
		case isKind(o, groupKyverno, kindKyvernoPolicy):
			x.kyverno[ns] = append(x.kyverno[ns], o)
		case isKind(o, groupKyverno, kindKyvernoClusterPol):
			x.kyvernoCluster = append(x.kyvernoCluster, o)
		}
	}
	return x
}

func (x *inputIndex) addCore(o load.Object) {
	switch o.Ref.Kind {
	case kindService:
		x.services[o.Ref.Namespace] = append(x.services[o.Ref.Namespace], parseService(o))
	case kindNamespace:
		if s, ok := scalarString(dig(o.U.Object, "metadata", "labels", psaEnforceLabel)); ok && s == psaRestricted {
			x.psaRestricted[o.Ref.Name] = true
		}
	case kindConfigMap, kindSecret:
		k := coreKey{o.Ref.Kind, o.Ref.Namespace, o.Ref.Name}
		x.core[k] = append(x.core[k], o)
	}
}

func (x *inputIndex) ciliumFor(ns string) []load.Object {
	return slices.Concat(x.ciliumPolicies[ns], x.ciliumCluster)
}

func (x *inputIndex) tracingFor(ns string) []load.Object {
	return slices.Concat(x.tracingNS[ns], x.tracing)
}

func (x *inputIndex) kyvernoFor(ns string) []load.Object {
	return slices.Concat(x.kyverno[ns], x.kyvernoCluster)
}
