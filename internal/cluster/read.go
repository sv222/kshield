package cluster

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	sourceFile     = "cluster"
	pageSize       = 500
	allNamespaces  = "all namespaces"
	unknownReason  = "Unknown"
	groupCore      = ""
	groupApps      = "apps"
	resNamespaces  = "namespaces"
	resConfigMaps  = "configmaps"
	resSecrets     = "secrets"
	resDaemonSets  = "daemonsets"
	resDeployments = "deployments"
	kindSecret     = "Secret"
)

var readSet = []schema.GroupResource{
	{Group: groupCore, Resource: "pods"},
	{Group: groupCore, Resource: "services"},
	{Group: groupCore, Resource: "serviceaccounts"},
	{Group: groupCore, Resource: resConfigMaps},
	{Group: groupCore, Resource: resNamespaces},
	{Group: groupApps, Resource: resDeployments},
	{Group: groupApps, Resource: "statefulsets"},
	{Group: groupApps, Resource: resDaemonSets},
	{Group: groupApps, Resource: "replicasets"},
	{Group: "batch", Resource: "jobs"},
	{Group: "batch", Resource: "cronjobs"},
	{Group: "networking.k8s.io", Resource: "ingresses"},
	{Group: "networking.k8s.io", Resource: "networkpolicies"},
	{Group: "ray.io", Resource: "rayclusters"},
	{Group: "ray.io", Resource: "rayservices"},
	{Group: "ray.io", Resource: "rayjobs"},
	{Group: "serving.kserve.io", Resource: "inferenceservices"},
	{Group: "serving.kserve.io", Resource: "servingruntimes"},
	{Group: "serving.kserve.io", Resource: "clusterservingruntimes"},
	{Group: "serving.knative.dev", Resource: "services"},
	{Group: "serving.knative.dev", Resource: "configurations"},
	{Group: "serving.knative.dev", Resource: "revisions"},
	{Group: "cilium.io", Resource: "ciliumnetworkpolicies"},
	{Group: "cilium.io", Resource: "ciliumclusterwidenetworkpolicies"},
	{Group: "cilium.io", Resource: "tracingpolicies"},
	{Group: "cilium.io", Resource: "tracingpoliciesnamespaced"},
	{Group: "kyverno.io", Resource: "policies"},
	{Group: "kyverno.io", Resource: "clusterpolicies"},
}

type ReadOptions struct {
	Namespaces []string
}

type Snapshot struct {
	Objects []load.Object
	Errors  []string
	Failed  []FailedRead
}

type FailedRead struct {
	Group, Version, Resource, Namespace string
}

const (
	VerbList = "list"
	VerbGet  = "get"
)

type readPrefix struct {
	verb, text string
}

func (f FailedRead) prefixes() []readPrefix {
	gv := schema.GroupVersion{Group: f.Group, Version: f.Version}
	if f.Resource == "" {
		return []readPrefix{{VerbList, discoverPrefix(gv)}}
	}
	gvr := gv.WithResource(f.Resource)
	where := allNamespaces
	if f.Namespace != "" {
		where = f.Namespace
	}
	out := []readPrefix{{VerbList, listPrefix(gvr, where)}}
	switch {
	case f.Resource == resNamespaces && f.Namespace != "":
		out = append(out, readPrefix{VerbGet, getPrefix(gvr, "", f.Namespace)})
	case f.Resource == resConfigMaps && f.Namespace != "":
		out = append(out, readPrefix{VerbGet, getPrefix(gvr, f.Namespace, check.CiliumConfigName)})
	}
	return out
}

func (f FailedRead) Prefix() string {
	return f.prefixes()[0].text
}

func (f FailedRead) Reason(errs []string) (string, bool) {
	_, reason, ok := f.Match(errs)
	return reason, ok
}

func (f FailedRead) Match(errs []string) (verb, reason string, ok bool) {
	for _, prefix := range f.prefixes() {
		for _, line := range errs {
			if reason, ok := strings.CutPrefix(line, prefix.text); ok {
				return prefix.verb, reason, true
			}
		}
	}
	return VerbList, "", false
}

func ReadSet() []schema.GroupResource {
	return slices.Clone(readSet)
}

type target struct {
	gvr        schema.GroupVersionResource
	kind       string
	namespaced bool
}

type reader struct {
	ctx        context.Context
	dyn        dynamic.Interface
	namespaces []string
	targets    []target
	objs       []load.Object
	seen       map[string]bool
	errs       []string
	failed     []FailedRead
}

var secretsGVR = schema.GroupVersionResource{Version: "v1", Resource: resSecrets}

func Read(ctx context.Context, c *Client, opt ReadOptions) (*Snapshot, error) {
	r := &reader{
		ctx:        ctx,
		dyn:        c.Dynamic,
		namespaces: slices.Compact(slices.Sorted(slices.Values(opt.Namespaces))),
		seen:       map[string]bool{},
	}
	if err := r.discover(c.Discovery); err != nil {
		return nil, err
	}
	if len(r.namespaces) == 0 {
		for _, t := range r.targets {
			r.list(t, "", nil)
		}
	} else if err := r.readNamespaces(); err != nil {
		return nil, err
	}
	r.readSecrets()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(r.objs, func(a, b load.Object) int {
		return cmp.Or(
			cmp.Compare(a.Ref.Namespace, b.Ref.Namespace),
			cmp.Compare(a.Ref.Kind, b.Ref.Kind),
			cmp.Compare(a.Ref.Name, b.Ref.Name),
			cmp.Compare(a.Ref.APIVersion, b.Ref.APIVersion),
		)
	})
	slices.Sort(r.errs)
	slices.SortFunc(r.failed, func(a, b FailedRead) int {
		return cmp.Or(
			cmp.Compare(a.Group, b.Group),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Resource, b.Resource),
			cmp.Compare(a.Namespace, b.Namespace),
		)
	})
	return &Snapshot{Objects: r.objs, Errors: slices.Compact(r.errs), Failed: slices.Compact(r.failed)}, nil
}

func (r *reader) discover(d discovery.DiscoveryInterface) error {
	groups, err := d.ServerGroups()
	if err != nil {
		return fmt.Errorf("cluster: discover groups: %w", err)
	}
	core := false
	for _, group := range groupNames() {
		i := slices.IndexFunc(groups.Groups, func(g metav1.APIGroup) bool { return g.Name == group })
		if i < 0 {
			continue
		}
		want := resourcesOf(group)
		found := map[string]target{}
		for _, gv := range versionsOf(groups.Groups[i]) {
			if len(found) == len(want) {
				break
			}
			list, err := d.ServerResourcesForGroupVersion(gv.String())
			if err != nil {
				if group == groupCore {
					return fmt.Errorf("cluster: discover %s: %w", gv, err)
				}
				r.errs = append(r.errs, discoverPrefix(gv)+reasonOf(err))
				r.failed = append(r.failed, FailedRead{Group: gv.Group, Version: gv.Version})
				continue
			}
			for _, ar := range list.APIResources {
				if _, done := found[ar.Name]; done || !slices.Contains(want, ar.Name) {
					continue
				}
				found[ar.Name] = target{gvr: gv.WithResource(ar.Name), kind: ar.Kind, namespaced: ar.Namespaced}
			}
		}
		for _, res := range want {
			if t, ok := found[res]; ok {
				r.targets = append(r.targets, t)
				core = core || group == groupCore
			}
		}
	}
	if !core {
		return errors.New("cluster: discover: the server does not serve the core group")
	}
	return nil
}

func groupNames() []string {
	var out []string
	for _, gr := range readSet {
		if !slices.Contains(out, gr.Group) {
			out = append(out, gr.Group)
		}
	}
	return out
}

func resourcesOf(group string) []string {
	var out []string
	for _, gr := range readSet {
		if gr.Group == group {
			out = append(out, gr.Resource)
		}
	}
	return out
}

func versionsOf(g metav1.APIGroup) []schema.GroupVersion {
	out := []schema.GroupVersion{{Group: g.Name, Version: g.PreferredVersion.Version}}
	for _, v := range g.Versions {
		gv := schema.GroupVersion{Group: g.Name, Version: v.Version}
		if !slices.Contains(out, gv) {
			out = append(out, gv)
		}
	}
	return out
}

func (r *reader) target(group, resource string) (target, bool) {
	i := slices.IndexFunc(r.targets, func(t target) bool { return t.gvr.Group == group && t.gvr.Resource == resource })
	if i < 0 {
		return target{}, false
	}
	return r.targets[i], true
}

func (r *reader) readNamespaces() error {
	if t, ok := r.target(groupCore, resNamespaces); ok {
		for _, ns := range r.namespaces {
			u, err := r.dyn.Resource(t.gvr).Get(r.ctx, ns, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				return fmt.Errorf("namespace %q not found", ns)
			case err != nil:
				r.errs = append(r.errs, getLine(t.gvr, "", ns, err))
				r.failed = append(r.failed, FailedRead{Group: t.gvr.Group, Version: t.gvr.Version, Resource: t.gvr.Resource, Namespace: ns})
			default:
				r.add(u, t, nil)
			}
		}
	}
	for _, t := range r.targets {
		switch {
		case t.gvr.Group == groupCore && t.gvr.Resource == resNamespaces:
		case !t.namespaced:
			r.list(t, "", nil)
		default:
			for _, ns := range r.namespaces {
				r.list(t, ns, nil)
			}
			if t.gvr.Group == groupApps && (t.gvr.Resource == resDaemonSets || t.gvr.Resource == resDeployments) {
				r.list(t, "", check.IsPrerequisite)
			}
		}
	}
	r.readCiliumConfigs()
	return nil
}

func (r *reader) inScope(ns string) bool {
	return len(r.namespaces) == 0 || slices.Contains(r.namespaces, ns)
}

func (r *reader) readCiliumConfigs() {
	t, ok := r.target(groupCore, resConfigMaps)
	if !ok {
		return
	}
	var cilium []string
	for _, o := range r.objs {
		ns := o.Ref.Namespace
		if check.IsCiliumAgent(o) && !r.inScope(ns) && !slices.Contains(cilium, ns) {
			cilium = append(cilium, ns)
		}
	}
	slices.Sort(cilium)
	for _, ns := range cilium {
		u, err := r.dyn.Resource(t.gvr).Namespace(ns).Get(r.ctx, check.CiliumConfigName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			r.errs = append(r.errs, getLine(t.gvr, ns, check.CiliumConfigName, err))
			r.failed = append(r.failed, FailedRead{Group: t.gvr.Group, Version: t.gvr.Version, Resource: t.gvr.Resource, Namespace: ns})
		default:
			r.add(u, t, nil)
		}
	}
}

func (r *reader) readSecrets() {
	t := target{gvr: secretsGVR, kind: kindSecret, namespaced: true}
	type ref struct{ ns, name string }
	var refs []ref
	note := func(ns, name string) {
		if name != "" && !slices.Contains(refs, ref{ns, name}) {
			refs = append(refs, ref{ns, name})
		}
	}
	for _, o := range r.objs {
		if o.Ref.Namespace == "" || !r.inScope(o.Ref.Namespace) {
			continue
		}
		ws, err := model.Extract([]load.Object{o})
		if err != nil {
			r.errs = append(r.errs, fmt.Sprintf("cluster: read secret references of %s %s: %v", o.Ref.APIVersion, o.Ref, err))
			continue
		}
		for _, w := range ws {
			for _, v := range w.Spec.Volumes {
				if v.Secret != nil {
					note(o.Ref.Namespace, v.Secret.SecretName)
				}
			}
			for _, c := range w.Containers {
				for _, ef := range c.Spec.EnvFrom {
					if ef.SecretRef != nil {
						note(o.Ref.Namespace, ef.SecretRef.Name)
					}
				}
			}
		}
	}
	slices.SortFunc(refs, func(a, b ref) int { return cmp.Or(cmp.Compare(a.ns, b.ns), cmp.Compare(a.name, b.name)) })
	for _, s := range refs {
		u, err := r.dyn.Resource(t.gvr).Namespace(s.ns).Get(r.ctx, s.name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err), apierrors.IsForbidden(err):
		case err != nil:
			r.errs = append(r.errs, getLine(t.gvr, s.ns, s.name, err))
		default:
			r.add(u, t, nil)
		}
	}
}

func (r *reader) list(t target, ns string, keep func(load.Object) bool) {
	res := r.dyn.Resource(t.gvr)
	var ri dynamic.ResourceInterface = res
	where := allNamespaces
	if ns != "" {
		ri = res.Namespace(ns)
		where = ns
	}
	var items []unstructured.Unstructured
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		page, err := ri.List(r.ctx, opts)
		if err != nil {
			r.errs = append(r.errs, listPrefix(t.gvr, where)+reasonOf(err))
			r.failed = append(r.failed, FailedRead{Group: t.gvr.Group, Version: t.gvr.Version, Resource: t.gvr.Resource, Namespace: ns})
			return
		}
		items = append(items, page.Items...)
		opts.Continue = page.GetContinue()
		if opts.Continue == "" {
			break
		}
	}
	for i := range items {
		r.add(&items[i], t, keep)
	}
}

func (r *reader) add(u *unstructured.Unstructured, t target, keep func(load.Object) bool) {
	if u.GetKind() == "" {
		u.SetAPIVersion(t.gvr.GroupVersion().String())
		u.SetKind(t.kind)
	}
	u.SetManagedFields(nil)
	o := load.Object{
		Ref:    load.ObjectRef{APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName()},
		Source: load.Source{File: sourceFile},
		U:      u,
	}
	if keep != nil && !keep(o) {
		return
	}
	key := "uid:" + string(u.GetUID())
	if u.GetUID() == "" {
		key = "ref:" + o.Ref.APIVersion + " " + o.Ref.String()
	}
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.objs = append(r.objs, o)
}

func discoverPrefix(gv schema.GroupVersion) string {
	return fmt.Sprintf("cluster: discover %s: ", gv)
}

func listPrefix(gvr schema.GroupVersionResource, where string) string {
	return fmt.Sprintf("cluster: list %s %s in %s: ", gvr.GroupVersion(), gvr.Resource, where)
}

func getPrefix(gvr schema.GroupVersionResource, ns, name string) string {
	where := ""
	if ns != "" {
		where = " in " + ns
	}
	return fmt.Sprintf("cluster: get %s %s %s%s: ", gvr.GroupVersion(), gvr.Resource, name, where)
}

func getLine(gvr schema.GroupVersionResource, ns, name string, err error) string {
	return getPrefix(gvr, ns, name) + reasonOf(err)
}

func reasonOf(err error) string {
	reason := string(apierrors.ReasonForError(err))
	if reason == "" {
		reason = unknownReason
	}
	msg := err.Error()
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		msg = status.Status().Message
	}
	if msg == "" {
		return reason
	}
	return reason + ": " + msg
}
