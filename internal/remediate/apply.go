package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	"github.com/sv222/kshield/internal/load"
)

const (
	FieldManager = "kshield"

	RolePolicy   = "policy"
	RoleWorkload = "workload"

	bundleRoot = "/bundle"
	peekSize   = 4096
)

type ApplyObject struct {
	Role       string
	Object     *unstructured.Unstructured
	Resource   schema.GroupVersionResource
	Namespaced bool
}

func (o ApplyObject) Ref() load.ObjectRef {
	return load.ObjectRef{APIVersion: o.Object.GetAPIVersion(), Kind: o.Object.GetKind(), Namespace: o.Object.GetNamespace(), Name: o.Object.GetName()}
}

func (o ApplyObject) Label() string {
	return o.Ref().String()
}

func decodeDocs(data []byte) ([]*unstructured.Unstructured, error) {
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), peekSize)
	var out []*unstructured.Unstructured
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		var m map[string]any
		if err := utiljson.Unmarshal(trimmed, &m); err != nil {
			return nil, err
		}
		out = append(out, &unstructured.Unstructured{Object: m})
	}
}

func patchedRefs(b *Bundle) ([]load.ObjectRef, error) {
	var rj remediationJSON
	if err := json.Unmarshal(b.Files[FileRemediation], &rj); err != nil {
		return nil, fmt.Errorf("%s: %w", FileRemediation, err)
	}
	var out []load.ObjectRef
	for _, it := range rj.Items {
		if it.Action != ActionPatch {
			continue
		}
		ref := load.ObjectRef{APIVersion: it.Object.APIVersion, Kind: it.Object.Kind, Namespace: it.Object.Namespace, Name: it.Object.Name}
		if !containsRef(out, ref) {
			out = append(out, ref)
		}
	}
	return out, nil
}

func containsRef(refs []load.ObjectRef, ref load.ObjectRef) bool {
	for _, r := range refs {
		if r == ref {
			return true
		}
	}
	return false
}

func kustomizeBundle(b *Bundle) ([]*unstructured.Unstructured, error) {
	fs := filesys.MakeFsInMemory()
	for name, data := range b.Files {
		p := path.Join(bundleRoot, name)
		if err := fs.MkdirAll(path.Dir(p)); err != nil {
			return nil, err
		}
		if err := fs.WriteFile(p, data); err != nil {
			return nil, err
		}
	}
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(fs, bundleRoot)
	if err != nil {
		return nil, fmt.Errorf("kustomize build of the bundle: %w", err)
	}
	var out []*unstructured.Unstructured
	for _, r := range m.Resources() {
		data, err := r.AsYAML()
		if err != nil {
			return nil, err
		}
		objs, err := decodeDocs(data)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	return out, nil
}

func workloadObjects(b *Bundle) ([]ApplyObject, error) {
	refs, err := patchedRefs(b)
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	built, err := kustomizeBundle(b)
	if err != nil {
		return nil, err
	}
	var out []ApplyObject
	for _, ref := range refs {
		found := false
		for _, u := range built {
			if u.GetAPIVersion() != ref.APIVersion || u.GetKind() != ref.Kind || u.GetName() != ref.Name {
				continue
			}
			if ns := u.GetNamespace(); ns != "" && ns != ref.Namespace {
				continue
			}
			if u.GetNamespace() == "" && ref.Namespace != "" {
				u.SetNamespace(ref.Namespace)
			}
			out = append(out, ApplyObject{Role: RoleWorkload, Object: u})
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("the patched %s is not in the kustomize build of the bundle", ref)
		}
	}
	return out, nil
}

func PlanApply(b *Bundle, withPatches bool) ([]ApplyObject, error) {
	var out []ApplyObject
	if withPatches {
		ws, err := workloadObjects(b)
		if err != nil {
			return nil, err
		}
		out = append(out, ws...)
	}
	policies, err := decodeDocs(b.Files[FilePolicies])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FilePolicies, err)
	}
	for _, u := range policies {
		out = append(out, ApplyObject{Role: RolePolicy, Object: u})
	}
	return out, nil
}

type MissingKind struct {
	APIVersion string
	Kind       string
	Product    string
	Objects    []ApplyObject
}

func productOf(apiVersion, kind string) string {
	group, _ := splitAPIVersion(apiVersion)
	switch {
	case group == "kyverno.io":
		return "Kyverno"
	case group == "cilium.io" && strings.HasPrefix(kind, "Tracing"):
		return "Tetragon"
	case group == "cilium.io":
		return "Cilium"
	}
	return ""
}

func Resolve(d discovery.DiscoveryInterface, objs []ApplyObject) ([]ApplyObject, []MissingKind, error) {
	groups, err := d.ServerGroups()
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: discover groups: %w", err)
	}
	served := map[string]bool{}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			served[v.GroupVersion] = true
		}
	}
	resources := map[string][]metav1.APIResource{}
	var found []ApplyObject
	var missing []MissingKind
	for _, o := range objs {
		gv, kind := o.Object.GetAPIVersion(), o.Object.GetKind()
		if served[gv] {
			if _, ok := resources[gv]; !ok {
				list, err := d.ServerResourcesForGroupVersion(gv)
				if err != nil {
					return nil, nil, fmt.Errorf("cluster: discover %s: %w", gv, err)
				}
				resources[gv] = list.APIResources
			}
		}
		i := slices.IndexFunc(resources[gv], func(r metav1.APIResource) bool { return r.Kind == kind && !strings.Contains(r.Name, "/") })
		if i < 0 {
			j := slices.IndexFunc(missing, func(m MissingKind) bool { return m.APIVersion == gv && m.Kind == kind })
			if j < 0 {
				missing = append(missing, MissingKind{APIVersion: gv, Kind: kind, Product: productOf(gv, kind)})
				j = len(missing) - 1
			}
			missing[j].Objects = append(missing[j].Objects, o)
			continue
		}
		parsed, err := schema.ParseGroupVersion(gv)
		if err != nil {
			return nil, nil, err
		}
		o.Resource = parsed.WithResource(resources[gv][i].Name)
		o.Namespaced = resources[gv][i].Namespaced
		found = append(found, o)
	}
	return found, missing, nil
}

type ApplyOptions struct {
	ForceConflicts bool
	DryRun         bool
}

type ApplyError struct {
	Object   ApplyObject
	Applied  int
	Conflict bool
	Err      error
}

func (e *ApplyError) Error() string {
	msg := fmt.Sprintf("apply %s failed after %d applied: %v", e.Object.Label(), e.Applied, e.Err)
	if e.Conflict {
		msg += "; another field manager owns a field kshield changes: review who owns it, then run again with --force-conflicts to take it over"
	}
	return msg
}

func (e *ApplyError) Unwrap() error {
	return e.Err
}

func RunApply(ctx context.Context, client dynamic.Interface, objs []ApplyObject, opt ApplyOptions, out io.Writer) error {
	po := metav1.ApplyOptions{FieldManager: FieldManager, Force: opt.ForceConflicts}
	verb := "applied"
	if opt.DryRun {
		po.DryRun = []string{metav1.DryRunAll}
		verb = "dry run ok"
	}
	for i, o := range objs {
		var ri dynamic.ResourceInterface = client.Resource(o.Resource)
		if o.Namespaced {
			ri = client.Resource(o.Resource).Namespace(o.Object.GetNamespace())
		}
		if _, err := ri.Apply(ctx, o.Object.GetName(), o.Object.DeepCopy(), po); err != nil {
			return &ApplyError{Object: o, Applied: i, Conflict: apierrors.IsConflict(err), Err: err}
		}
		if _, err := fmt.Fprintf(out, "%s %s\n", verb, o.Label()); err != nil {
			return err
		}
	}
	return nil
}
