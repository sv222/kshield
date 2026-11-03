package model

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/sv222/kshield/internal/load"
)

const (
	groupApps   = "apps"
	groupBatch  = "batch"
	groupRay    = "ray.io"
	groupKServe = "serving.kserve.io"

	groupHead = "head"

	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/controllers/ray/utils/constant.go@v1.7.1
	rayClusterLabel = "ray.io/cluster"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/controllers/ray/utils/constant.go@v1.7.1
	rayNodeTypeLabel = "ray.io/node-type"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/controllers/ray/utils/constant.go@v1.7.1
	rayGroupLabel = "ray.io/group"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/controllers/ray/utils/constant.go@v1.7.1
	rayHeadGroupValue = "headgroup"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/apis/ray/v1/raycluster_types.go@v1.7.1
	rayHeadNodeType = "head"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/apis/ray/v1/raycluster_types.go@v1.7.1
	rayWorkerNodeType = "worker"

	// source: https://github.com/kserve/kserve/blob/v0.21.0/pkg/constants/constants.go@v0.21.0
	kserveServiceLabel = "serving.kserve.io/inferenceservice"
	// source: https://github.com/kserve/kserve/blob/v0.21.0/pkg/constants/constants.go@v0.21.0
	kserveComponentLabel = "component"
)

var kserveComponents = []string{"predictor", "transformer", "explainer"}

type site struct {
	spec  []string
	meta  []string
	extra []string
	group string
	synth map[string]string
	drop  []string
}

func Extract(objs []load.Object) ([]Workload, error) {
	var out []Workload
	for i := range objs {
		o := &objs[i]
		if o.U == nil {
			continue
		}
		sites, err := sitesOf(o)
		if err != nil {
			return nil, err
		}
		for _, s := range sites {
			w, ok, err := build(o, s)
			if err != nil {
				return nil, err
			}
			if ok {
				Classify(&w)
				out = append(out, w)
			}
		}
	}
	return out, nil
}

func sitesOf(o *load.Object) ([]site, error) {
	gk := schema.FromAPIVersionAndKind(o.Ref.APIVersion, o.Ref.Kind).GroupKind()
	switch gk.Group {
	case "":
		if gk.Kind == "Pod" {
			return []site{{spec: []string{"spec"}, meta: []string{"metadata"}}}, nil
		}
	case groupApps:
		switch gk.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
			return []site{templateSite("spec")}, nil
		}
	case groupBatch:
		switch gk.Kind {
		case "Job":
			return []site{templateSite("spec")}, nil
		case "CronJob":
			return []site{templateSite("spec", "jobTemplate", "spec")}, nil
		}
	case groupRay:
		switch gk.Kind {
		case "RayCluster":
			return raySites(o, []string{"spec"}, o.Ref.Name)
		case "RayService":
			return raySites(o, []string{"spec", "rayClusterConfig"}, "")
		case "RayJob":
			return raySites(o, []string{"spec", "rayClusterSpec"}, "")
		}
	case groupKServe:
		switch gk.Kind {
		case "InferenceService":
			return kserveSites(o.Ref.Name), nil
		case "ServingRuntime", "ClusterServingRuntime":
			return []site{{spec: []string{"spec"}, meta: []string{"metadata"}}}, nil
		}
	}
	return nil, nil
}

func templateSite(base ...string) site {
	return site{
		spec: slices.Concat(base, []string{"template", "spec"}),
		meta: slices.Concat(base, []string{"template", "metadata"}),
	}
}

func kserveSites(name string) []site {
	out := make([]site, 0, len(kserveComponents))
	for _, comp := range kserveComponents {
		out = append(out, site{
			spec:  []string{"spec", comp},
			meta:  []string{"metadata"},
			extra: []string{"spec", comp},
			group: comp,
			synth: map[string]string{kserveServiceLabel: name, kserveComponentLabel: comp},
		})
	}
	return out
}

func raySites(o *load.Object, base []string, cluster string) ([]site, error) {
	synth := func(nodeType, group string) map[string]string {
		m := map[string]string{rayNodeTypeLabel: nodeType, rayGroupLabel: group}
		if cluster != "" {
			m[rayClusterLabel] = cluster
		}
		return m
	}
	var drop []string
	if cluster == "" {
		drop = []string{rayClusterLabel}
	}
	headBase := slices.Concat(base, []string{"headGroupSpec"})
	out := []site{{
		spec:  slices.Concat(headBase, []string{"template", "spec"}),
		meta:  slices.Concat(headBase, []string{"template", "metadata"}),
		extra: headBase,
		group: groupHead,
		synth: synth(rayHeadNodeType, rayHeadGroupValue),
		drop:  drop,
	}}
	workersPath := slices.Concat(base, []string{"workerGroupSpecs"})
	v, found, err := lookup(o.U.Object, workersPath)
	if err != nil {
		return nil, fail(o.Ref, workersPath, err)
	}
	if !found || v == nil {
		return out, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fail(o.Ref, workersPath, fmt.Errorf("expected array, got %T", v))
	}
	for i, item := range list {
		entryPath := slices.Concat(workersPath, []string{strconv.Itoa(i)})
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fail(o.Ref, entryPath, fmt.Errorf("expected object, got %T", item))
		}
		name := ""
		if raw, present := entry["groupName"]; present && raw != nil {
			if name, ok = raw.(string); !ok {
				return nil, fail(o.Ref, slices.Concat(entryPath, []string{"groupName"}), fmt.Errorf("expected string, got %T", raw))
			}
		}
		out = append(out, site{
			spec:  slices.Concat(entryPath, []string{"template", "spec"}),
			meta:  slices.Concat(entryPath, []string{"template", "metadata"}),
			extra: entryPath,
			group: name,
			synth: synth(rayWorkerNodeType, name),
			drop:  drop,
		})
	}
	return out, nil
}

func build(o *load.Object, s site) (Workload, bool, error) {
	obj := o.U.Object
	specMap, found, err := lookupMap(obj, s.spec)
	if err != nil {
		return Workload{}, false, fail(o.Ref, s.spec, err)
	}
	if !found {
		return Workload{}, false, nil
	}
	specPath := pointer(s.spec)
	var spec corev1.PodSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(specMap, &spec); err != nil {
		return Workload{}, false, fail(o.Ref, s.spec, err)
	}
	labels, err := merged(o.Ref, obj, "labels", s.meta, s.extra)
	if err != nil {
		return Workload{}, false, err
	}
	annotations, err := merged(o.Ref, obj, "annotations", s.meta, s.extra)
	if err != nil {
		return Workload{}, false, err
	}
	maps.Copy(labels, s.synth)
	for _, k := range s.drop {
		delete(labels, k)
	}
	return Workload{
		Owner:       o.Ref,
		Object:      o,
		SpecPath:    specPath,
		Group:       s.group,
		Labels:      labels,
		Annotations: annotations,
		Spec:        spec,
		Containers:  containersOf(specPath, spec),
	}, true, nil
}

func containersOf(specPath string, spec corev1.PodSpec) []Container {
	var out []Container
	for i, c := range spec.InitContainers {
		out = append(out, Container{Index: i, Init: true, Spec: c, Path: specPath + "/initContainers/" + strconv.Itoa(i)})
	}
	for i, c := range spec.Containers {
		out = append(out, Container{Index: i, Spec: c, Path: specPath + "/containers/" + strconv.Itoa(i)})
	}
	return out
}

func lookup(root any, path []string) (any, bool, error) {
	cur := root
	for i, seg := range path {
		switch node := cur.(type) {
		case nil:
			return nil, false, nil
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false, nil
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, false, fmt.Errorf("%s: expected object, got %T", pointer(path[:i]), cur)
			}
			if idx < 0 || idx >= len(node) {
				return nil, false, nil
			}
			cur = node[idx]
		default:
			return nil, false, fmt.Errorf("%s: expected object, got %T", pointer(path[:i]), cur)
		}
	}
	return cur, true, nil
}

func lookupMap(obj map[string]any, path []string) (map[string]any, bool, error) {
	v, found, err := lookup(obj, path)
	if err != nil {
		return nil, false, err
	}
	if !found || v == nil {
		return nil, false, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("expected object, got %T", v)
	}
	return m, true, nil
}

func merged(ref load.ObjectRef, obj map[string]any, key string, sources ...[]string) (map[string]string, error) {
	out := map[string]string{}
	for _, src := range sources {
		if src == nil {
			continue
		}
		path := slices.Concat(src, []string{key})
		m, err := stringMap(obj, path)
		if err != nil {
			return nil, fail(ref, path, err)
		}
		maps.Copy(out, m)
	}
	return out, nil
}

func stringMap(obj map[string]any, path []string) (map[string]string, error) {
	m, found, err := lookupMap(obj, path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	out := make(map[string]string, len(m))
	for k, raw := range m {
		if raw == nil {
			out[k] = ""
			continue
		}
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%s: expected string, got %T", k, raw)
		}
		out[k] = s
	}
	return out, nil
}

func pointer(path []string) string {
	return "/" + strings.Join(path, "/")
}

func fail(ref load.ObjectRef, path []string, err error) error {
	return fmt.Errorf("%s: %s: %w", ref, pointer(path), err)
}
