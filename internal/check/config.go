package check

import (
	"encoding/base64"
	"maps"
	"slices"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	kindConfigMap = "ConfigMap"
	kindSecret    = "Secret"
)

func MountedConfig(in *Input, w model.Workload) []map[string]any {
	var out []map[string]any
	for _, v := range w.Spec.Volumes {
		if v.ConfigMap == nil {
			continue
		}
		for _, o := range coreObjects(in, kindConfigMap, w.Owner.Namespace, v.ConfigMap.Name) {
			data := map[string]string{}
			raw, _ := dig(o.U.Object, "data").(map[string]any)
			for k, val := range raw {
				if s, ok := val.(string); ok {
					data[k] = s
				}
			}
			out = append(out, parseConfigs(data)...)
		}
	}
	return out
}

type MissingSecret struct {
	Volume string
	Secret string
}

func MountedSecretConfig(in *Input, w model.Workload) (cfgs []map[string]any, missing []MissingSecret) {
	for _, v := range w.Spec.Volumes {
		if v.Secret == nil {
			continue
		}
		objs := coreObjects(in, kindSecret, w.Owner.Namespace, v.Secret.SecretName)
		if len(objs) == 0 {
			missing = append(missing, MissingSecret{Volume: v.Name, Secret: v.Secret.SecretName})
			continue
		}
		for _, o := range objs {
			cfgs = append(cfgs, parseConfigs(secretData(o))...)
		}
	}
	return cfgs, missing
}

func secretData(o load.Object) map[string]string {
	data := map[string]string{}
	raw, _ := dig(o.U.Object, "data").(map[string]any)
	for k, val := range raw {
		s, ok := val.(string)
		if !ok {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			continue
		}
		data[k] = string(b)
	}
	plain, _ := dig(o.U.Object, "stringData").(map[string]any)
	for k, val := range plain {
		if s, ok := val.(string); ok {
			data[k] = s
		}
	}
	return data
}

var envFromKeyFields = map[string][]string{
	kindConfigMap: {"data", "binaryData"},
	kindSecret:    {"data", "stringData"},
}

func EnvFromKey(in *Input, namespace string, c model.Container, key string) (found bool, missing []string) {
	for _, ef := range c.Spec.EnvFrom {
		kind, name := "", ""
		switch {
		case ef.SecretRef != nil:
			kind, name = kindSecret, ef.SecretRef.Name
		case ef.ConfigMapRef != nil:
			kind, name = kindConfigMap, ef.ConfigMapRef.Name
		default:
			continue
		}
		objs := coreObjects(in, kind, namespace, name)
		if len(objs) == 0 {
			missing = append(missing, kind+" "+name)
			continue
		}
		for _, o := range objs {
			for _, field := range envFromKeyFields[kind] {
				for k := range mapOf(dig(o.U.Object, field)) {
					if ef.Prefix+k == key {
						found = true
					}
				}
			}
		}
	}
	return found, missing
}

func coreObjects(in *Input, kind, namespace, name string) []load.Object {
	return in.idx().core[coreKey{kind, namespace, name}]
}

func parseConfigs(data map[string]string) []map[string]any {
	var out []map[string]any
	for _, k := range slices.Sorted(maps.Keys(data)) {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(data[k]), &m); err != nil || m == nil {
			continue
		}
		out = append(out, m)
	}
	return out
}
