package check

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/model"
)

const (
	rayAPIGroupPrefix = "ray.io/"
	rayHeadSpecSuffix = "/headGroupSpec"
	templateSpec      = "/template/spec"

	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/apis/ray/v1/raycluster_types.go@v1.7.1
	rayServiceTypeField = "serviceType"
	// source: https://github.com/ray-project/kuberay/blob/v1.7.1/ray-operator/apis/ray/v1/raycluster_types.go@v1.7.1
	rayEnableIngressField = "enableIngress"

	rayTLSEnv = "RAY_USE_TLS"
	rayTLSOn  = "1"

	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/src/settings.rs@v1.19.2
	qdrantAPIKeyEnv = "QDRANT__SERVICE__API_KEY"
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/src/settings.rs@v1.19.2
	qdrantTLSEnv = "QDRANT__SERVICE__ENABLE_TLS"
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/config/config.yaml@v1.19.2
	qdrantServiceKey = "service"
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/config/config.yaml@v1.19.2
	qdrantAPIKeyKey = "api_key"
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/config/config.yaml@v1.19.2
	qdrantTLSKey = "enable_tls"
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/src/settings.rs@v1.19.2
	// source: https://github.com/qdrant/qdrant/blob/v1.19.2/Dockerfile@v1.19.2
	qdrantConfigDir = "/qdrant/config"

	// source: https://github.com/milvus-io/milvus/blob/v3.0.3/pkg/config/env_source.go@v3.0.3
	milvusEnvPrefix = "MILVUS_CONF_"
	// source: https://github.com/milvus-io/milvus/blob/v3.0.3/configs/milvus.yaml@v3.0.3
	milvusAuthKey = "common.security.authorizationEnabled"

	fieldEnv     = "env"
	fieldVolumes = "volumes"
)

var (
	rayKinds        = []string{"RayCluster", "RayService", "RayJob"}
	rayPorts        = []int32{6379, 10001, 8265}
	qdrantTrueValue = []string{"true", "1"}
)

func isRayGroup(w model.Workload) bool {
	return strings.HasPrefix(w.Owner.APIVersion, rayAPIGroupPrefix) && slices.Contains(rayKinds, w.Owner.Kind)
}

func rayHeadPrefix(w model.Workload) (string, bool) {
	if !isRayGroup(w) {
		return "", false
	}
	prefix, ok := strings.CutSuffix(w.SpecPath, templateSpec)
	return prefix, ok && strings.HasSuffix(prefix, rayHeadSpecSuffix)
}

func pointerKeys(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func lastEnv(env []corev1.EnvVar, name string) (corev1.EnvVar, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		if env[i].Name == name {
			return env[i], true
		}
	}
	return corev1.EnvVar{}, false
}

func firstContainer(w model.Workload, match func(model.Container) bool) (model.Container, bool) {
	for _, c := range w.Containers {
		if !c.Init && match(c) {
			return c, true
		}
	}
	return model.Container{}, false
}

func suspect(f Finding) Finding {
	f.Strength = Suspect
	return f
}

func aiRayExposed(in *Input) Result {
	ws := AIWorkloads(in)
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	seen := map[string]int{}
	for _, w := range ws {
		prefix, ok := rayHeadPrefix(w)
		if !ok {
			continue
		}
		var head any
		if w.Object != nil && w.Object.U != nil {
			head = dig(w.Object.U.Object, pointerKeys(prefix)...)
		}
		if t := stringOf(dig(head, rayServiceTypeField)); serviceExposureKind(t) != "" {
			msg := fmt.Sprintf("head %s is %s: Ray GCS 6379, client 10001 and dashboard 8265 are reachable outside the cluster", rayServiceTypeField, t)
			res.Findings = append(res.Findings, violation(w, "", prefix+"/"+rayServiceTypeField, msg))
		}
		if on, _ := dig(head, rayEnableIngressField).(bool); on {
			msg := fmt.Sprintf("head %s is true: the operator creates an Ingress to the Ray dashboard 8265", rayEnableIngressField)
			res.Findings = append(res.Findings, violation(w, "", prefix+"/"+rayEnableIngressField, msg))
		}
		res.Findings = appendExposures(res.Findings, seen, Exposures(in, w, rayPorts), false, Violation, func(e Exposure) string {
			return fmt.Sprintf("%s exposes the Ray head of %s on GCS 6379, client 10001 or dashboard 8265 outside the cluster", exposureWhat(e), w.Owner)
		})
	}
	return res
}

func aiRayTLS(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		if !isRayGroup(w) {
			return nil
		}
		c, ok := firstContainer(w, func(c model.Container) bool { return c.Index == 0 })
		if !ok {
			return nil
		}
		path := c.Path + "/" + fieldEnv
		e, set := lastEnv(c.Spec.Env, rayTLSEnv)
		switch {
		case set && e.ValueFrom != nil:
			return []Finding{suspect(violation(w, c.Spec.Name, path, rayTLSEnv+" comes from a reference: the scanner cannot see if it is "+rayTLSOn))}
		case set && e.Value == rayTLSOn:
			return nil
		case set:
			return []Finding{violation(w, c.Spec.Name, path, fmt.Sprintf("%s is %q, not %q: Ray traffic is not encrypted", rayTLSEnv, e.Value, rayTLSOn))}
		}
		return []Finding{violation(w, c.Spec.Name, path, rayTLSEnv+" is not set: Ray traffic is not encrypted")}
	})
}

func aiOllamaExposed(in *Input) Result {
	ws := AIWorkloads(in)
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	seen := map[string]int{}
	for _, w := range ws {
		if !w.HasStack(model.Ollama) {
			continue
		}
		res.Findings = appendExposures(res.Findings, seen, Exposures(in, w, nil), true, Violation, func(e Exposure) string {
			return fmt.Sprintf("%s exposes Ollama in %s outside the cluster without an auth proxy (Ollama has no authentication of its own)", exposureWhat(e), w.Owner)
		})
	}
	return res
}

func isStack(s model.Stack) func(model.Container) bool {
	return func(c model.Container) bool { return c.Stack == s }
}

func aiQdrant(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		if !w.HasStack(model.Qdrant) {
			return nil
		}
		c, ok := firstContainer(w, isStack(model.Qdrant))
		if !ok {
			return nil
		}
		secretCfgs, missing := MountedSecretConfig(in, w)
		cfgs := append(MountedConfig(in, w), secretCfgs...)
		path := c.Path + "/" + fieldEnv
		var out []Finding
		_, envSet := lastEnv(c.Spec.Env, qdrantAPIKeyEnv)
		fromEnvFrom, missingRefs := false, []string(nil)
		if !envSet {
			fromEnvFrom, missingRefs = EnvFromKey(in, w.Owner.Namespace, c, qdrantAPIKeyEnv)
		}
		if !fromEnvFrom && !qdrantHasKey(c.Spec.Env, cfgs) {
			var names []string
			if !envSet {
				names = qdrantConfigSecrets(c, missing)
			}
			switch {
			case len(missingRefs) > 0:
				out = append(out, suspect(violation(w, c.Spec.Name, path, fmt.Sprintf("Qdrant API key may come from envFrom %s, not in the input: the scanner cannot see if %s is set", strings.Join(missingRefs, ", "), qdrantAPIKeyEnv))))
			case len(names) > 0:
				out = append(out, suspect(violation(w, c.Spec.Name, path, fmt.Sprintf("Qdrant API key may come from Secret %s, mounted under %s but not in the input: the scanner cannot see if service.api_key is set", strings.Join(names, ", "), qdrantConfigDir))))
			default:
				out = append(out, violation(w, c.Spec.Name, path, "Qdrant has no API key: "+qdrantAPIKeyEnv+" is not set and no mounted ConfigMap or Secret sets service.api_key"))
			}
		}
		switch tls, known := qdrantTLS(c.Spec.Env, cfgs); {
		case !known:
			out = append(out, suspect(violation(w, c.Spec.Name, path, qdrantTLSEnv+" comes from a reference: the scanner cannot see if TLS is on")))
		case !tls:
			out = append(out, violation(w, c.Spec.Name, path, "Qdrant serves without TLS: "+qdrantTLSEnv+" is not true and no mounted ConfigMap or Secret sets service.enable_tls: true"))
		}
		return out
	})
}

func qdrantConfigSecrets(c model.Container, missing []MissingSecret) []string {
	var names []string
	for _, m := range missing {
		if slices.Contains(names, m.Secret) {
			continue
		}
		if slices.ContainsFunc(c.Spec.VolumeMounts, func(vm corev1.VolumeMount) bool {
			p := path.Clean(vm.MountPath)
			return vm.Name == m.Volume && (p == qdrantConfigDir || strings.HasPrefix(p, qdrantConfigDir+"/"))
		}) {
			names = append(names, m.Secret)
		}
	}
	return names
}

func qdrantHasKey(env []corev1.EnvVar, cfgs []map[string]any) bool {
	if e, set := lastEnv(env, qdrantAPIKeyEnv); set {
		return e.ValueFrom != nil || e.Value != ""
	}
	return slices.ContainsFunc(cfgs, func(m map[string]any) bool {
		s, ok := scalarString(dig(m, qdrantServiceKey, qdrantAPIKeyKey))
		return ok && s != ""
	})
}

func qdrantTLS(env []corev1.EnvVar, cfgs []map[string]any) (on, known bool) {
	if e, set := lastEnv(env, qdrantTLSEnv); set {
		if e.ValueFrom != nil {
			return false, false
		}
		return slices.Contains(qdrantTrueValue, strings.ToLower(e.Value)), true
	}
	return slices.ContainsFunc(cfgs, func(m map[string]any) bool {
		s, ok := scalarString(dig(m, qdrantServiceKey, qdrantTLSKey))
		return ok && slices.Contains(qdrantTrueValue, strings.ToLower(s))
	}), true
}

// source: https://github.com/milvus-io/milvus/blob/v3.0.3/pkg/util/paramtable/base_table.go@v3.0.3
func milvusKey(key string) string {
	k := strings.TrimPrefix(strings.ToLower(key), "milvus.")
	return strings.NewReplacer("/", "", "_", "", ".", "").Replace(k)
}

func milvusAuthEnv(env []corev1.EnvVar) (corev1.EnvVar, bool) {
	want := milvusKey(milvusAuthKey)
	for i := len(env) - 1; i >= 0; i-- {
		name := env[i].Name
		if milvusKey(name) == want || (strings.HasPrefix(name, milvusEnvPrefix) && milvusKey(name[len(milvusEnvPrefix):]) == want) {
			return env[i], true
		}
	}
	return corev1.EnvVar{}, false
}

func aiMilvusAuth(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		if !w.HasStack(model.Milvus) {
			return nil
		}
		path := w.SpecPath + "/" + fieldVolumes
		if c, ok := firstContainer(w, isStack(model.Milvus)); ok {
			if e, set := milvusAuthEnv(c.Spec.Env); set {
				if e.ValueFrom != nil {
					return []Finding{suspect(violation(w, "", path, fmt.Sprintf("env %s comes from a reference: the scanner cannot see if %s is true", e.Name, milvusAuthKey)))}
				}
				if on, err := strconv.ParseBool(e.Value); err == nil && on {
					return nil
				}
				return []Finding{violation(w, "", path, fmt.Sprintf("env %s=%q turns off Milvus authorization (%s)", e.Name, e.Value, milvusAuthKey))}
			}
		}
		on := false
		for _, m := range MountedConfig(in, w) {
			if v, set := milvusAuthValue(m); set {
				on = v
			}
		}
		if on {
			return nil
		}
		return []Finding{violation(w, "", path, "Milvus authorization is off: "+milvusAuthKey+" is not true in the last mounted config file that sets it")}
	})
}

func milvusAuthValue(m map[string]any) (on, set bool) {
	v := dig(m, pointerKeys(strings.ReplaceAll(milvusAuthKey, ".", "/"))...)
	if v == nil {
		return false, false
	}
	s, ok := scalarString(v)
	if !ok {
		return false, true
	}
	on, err := strconv.ParseBool(s)
	return err == nil && on, true
}
