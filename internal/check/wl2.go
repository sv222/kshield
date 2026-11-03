package check

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	digestMarker          = "@sha256:"
	nvidiaDevPrefix       = "/dev/nvidia"
	nvidiaVisibleDevices  = "NVIDIA_VISIBLE_DEVICES"
	gpuResource           = corev1.ResourceName("nvidia.com/gpu")
	defaultServiceAccount = "default"
	kindServiceAccount    = "ServiceAccount"
	coreAPIVersion        = "v1"
	automountField        = "automountServiceAccountToken"
)

var (
	visibleDevicesNone = []string{"void", "none"}
	secretEnvName      = regexp.MustCompile(`(?i)(^|_)(TOKEN|SECRETS?|PASSWORDS?|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)(_|$)`)
	fileEnvName        = regexp.MustCompile(`(?i)_(FILE|PATH)$`)
)

func wlReadOnlyRootFS(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if sc := c.Spec.SecurityContext; sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
			return nil
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/securityContext/readOnlyRootFilesystem", "readOnlyRootFilesystem is not set to true")}
	})
}

func wlSeccomp(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		p := effectiveSeccomp(w, c)
		if p != nil && (p.Type == corev1.SeccompProfileTypeRuntimeDefault || p.Type == corev1.SeccompProfileTypeLocalhost) {
			return nil
		}
		msg := "seccompProfile is not set: the container runs without a seccomp profile"
		if p != nil {
			msg = fmt.Sprintf("seccompProfile type is %s (use RuntimeDefault or Localhost)", p.Type)
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/securityContext/seccompProfile", msg)}
	})
}

func serviceAccountName(spec corev1.PodSpec) string {
	switch {
	case spec.ServiceAccountName != "":
		return spec.ServiceAccountName
	case spec.DeprecatedServiceAccount != "":
		return spec.DeprecatedServiceAccount
	}
	return defaultServiceAccount
}

func tokenlessServiceAccounts(objs []load.Object) map[string]bool {
	out := map[string]bool{}
	for _, o := range objs {
		if o.U == nil || o.Ref.Kind != kindServiceAccount || o.Ref.APIVersion != coreAPIVersion {
			continue
		}
		if v, found, err := unstructured.NestedBool(o.U.Object, automountField); err == nil && found && !v {
			out[o.Ref.Namespace+"/"+o.Ref.Name] = true
		}
	}
	return out
}

func wlAutomountToken(in *Input) Result {
	tokenless := in.idx().tokenless
	return forNamespacedWorkloads(in, func(w model.Workload) []Finding {
		field := w.SpecPath + "/" + automountField
		if v := w.Spec.AutomountServiceAccountToken; v != nil {
			if !*v {
				return nil
			}
			return []Finding{violation(w, "", field, "pod sets "+automountField+" to true")}
		}
		name := serviceAccountName(w.Spec)
		if tokenless[w.Owner.Namespace+"/"+name] {
			return nil
		}
		msg := fmt.Sprintf("%s is not false on the pod, and ServiceAccount %q in namespace %q does not set it to false", automountField, name, w.Owner.Namespace)
		return []Finding{violation(w, "", field, msg)}
	})
}

func wlSecretEnv(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		var out []Finding
		for i, e := range c.Spec.Env {
			if e.Value == "" || model.HasK8sReference(e.Value) || e.ValueFrom != nil {
				continue
			}
			if !secretEnvName.MatchString(e.Name) || fileEnvName.MatchString(e.Name) {
				continue
			}
			msg := fmt.Sprintf("env %s holds a literal value (use valueFrom.secretKeyRef)", e.Name)
			out = append(out, violation(w, c.Spec.Name, c.Path+"/env/"+strconv.Itoa(i)+"/value", msg))
		}
		if ParseVLLM(c).APIKeyLiteral {
			msg := "vLLM " + flagAPIKey + " holds a literal value (pass it through an env var from valueFrom.secretKeyRef)"
			out = append(out, violation(w, c.Spec.Name, c.Path+"/"+flagField(c, flagAPIKey), msg))
		}
		return out
	})
}

func wlImageDigest(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if strings.Contains(c.Spec.Image, digestMarker) {
			return nil
		}
		msg := fmt.Sprintf("image %q has no %s digest", c.Spec.Image, digestMarker)
		return []Finding{violation(w, c.Spec.Name, c.Path+"/image", msg)}
	})
}

func wlMemoryLimit(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if _, ok := c.Spec.Resources.Limits[corev1.ResourceMemory]; ok {
			return nil
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/resources/limits/memory", "resources.limits.memory is not set")}
	})
}

func isLiteralVisibleDevices(e corev1.EnvVar) bool {
	return e.Name == nvidiaVisibleDevices && e.ValueFrom == nil && e.Value != "" && !slices.Contains(visibleDevicesNone, e.Value)
}

func wlGPUAccess(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		var out []Finding
		for i, v := range w.Spec.Volumes {
			if v.HostPath == nil || !strings.HasPrefix(path.Clean(v.HostPath.Path), nvidiaDevPrefix) {
				continue
			}
			msg := fmt.Sprintf("volume %q mounts hostPath %s (request GPUs through the device plugin with %s limits)", v.Name, v.HostPath.Path, gpuResource)
			out = append(out, violation(w, "", w.SpecPath+"/volumes/"+strconv.Itoa(i), msg))
		}
		for _, c := range w.Containers {
			if _, ok := c.Spec.Resources.Limits[gpuResource]; ok {
				continue
			}
			for i, e := range c.Spec.Env {
				if !isLiteralVisibleDevices(e) {
					continue
				}
				msg := fmt.Sprintf("%s=%s without a %s limit (request GPUs through the device plugin)", nvidiaVisibleDevices, e.Value, gpuResource)
				out = append(out, violation(w, c.Spec.Name, c.Path+"/env/"+strconv.Itoa(i), msg))
			}
		}
		return out
	})
}
