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
	devDir         = "/dev"
	shmDir         = "/dev/shm"
	netBindService = "NET_BIND_SERVICE"
	dropAll        = "ALL"
)

func forWorkloads(in *Input, visit func(w model.Workload) []Finding) Result {
	return forEach(AIWorkloads(in), visit)
}

func namespacedAIWorkloads(in *Input) []model.Workload {
	var out []model.Workload
	for _, w := range AIWorkloads(in) {
		if w.Owner.Namespace != "" {
			out = append(out, w)
		}
	}
	return out
}

func forNamespacedWorkloads(in *Input, visit func(w model.Workload) []Finding) Result {
	return forEach(namespacedAIWorkloads(in), visit)
}

func forEach(ws []model.Workload, visit func(w model.Workload) []Finding) Result {
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	for _, w := range ws {
		res.Findings = append(res.Findings, visit(w)...)
	}
	return res
}

func forContainers(in *Input, visit func(w model.Workload, c model.Container) []Finding) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		var out []Finding
		for _, c := range w.Containers {
			out = append(out, visit(w, c)...)
		}
		return out
	})
}

func violation(w model.Workload, container, field, msg string) Finding {
	return Finding{
		Object:    w.Owner,
		Group:     w.Group,
		Container: container,
		Path:      field,
		Message:   msg,
		Strength:  Violation,
	}
}

func wlRunAsRoot(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if uid := effectiveRunAsUser(w, c); uid != nil {
			if *uid != 0 {
				return nil
			}
			return []Finding{violation(w, c.Spec.Name, c.Path+"/securityContext/runAsUser", "container runs as UID 0 (root)")}
		}
		if nonRoot := effectiveRunAsNonRoot(w, c); nonRoot != nil && *nonRoot {
			return nil
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/securityContext/runAsNonRoot", "container may run as root: runAsNonRoot is not true and runAsUser is not set")}
	})
}

func wlPrivileged(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		sc := c.Spec.SecurityContext
		var out []Finding
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			out = append(out, violation(w, c.Spec.Name, c.Path+"/securityContext/privileged", "container is privileged"))
		}
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			out = append(out, violation(w, c.Spec.Name, c.Path+"/securityContext/allowPrivilegeEscalation", "allowPrivilegeEscalation is not set to false"))
		}
		return out
	})
}

func wlCapabilities(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		var caps *corev1.Capabilities
		if sc := c.Spec.SecurityContext; sc != nil {
			caps = sc.Capabilities
		}
		var problems []string
		if caps == nil || !slices.ContainsFunc(caps.Drop, func(d corev1.Capability) bool { return strings.EqualFold(string(d), dropAll) }) {
			problems = append(problems, "capabilities.drop does not contain "+dropAll)
		}
		if caps != nil {
			var extra []string
			for _, a := range caps.Add {
				if string(a) != netBindService {
					extra = append(extra, string(a))
				}
			}
			if len(extra) > 0 {
				problems = append(problems, "capabilities.add has "+strings.Join(extra, ", ")+" (only "+netBindService+" is allowed)")
			}
		}
		if len(problems) == 0 {
			return nil
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/securityContext/capabilities", strings.Join(problems, "; "))}
	})
}

func wlHostNamespaces(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		fields := []struct {
			name string
			on   bool
		}{
			{"hostIPC", w.Spec.HostIPC},
			{"hostPID", w.Spec.HostPID},
			{"hostNetwork", w.Spec.HostNetwork},
		}
		var out []Finding
		for _, f := range fields {
			if f.on {
				out = append(out, violation(w, "", w.SpecPath+"/"+f.name, "pod sets "+f.name+" to true"))
			}
		}
		return out
	})
}

func isHostDevPath(p string) bool {
	return p == devDir || p == shmDir || strings.HasPrefix(p, shmDir+"/")
}

func wlHostPathDev(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		var out []Finding
		for i, v := range w.Spec.Volumes {
			if v.HostPath == nil || !isHostDevPath(path.Clean(v.HostPath.Path)) {
				continue
			}
			msg := fmt.Sprintf("volume %q mounts hostPath %s", v.Name, v.HostPath.Path)
			out = append(out, violation(w, "", w.SpecPath+"/volumes/"+strconv.Itoa(i), msg))
		}
		return out
	})
}

func wlShmSizeLimit(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		mountedAtShm := map[string]bool{}
		for _, c := range w.Containers {
			for _, m := range c.Spec.VolumeMounts {
				if path.Clean(m.MountPath) == shmDir {
					mountedAtShm[m.Name] = true
				}
			}
		}
		var out []Finding
		for i, v := range w.Spec.Volumes {
			ed := v.EmptyDir
			if ed == nil || ed.Medium != corev1.StorageMediumMemory || ed.SizeLimit != nil || !mountedAtShm[v.Name] {
				continue
			}
			msg := fmt.Sprintf("memory emptyDir %q is mounted at %s without sizeLimit", v.Name, shmDir)
			out = append(out, violation(w, "", w.SpecPath+"/volumes/"+strconv.Itoa(i)+"/emptyDir/sizeLimit", msg))
		}
		return out
	})
}

func wlShareProcessNamespace(in *Input) Result {
	return forWorkloads(in, func(w model.Workload) []Finding {
		if p := w.Spec.ShareProcessNamespace; p == nil || !*p {
			return nil
		}
		return []Finding{violation(w, "", w.SpecPath+"/shareProcessNamespace", "pod sets shareProcessNamespace to true")}
	})
}
