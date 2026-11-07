package remediate

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// restrictedViolations returns the Pod Security Standards `restricted`
// violations of a pod spec, as MANUAL.md lines. It mirrors what the
// `kshield-pod-security` Kyverno rule (podSecurity level restricted)
// rejects. It is a listing for humans, never a check verdict. Windows pods
// are checked for hostProcess, host namespaces and volume types only.
func restrictedViolations(spec corev1.PodSpec) []string {
	var out []string
	if spec.HostNetwork {
		out = append(out, "hostNetwork is true")
	}
	if spec.HostPID {
		out = append(out, "hostPID is true")
	}
	if spec.HostIPC {
		out = append(out, "hostIPC is true")
	}
	if hostProcessOfPod(spec.SecurityContext) {
		out = append(out, "pod windowsOptions.hostProcess is true")
	}
	for _, v := range spec.Volumes {
		if !restrictedVolumeOK(v) {
			out = append(out, "volume "+v.Name+" ("+volumeType(v)+") is not allowed by restricted")
		}
	}
	if spec.OS != nil && spec.OS.Name == corev1.Windows {
		for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
			if hostProcessOf(c.SecurityContext) {
				out = append(out, "container "+c.Name+" windowsOptions.hostProcess is true")
			}
		}
		return out
	}
	containers := slices.Concat(spec.InitContainers, spec.Containers)
	if !runAsNonRootOfPod(spec.SecurityContext) {
		for _, c := range containers {
			if !runAsNonRootOf(c.SecurityContext) {
				out = append(out, "container "+c.Name+" runAsNonRoot is not true")
			}
		}
	}
	if s := spec.SecurityContext; s != nil && s.RunAsUser != nil && *s.RunAsUser == 0 {
		out = append(out, "pod runAsUser is 0")
	}
	for _, c := range containers {
		s := c.SecurityContext
		if s == nil || s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation {
			out = append(out, "container "+c.Name+" allowPrivilegeEscalation is not false")
		}
		if s != nil && s.RunAsUser != nil && *s.RunAsUser == 0 {
			out = append(out, "container "+c.Name+" runAsUser is 0")
		}
		if s == nil || s.SeccompProfile == nil || (s.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault && s.SeccompProfile.Type != corev1.SeccompProfileTypeLocalhost) {
			out = append(out, "container "+c.Name+" seccompProfile is not RuntimeDefault or Localhost")
		}
		if s == nil || s.Capabilities == nil || !slices.ContainsFunc(s.Capabilities.Drop, func(d corev1.Capability) bool { return d == corev1.Capability(dropAll) }) {
			out = append(out, "container "+c.Name+" capabilities drop ALL is missing")
		}
		if s != nil && s.Capabilities != nil {
			for _, a := range s.Capabilities.Add {
				if a != corev1.Capability(netBindService) {
					out = append(out, "container "+c.Name+" capabilities add "+string(a)+" is not allowed")
				}
			}
		}
	}
	return out
}

func hostProcessOf(s *corev1.SecurityContext) bool {
	return s != nil && s.WindowsOptions != nil && s.WindowsOptions.HostProcess != nil && *s.WindowsOptions.HostProcess
}

func hostProcessOfPod(s *corev1.PodSecurityContext) bool {
	return s != nil && s.WindowsOptions != nil && s.WindowsOptions.HostProcess != nil && *s.WindowsOptions.HostProcess
}

func runAsNonRootOf(s *corev1.SecurityContext) bool {
	return s != nil && s.RunAsNonRoot != nil && *s.RunAsNonRoot
}

func runAsNonRootOfPod(s *corev1.PodSecurityContext) bool {
	return s != nil && s.RunAsNonRoot != nil && *s.RunAsNonRoot
}

func restrictedVolumeOK(v corev1.Volume) bool {
	return v.ConfigMap != nil || v.Secret != nil || v.Projected != nil || v.DownwardAPI != nil ||
		v.EmptyDir != nil || v.PersistentVolumeClaim != nil || v.Ephemeral != nil
}

func volumeType(v corev1.Volume) string {
	switch {
	case v.HostPath != nil:
		return "hostPath"
	case v.ConfigMap != nil:
		return "configMap"
	case v.Secret != nil:
		return "secret"
	case v.Projected != nil:
		return "projected"
	case v.DownwardAPI != nil:
		return "downwardAPI"
	case v.EmptyDir != nil:
		return "emptyDir"
	case v.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case v.Ephemeral != nil:
		return "ephemeral"
	case v.CSI != nil:
		return "csi"
	case v.NFS != nil:
		return "nfs"
	}
	return "other"
}
