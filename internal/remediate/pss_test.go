package remediate

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestRestrictedViolations(t *testing.T) {
	// makeRestricted returns a pod spec that conforms to the Pod Security
	// Standards `restricted` profile: pod-level runAsNonRoot unset (rescued
	// by the container), one container with everything set correctly.
	makeRestricted := func() corev1.PodSpec {
		nonRoot, notAPE := true, false
		return corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "c0",
				Image: "registry.internal/m:v1",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:             &nonRoot,
					AllowPrivilegeEscalation: &notAPE,
					SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{corev1.Capability(dropAll)}},
				},
			}},
		}
	}
	makeWindows := func() corev1.PodSpec {
		s := makeRestricted()
		s.OS = &corev1.PodOS{Name: corev1.Windows}
		return s
	}
	hostProcessSC := func() *corev1.SecurityContext {
		hp := true
		return &corev1.SecurityContext{WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: &hp}}
	}

	cases := []struct {
		name string
		spec corev1.PodSpec
		want []string
	}{
		{"fully restricted spec", makeRestricted(), nil},
		{"hostNetwork", func() corev1.PodSpec {
			s := makeRestricted()
			s.HostNetwork = true
			return s
		}(), []string{"hostNetwork is true"}},
		{"hostPID", func() corev1.PodSpec {
			s := makeRestricted()
			s.HostPID = true
			return s
		}(), []string{"hostPID is true"}},
		{"hostIPC", func() corev1.PodSpec {
			s := makeRestricted()
			s.HostIPC = true
			return s
		}(), []string{"hostIPC is true"}},
		{"pod runAsNonRoot unset and container unset", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.RunAsNonRoot = nil
			return s
		}(), []string{"container c0 runAsNonRoot is not true"}},
		{"container runAsNonRoot rescues unset pod value", func() corev1.PodSpec {
			s := makeRestricted()
			nonRoot := true
			sc := *s.Containers[0].SecurityContext
			s.Containers = []corev1.Container{
				{Name: "c0", SecurityContext: &sc},
				{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &nonRoot}},
			}
			return s
		}(), []string{
			"container c1 allowPrivilegeEscalation is not false",
			"container c1 seccompProfile is not RuntimeDefault or Localhost",
			"container c1 capabilities drop ALL is missing",
		}},
		{"bare container with runAsNonRoot true still lists its other violations", func() corev1.PodSpec {
			nonRoot := true
			return corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &nonRoot}},
				},
			}
		}(), []string{
			"container c1 allowPrivilegeEscalation is not false",
			"container c1 seccompProfile is not RuntimeDefault or Localhost",
			"container c1 capabilities drop ALL is missing",
		}},
		{"pod runAsUser 0", func() corev1.PodSpec {
			s := makeRestricted()
			zero := int64(0)
			s.SecurityContext = &corev1.PodSecurityContext{RunAsUser: &zero}
			return s
		}(), []string{"pod runAsUser is 0"}},
		{"container runAsUser 0", func() corev1.PodSpec {
			s := makeRestricted()
			zero := int64(0)
			s.Containers[0].SecurityContext.RunAsUser = &zero
			return s
		}(), []string{"container c0 runAsUser is 0"}},
		{"allowPrivilegeEscalation unset", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
			return s
		}(), []string{"container c0 allowPrivilegeEscalation is not false"}},
		{"allowPrivilegeEscalation true", func() corev1.PodSpec {
			s := makeRestricted()
			ape := true
			s.Containers[0].SecurityContext.AllowPrivilegeEscalation = &ape
			return s
		}(), []string{"container c0 allowPrivilegeEscalation is not false"}},
		{"seccompProfile unset", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.SeccompProfile = nil
			return s
		}(), []string{"container c0 seccompProfile is not RuntimeDefault or Localhost"}},
		{"seccompProfile other type", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
			return s
		}(), []string{"container c0 seccompProfile is not RuntimeDefault or Localhost"}},
		{"capabilities drop ALL missing", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{}
			return s
		}(), []string{"container c0 capabilities drop ALL is missing"}},
		{"capabilities add SYS_ADMIN", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
			return s
		}(), []string{"container c0 capabilities add SYS_ADMIN is not allowed"}},
		{"capabilities add NET_BIND_SERVICE only", func() corev1.PodSpec {
			s := makeRestricted()
			s.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{corev1.Capability(netBindService)}
			return s
		}(), nil},
		{"hostPath volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/etc/keys"},
			}}}
			return s
		}(), []string{"volume data (hostPath) is not allowed by restricted"}},
		{"configMap volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{},
			}}}
			return s
		}(), nil},
		{"secret volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "sec", VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{},
			}}}
			return s
		}(), nil},
		{"projected volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "proj", VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{},
			}}}
			return s
		}(), nil},
		{"downwardAPI volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "dapi", VolumeSource: corev1.VolumeSource{
				DownwardAPI: &corev1.DownwardAPIVolumeSource{},
			}}}
			return s
		}(), nil},
		{"emptyDir volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			}}}
			return s
		}(), nil},
		{"persistentVolumeClaim volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "pvc", VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "models"},
			}}}
			return s
		}(), nil},
		{"ephemeral volume", func() corev1.PodSpec {
			s := makeRestricted()
			s.Volumes = []corev1.Volume{{Name: "eph", VolumeSource: corev1.VolumeSource{
				Ephemeral: &corev1.EphemeralVolumeSource{},
			}}}
			return s
		}(), nil},
		{"windows pod hostProcess", func() corev1.PodSpec {
			s := makeWindows()
			hp := true
			s.SecurityContext = &corev1.PodSecurityContext{
				WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: &hp},
			}
			return s
		}(), []string{"pod windowsOptions.hostProcess is true"}},
		{"windows container hostProcess", func() corev1.PodSpec {
			s := makeWindows()
			s.Containers[0].SecurityContext = hostProcessSC()
			return s
		}(), []string{"container c0 windowsOptions.hostProcess is true"}},
		{"linux checks skipped on windows pod", func() corev1.PodSpec {
			// No seccomp, privilege escalation allowed, root uid, no
			// capability drop: none of these are reported for a windows pod.
			s := makeWindows()
			s.Containers[0].SecurityContext = nil
			return s
		}(), nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := restrictedViolations(c.spec)
			if !slices.Equal(got, c.want) {
				t.Fatalf("restrictedViolations = %q, want %q", got, c.want)
			}
		})
	}
}
