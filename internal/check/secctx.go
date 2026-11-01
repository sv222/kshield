package check

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/model"
)

func effectiveRunAsUser(w model.Workload, c model.Container) *int64 {
	if sc := c.Spec.SecurityContext; sc != nil && sc.RunAsUser != nil {
		return sc.RunAsUser
	}
	if sc := w.Spec.SecurityContext; sc != nil {
		return sc.RunAsUser
	}
	return nil
}

func effectiveRunAsNonRoot(w model.Workload, c model.Container) *bool {
	if sc := c.Spec.SecurityContext; sc != nil && sc.RunAsNonRoot != nil {
		return sc.RunAsNonRoot
	}
	if sc := w.Spec.SecurityContext; sc != nil {
		return sc.RunAsNonRoot
	}
	return nil
}

func effectiveSeccomp(w model.Workload, c model.Container) *corev1.SeccompProfile {
	if sc := c.Spec.SecurityContext; sc != nil && sc.SeccompProfile != nil {
		return sc.SeccompProfile
	}
	if sc := w.Spec.SecurityContext; sc != nil {
		return sc.SeccompProfile
	}
	return nil
}
