package check

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/model"
)

func ptr[T any](v T) *T { return &v }

func ctxWorkload(sc *corev1.PodSecurityContext) model.Workload {
	return model.Workload{Spec: corev1.PodSpec{SecurityContext: sc}}
}

func ctxContainer(sc *corev1.SecurityContext) model.Container {
	return model.Container{Spec: corev1.Container{SecurityContext: sc}}
}

func TestEffectiveSecurityContext(t *testing.T) {
	t.Run("pod runAsNonRoot true and container unset gives true", func(t *testing.T) {
		w := ctxWorkload(&corev1.PodSecurityContext{RunAsNonRoot: ptr(true)})
		got := effectiveRunAsNonRoot(w, ctxContainer(nil))
		if got == nil || !*got {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("pod runAsUser 1000 and container runAsUser 0 gives 0", func(t *testing.T) {
		w := ctxWorkload(&corev1.PodSecurityContext{RunAsUser: ptr(int64(1000))})
		c := ctxContainer(&corev1.SecurityContext{RunAsUser: ptr(int64(0))})
		got := effectiveRunAsUser(w, c)
		if got == nil || *got != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("pod seccomp RuntimeDefault and container Unconfined gives Unconfined", func(t *testing.T) {
		w := ctxWorkload(&corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}})
		c := ctxContainer(&corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}})
		got := effectiveSeccomp(w, c)
		if got == nil || got.Type != corev1.SeccompProfileTypeUnconfined {
			t.Fatalf("got %v", got)
		}
	})
}

func TestEffectiveRunAsUser(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.PodSecurityContext
		ctr  *corev1.SecurityContext
		want *int64
	}{
		{"no contexts", nil, nil, nil},
		{"empty contexts", &corev1.PodSecurityContext{}, &corev1.SecurityContext{}, nil},
		{"pod only", &corev1.PodSecurityContext{RunAsUser: ptr(int64(1000))}, nil, ptr(int64(1000))},
		{"container only", nil, &corev1.SecurityContext{RunAsUser: ptr(int64(2000))}, ptr(int64(2000))},
		{"container wins", &corev1.PodSecurityContext{RunAsUser: ptr(int64(1000))}, &corev1.SecurityContext{RunAsUser: ptr(int64(2000))}, ptr(int64(2000))},
		{"container context without the field falls back to pod", &corev1.PodSecurityContext{RunAsUser: ptr(int64(1000))}, &corev1.SecurityContext{RunAsNonRoot: ptr(true)}, ptr(int64(1000))},
		{"container zero wins over pod", &corev1.PodSecurityContext{RunAsUser: ptr(int64(1000))}, &corev1.SecurityContext{RunAsUser: ptr(int64(0))}, ptr(int64(0))},
		{"pod zero loses to container", &corev1.PodSecurityContext{RunAsUser: ptr(int64(0))}, &corev1.SecurityContext{RunAsUser: ptr(int64(1000))}, ptr(int64(1000))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveRunAsUser(ctxWorkload(tc.pod), ctxContainer(tc.ctr))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", deref(got), deref(tc.want))
			}
		})
	}
}

func TestEffectiveRunAsNonRoot(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.PodSecurityContext
		ctr  *corev1.SecurityContext
		want *bool
	}{
		{"no contexts", nil, nil, nil},
		{"empty contexts", &corev1.PodSecurityContext{}, &corev1.SecurityContext{}, nil},
		{"pod only", &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}, nil, ptr(true)},
		{"container only", nil, &corev1.SecurityContext{RunAsNonRoot: ptr(true)}, ptr(true)},
		{"container false wins over pod true", &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}, &corev1.SecurityContext{RunAsNonRoot: ptr(false)}, ptr(false)},
		{"container true wins over pod false", &corev1.PodSecurityContext{RunAsNonRoot: ptr(false)}, &corev1.SecurityContext{RunAsNonRoot: ptr(true)}, ptr(true)},
		{"container context without the field falls back to pod", &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}, &corev1.SecurityContext{RunAsUser: ptr(int64(0))}, ptr(true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveRunAsNonRoot(ctxWorkload(tc.pod), ctxContainer(tc.ctr))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", deref(got), deref(tc.want))
			}
		})
	}
}

func TestEffectiveSeccomp(t *testing.T) {
	runtimeDefault := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	unconfined := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
	cases := []struct {
		name string
		pod  *corev1.PodSecurityContext
		ctr  *corev1.SecurityContext
		want *corev1.SeccompProfile
	}{
		{"no contexts", nil, nil, nil},
		{"empty contexts", &corev1.PodSecurityContext{}, &corev1.SecurityContext{}, nil},
		{"pod only", &corev1.PodSecurityContext{SeccompProfile: runtimeDefault}, nil, runtimeDefault},
		{"container only", nil, &corev1.SecurityContext{SeccompProfile: unconfined}, unconfined},
		{"container wins", &corev1.PodSecurityContext{SeccompProfile: runtimeDefault}, &corev1.SecurityContext{SeccompProfile: unconfined}, unconfined},
		{"container context without the field falls back to pod", &corev1.PodSecurityContext{SeccompProfile: runtimeDefault}, &corev1.SecurityContext{RunAsNonRoot: ptr(true)}, runtimeDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveSeccomp(ctxWorkload(tc.pod), ctxContainer(tc.ctr))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
