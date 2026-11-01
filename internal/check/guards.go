package check

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const GuardLabel = "kshield.io/guard"

const (
	GuardShellExec     = "shell-exec"
	GuardEgressConnect = "egress-connect"
	GuardAdmission     = "admission"
)

const namespacePath = "/metadata/namespace"

func apiGroup(apiVersion string) string {
	group, _, ok := strings.Cut(apiVersion, "/")
	if !ok {
		return ""
	}
	return group
}

func isKind(o load.Object, group string, kinds ...string) bool {
	if o.U == nil || apiGroup(o.Ref.APIVersion) != group {
		return false
	}
	for _, k := range kinds {
		if o.Ref.Kind == k {
			return true
		}
	}
	return false
}

func guardLabelled(o load.Object, guard string) bool {
	s, ok := scalarString(dig(o.U.Object, "metadata", "labels", GuardLabel))
	return ok && s == guard
}

func labelSelectorOf(m map[string]any) (*metav1.LabelSelector, bool) {
	if m == nil {
		return nil, false
	}
	var ls metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &ls); err != nil {
		return nil, false
	}
	return &ls, true
}

func selectorMatches(m map[string]any, labels map[string]string) bool {
	ls, ok := labelSelectorOf(m)
	if !ok {
		return false
	}
	match, err := model.Selects(ls, labels)
	return err == nil && match
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
