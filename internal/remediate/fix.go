package remediate

import (
	"strings"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/model"
)

const (
	NonRootUID     = 1000
	CacheDir       = "/kshield/cache"
	DefaultShmSize = "8Gi"

	reasonNoFix = "no automatic fix for this finding"
)

type Residual struct {
	Check   string
	Finding check.Finding
	Reason  string
}

type Fixer func(w model.Workload, f check.Finding, in *check.Input, mode string) ([]Op, *Residual)

type fix func(w model.Workload, f check.Finding, in *check.Input, mode string) ([]Op, string)

type containerFix func(w model.Workload, c model.Container, in *check.Input) ([]Op, string)

func Fixers() map[string]Fixer {
	fixes := map[string]fix{
		"KS-WL-001":  onContainer(fixRunAsRoot),
		"KS-WL-002":  onContainer(fixPrivileged),
		"KS-WL-003":  onContainer(fixCapabilities),
		"KS-WL-004":  fixHostNamespaces,
		"KS-WL-005":  fixShmHostPath,
		"KS-WL-006":  fixShmSizeLimit,
		"KS-WL-007":  fixShareProcessNamespace,
		"KS-WL-008":  onContainer(fixReadOnlyRootFS),
		"KS-WL-009":  onContainer(fixSeccomp),
		"KS-WL-010":  fixAutomountToken,
		"KS-AI-001":  onContainer(fixAPIKey),
		"KS-AI-002":  onContainer(fixTrustRemoteCode),
		"KS-AI-003":  onContainer(fixLoadFormat),
		"KS-AI-005":  fixRayExposure,
		"KS-NET-002": fixBroadEgress,
	}
	out := make(map[string]Fixer, len(fixes))
	for id, fn := range fixes {
		out[id] = bind(id, fn)
	}
	return out
}

func bind(id string, fn fix) Fixer {
	return func(w model.Workload, f check.Finding, in *check.Input, mode string) ([]Op, *Residual) {
		if w.Object == nil || w.Object.U == nil {
			return nil, &Residual{Check: id, Finding: f, Reason: "the object is not in the input"}
		}
		ops, reason := fn(w, f, in, mode)
		if reason == "" && len(ops) == 0 {
			reason = reasonNoFix
		}
		if reason != "" {
			return nil, &Residual{Check: id, Finding: f, Reason: reason}
		}
		return ops, nil
	}
}

func onContainer(fn containerFix) fix {
	return func(w model.Workload, f check.Finding, in *check.Input, _ string) ([]Op, string) {
		for _, c := range w.Containers {
			if f.Path == c.Path || strings.HasPrefix(f.Path, c.Path+"/") {
				return fn(w, c, in)
			}
		}
		return nil, "the finding path " + f.Path + " names no container of the workload"
	}
}
