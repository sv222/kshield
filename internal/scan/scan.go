package scan

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/version"
)

const (
	toolName             = "kshield"
	deterministicVersion = "0.0.0-deterministic"
	deterministicStart   = "1970-01-01T00:00:00Z"
)

type Options struct {
	Inputs        []string
	Namespace     string
	ProfileID     string
	Deterministic bool
	Stdin         io.Reader
	Now           func() time.Time
}

func Manifest(opt Options) (*report.Report, error) {
	r, _, err := ManifestInput(opt)
	return r, err
}

func ManifestInput(opt Options) (*report.Report, *check.Input, error) {
	p, err := profile.Load(opt.ProfileID)
	if err != nil {
		return nil, nil, err
	}
	return manifestInput(opt, p, check.All())
}

func manifest(opt Options, p *profile.Profile, checks []check.Check) (*report.Report, error) {
	r, _, err := manifestInput(opt, p, checks)
	return r, err
}

func manifestInput(opt Options, p *profile.Profile, checks []check.Check) (*report.Report, *check.Input, error) {
	if err := validate(p, checks); err != nil {
		return nil, nil, err
	}
	digests := []load.Digest{}
	objs, err := load.Read(opt.Inputs, load.Options{DefaultNamespace: opt.Namespace, Stdin: opt.Stdin, Digests: &digests})
	if err != nil {
		return nil, nil, err
	}
	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("no Kubernetes objects found in %s", strings.Join(slashed(opt.Inputs), ", "))
	}
	workloads, err := model.Extract(objs)
	if err != nil {
		return nil, nil, err
	}
	in := &check.Input{Objects: objs, Workloads: workloads}
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          toolInfo(opt),
		Profile:       report.ProfileInfo{ID: p.ID, Version: p.Version, Title: p.Title, SHA256: p.SHA256},
		Scan: report.ScanInfo{
			Mode:         report.ModeManifest,
			Inputs:       slashed(opt.Inputs),
			InputDigests: digests,
			Namespace:    opt.Namespace,
			StartedAt:    startedAt(opt),
			Objects:      len(objs),
			AIWorkloads:  countAI(workloads),
		},
		Checks: []report.CheckResult{},
		Errors: []string{},
	}
	sources := firstSources(objs)
	for _, c := range checks {
		r.Checks = append(r.Checks, evaluate(c, p.Checks[c.ID], in, sources))
	}
	r.Summary = summarize(r.Checks)
	r.Summary.Incomplete = len(r.Errors) > 0
	return r, in, nil
}

func validate(p *profile.Profile, checks []check.Check) error {
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID
	}
	if err := p.Validate(ids, regtext.Has); err != nil {
		return fmt.Errorf("profile %s: %w", p.ID, err)
	}
	return nil
}

func toolInfo(opt Options) report.Tool {
	if opt.Deterministic {
		return report.Tool{Name: toolName, Version: deterministicVersion}
	}
	return report.Tool{Name: toolName, Version: version.Version}
}

func startedAt(opt Options) string {
	if opt.Deterministic {
		return deterministicStart
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	return now().UTC().Format(time.RFC3339)
}

func slashed(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.ToSlash(p)
	}
	return out
}

func countAI(ws []model.Workload) int {
	n := 0
	for _, w := range ws {
		if w.IsAI() {
			n++
		}
	}
	return n
}

func firstSources(objs []load.Object) map[load.ObjectRef]report.Source {
	out := make(map[load.ObjectRef]report.Source, len(objs))
	for _, o := range objs {
		if _, ok := out[o.Ref]; !ok {
			out[o.Ref] = report.Source{File: o.Source.File, Line: o.Source.Line}
		}
	}
	return out
}

func sourceOf(sources map[load.ObjectRef]report.Source, ref load.ObjectRef) *report.Source {
	s, ok := sources[ref]
	if !ok || s.Line <= 0 {
		return nil
	}
	return &s
}

func evaluate(c check.Check, e profile.Entry, in *check.Input, sources map[load.ObjectRef]report.Source) report.CheckResult {
	return checkResult(c, e, check.Evaluate(c, in), sources)
}

func checkResult(c check.Check, e profile.Entry, res check.Result, sources map[load.ObjectRef]report.Source) report.CheckResult {
	out := report.CheckResult{
		ID:       c.ID,
		Display:  e.Display,
		Title:    c.Title,
		Severity: string(e.Severity),
		Fix:      string(c.Fix),
		Refs:     make([]report.Ref, 0, len(e.Refs)),
		Findings: []report.Finding{},
	}
	for _, id := range e.Refs {
		_, src, _ := regtext.Lookup(id)
		out.Refs = append(out.Refs, report.Ref{ID: id, Label: regtext.Label(id), Source: src.ID, URL: src.URL})
	}
	if !res.Applicable {
		out.Verdict = report.VerdictNA
		return out
	}
	for _, f := range res.Findings {
		out.Findings = append(out.Findings, report.Finding{
			Object:    f.Object,
			Source:    sourceOf(sources, f.Object),
			Group:     f.Group,
			Container: f.Container,
			Path:      f.Path,
			Message:   f.Message,
			Verdict:   FindingVerdict(e.Severity, f.Strength),
		})
	}
	out.Verdict = worst(out.Findings)
	return out
}

func FindingVerdict(sev profile.Severity, s check.Strength) string {
	switch {
	case s == check.Unknown:
		return report.VerdictUnknown
	case sev == profile.SevInfo:
		return report.VerdictInfo
	case sev == profile.SevFail && s == check.Violation:
		return report.VerdictFail
	}
	return report.VerdictWarn
}

func worst(fs []report.Finding) string {
	verdict := report.VerdictPass
	for _, f := range fs {
		if rank(f.Verdict) > rank(verdict) {
			verdict = f.Verdict
		}
	}
	return verdict
}

func rank(verdict string) int {
	switch verdict {
	case report.VerdictFail:
		return 4
	case report.VerdictUnknown:
		return 3
	case report.VerdictWarn:
		return 2
	case report.VerdictInfo:
		return 1
	}
	return 0
}

func summarize(cs []report.CheckResult) report.Summary {
	var s report.Summary
	for _, c := range cs {
		switch c.Verdict {
		case report.VerdictFail:
			s.Fail++
		case report.VerdictWarn:
			s.Warn++
		case report.VerdictInfo:
			s.Info++
		case report.VerdictPass:
			s.Pass++
		case report.VerdictNA:
			s.NA++
		case report.VerdictUnknown:
			s.Unknown++
		}
	}
	return s
}
