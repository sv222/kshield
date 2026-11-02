package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
)

func isBidiControl(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func showBidi(s string) string {
	if !strings.ContainsFunc(s, isBidiControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isBidiControl(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func showBidiAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = showBidi(s)
	}
	return out
}

func forDisplay(r *Report) *Report {
	out := *r
	out.SchemaVersion = showBidi(r.SchemaVersion)
	out.Tool = Tool{Name: showBidi(r.Tool.Name), Version: showBidi(r.Tool.Version)}
	out.Profile.ID = showBidi(r.Profile.ID)
	out.Profile.Title = showBidi(r.Profile.Title)
	out.Profile.SHA256 = showBidi(r.Profile.SHA256)
	out.Scan.Mode = showBidi(r.Scan.Mode)
	out.Scan.Inputs = showBidiAll(r.Scan.Inputs)
	out.Scan.Namespace = showBidi(r.Scan.Namespace)
	out.Scan.StartedAt = showBidi(r.Scan.StartedAt)
	if c := r.Scan.Cluster; c != nil {
		out.Scan.Cluster = &ClusterInfo{
			Context:        showBidi(c.Context),
			Server:         showBidi(c.Server),
			Namespaces:     showBidiAll(c.Namespaces),
			NodeProbe:      c.NodeProbe,
			ProbeNamespace: showBidi(c.ProbeNamespace),
		}
	}
	if r.Scan.InputDigests != nil {
		out.Scan.InputDigests = make([]load.Digest, len(r.Scan.InputDigests))
		for i, d := range r.Scan.InputDigests {
			out.Scan.InputDigests[i] = load.Digest{Path: showBidi(d.Path), SHA256: showBidi(d.SHA256)}
		}
	}
	out.Errors = showBidiAll(r.Errors)
	out.Checks = slices.Clone(r.Checks)
	for i, c := range r.Checks {
		dc := &out.Checks[i]
		dc.ID = showBidi(c.ID)
		dc.Display = showBidi(c.Display)
		dc.Title = showBidi(c.Title)
		dc.Verdict = showBidi(c.Verdict)
		dc.Severity = showBidi(c.Severity)
		dc.Fix = showBidi(c.Fix)
		if c.Refs != nil {
			dc.Refs = make([]Ref, len(c.Refs))
			for j, ref := range c.Refs {
				dc.Refs[j] = Ref{ID: ref.ID, Label: showBidi(ref.Label), Source: showBidi(ref.Source), URL: showBidi(ref.URL)}
			}
		}
		if c.Findings != nil {
			dc.Findings = make([]Finding, len(c.Findings))
			for j, f := range c.Findings {
				dc.Findings[j] = displayFinding(f)
			}
		}
	}
	return &out
}

func displayFinding(f Finding) Finding {
	out := Finding{
		Object: load.ObjectRef{
			APIVersion: showBidi(f.Object.APIVersion),
			Kind:       showBidi(f.Object.Kind),
			Namespace:  showBidi(f.Object.Namespace),
			Name:       showBidi(f.Object.Name),
		},
		Group:     showBidi(f.Group),
		Container: showBidi(f.Container),
		Path:      showBidi(f.Path),
		Message:   showBidi(f.Message),
		Verdict:   showBidi(f.Verdict),
	}
	if f.Source != nil {
		out.Source = &Source{File: showBidi(f.Source.File), Line: f.Source.Line}
	}
	return out
}
