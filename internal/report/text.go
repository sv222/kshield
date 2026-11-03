package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sv222/kshield/internal/check"
)

const (
	tagWidth = 7
	indent   = "       "

	noAIWorkloadsNote = "note: no AI workloads found; all checks are N/A"
)

func WriteText(w io.Writer, r *Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s | profile %s v%d | %s scan | %d objects, %d AI workloads\n",
		r.Tool.Name, r.Tool.Version, r.Profile.ID, r.Profile.Version, r.Scan.Mode, r.Scan.Objects, r.Scan.AIWorkloads)
	if c := r.Scan.Cluster; c != nil {
		fmt.Fprintf(&b, "cluster: context %s | server %s | namespaces %s | node probe %s\n", c.Context, c.Server, namespacesLabel(c), nodeProbeLabel(c))
	}
	if noAIWorkloads(r) {
		b.WriteString(noAIWorkloadsNote + "\n")
	}
	b.WriteString("\n")
	for _, c := range r.Checks {
		writeCheck(&b, c)
	}
	if len(r.Checks) > 0 {
		b.WriteString("\n")
	}
	s := r.Summary
	unknown := ""
	if s.Unknown > 0 {
		unknown = fmt.Sprintf(" %d UNKNOWN,", s.Unknown)
	}
	fmt.Fprintf(&b, "Summary: %d FAIL,%s %d WARN, %d PASS, %d INFO, %d N/A\n", s.Fail, unknown, s.Warn, s.Pass, s.Info, s.NA)
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "error: %s\n", e)
	}
	if s.Incomplete {
		b.WriteString("scan incomplete\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeCheck(b *strings.Builder, c CheckResult) {
	fmt.Fprintf(b, "%-*s %s %s %s\n", tagWidth-1, "["+c.Verdict+"]", c.Display, c.ID, c.Title)
	if len(c.Findings) == 0 {
		return
	}
	for _, f := range c.Findings {
		b.WriteString(indent)
		b.WriteString(f.Verdict)
		b.WriteString(" ")
		b.WriteString(f.Object.String())
		if f.Group != "" {
			b.WriteString(" group=" + f.Group)
		}
		if f.Container != "" {
			b.WriteString(" container=" + f.Container)
		}
		b.WriteString(": ")
		b.WriteString(f.Message)
		b.WriteString("\n")
	}
	var parts []string
	if label := fixLabel(c); label != "" {
		parts = append(parts, "fix: "+label)
	}
	if len(c.Refs) > 0 {
		labels := make([]string, len(c.Refs))
		for i, ref := range c.Refs {
			labels[i] = ref.Label
		}
		parts = append(parts, "supports evidence for: "+strings.Join(labels, ", "))
	}
	if len(parts) > 0 {
		b.WriteString(indent)
		b.WriteString(strings.Join(parts, " | "))
		b.WriteString("\n")
	}
}

func namespacesLabel(c *ClusterInfo) string {
	if len(c.Namespaces) == 0 {
		return "all"
	}
	return strings.Join(c.Namespaces, ", ")
}

func nodeProbeLabel(c *ClusterInfo) string {
	switch {
	case !c.NodeProbe:
		return "off"
	case c.ProbeNamespace != "":
		return "on (namespace " + c.ProbeNamespace + ")"
	}
	return "on"
}

func noAIWorkloads(r *Report) bool {
	return r.Scan.Objects > 0 && r.Scan.AIWorkloads == 0
}

func fixLabel(c CheckResult) string {
	switch check.Fix(c.Fix) {
	case check.FixPatch:
		return "workload patch (kshield remediate)"
	case check.FixPolicy:
		return "guardrail policy (kshield remediate)"
	case check.FixManual:
		return "manual (kshield checks explain " + c.ID + ")"
	}
	return c.Fix
}
