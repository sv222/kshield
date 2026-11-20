package cli

import (
	"strings"
	"testing"
)

func TestChecksExplainPortedChecks(t *testing.T) {
	cases := []struct {
		id, display, fix, severity, title, article string
	}{
		{"KS-WL-015", "DORA-CH2-034", "manual", "fail", "hostPath volume outside", "DORA Art. 9(3)(c)"},
		{"KS-WL-016", "DORA-CH2-035", "patch", "fail", "hostPort on an AI container", "DORA Art. 9(3)(c)"},
		{"KS-AI-010", "DORA-CH2-036", "manual", "warn", "without API key or gateway auth evidence", "DORA Art. 9(4)(d)"},
		{"KS-AI-011", "DORA-CH2-037", "manual", "warn", "Debug or insecure flags", "DORA Art. 9(4)(d)"},
		{"KS-AI-012", "DORA-CH2-038", "manual", "fail", "Unsafe model source or format", "DORA Art. 9(3)(b)"},
		{"KS-NET-004", "DORA-CH2-039", "manual", "warn", "no ingress isolation", "DORA Art. 9(4)(b)"},
		{"KS-AI-013", "DORA-CH2-040", "manual", "fail", "HTTPRoute exposes an AI engine Service", "DORA Art. 9(4)(b)"},
	}
	for _, c := range cases {
		for _, arg := range []string{c.id, c.display, strings.ToLower(c.id)} {
			t.Run(c.id+"/"+arg, func(t *testing.T) {
				code, out, errs := run(t, "", "checks", "explain", arg)
				if code != ExitOK || errs != "" {
					t.Fatalf("code=%d stderr=%q", code, errs)
				}
				for _, want := range []string{c.id + " (" + c.display + ")", "Fix:      " + c.fix, "Severity: " + c.severity, c.title, c.article, "Source: "} {
					if !strings.Contains(out, want) {
						t.Errorf("output lacks %q:\n%s", want, out)
					}
				}
			})
		}
	}
}
