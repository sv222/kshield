package cli

import (
	"strings"
	"testing"
)

func TestChecksListNis2Golden(t *testing.T) {
	golden(t, "checks-list-nis2.txt", runOK(t, "checks", "list", "--profile", "nis2"))
	golden(t, "checks-list-nis2.json", runOK(t, "checks", "list", "--profile", "nis2", "--format", "json"))
}

func TestChecksExplainNis2Golden(t *testing.T) {
	out := runOK(t, "checks", "explain", "NIS2-K8S-001", "--profile", "nis2")
	golden(t, "checks-explain-nis2-k8s-001.txt", out)
	if !strings.Contains(out, "Note:") || !strings.Contains(out, "lex specialis") {
		t.Errorf("explain misses the applicability note:\n%s", out)
	}
	if got := runOK(t, "checks", "explain", "KS-WL-001", "--profile", "nis2"); got != out {
		t.Errorf("explain by check id differs from display id:\n%s", got)
	}
}

func TestChecksExplainNis2Excluded(t *testing.T) {
	out := runOK(t, "checks", "explain", "KS-WL-006", "--profile", "nis2")
	if !strings.Contains(out, "References: none in this profile") {
		t.Errorf("explain of an excluded check misses the references line:\n%s", out)
	}
}

func TestUnknownProfileError(t *testing.T) {
	for _, args := range [][]string{
		{"checks", "list", "--profile", "nope"},
		{"checks", "explain", "KS-WL-001", "--profile", "nope"},
		{"scan", "manifest", "-f", "-", "--profile", "nope"},
	} {
		code, _, errs := run(t, "", args...)
		if code != ExitUsage || !strings.Contains(errs, "dora, nis2") {
			t.Errorf("%v: code=%d stderr=%q", args, code, errs)
		}
	}
}
