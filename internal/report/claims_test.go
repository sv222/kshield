package report

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sv222/kshield/internal/claimcheck"
	"github.com/sv222/kshield/internal/regtext"
)

const toxicJSON = "../../test/golden/toxic.json"

func toxicReport(t *testing.T) *Report {
	t.Helper()
	b, err := os.ReadFile(toxicJSON)
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func citedExcerpts(t *testing.T, r *Report) []string {
	t.Helper()
	var out []string
	for _, c := range r.Checks {
		for _, ref := range c.Refs {
			ex, _, ok := regtext.Lookup(ref.ID)
			if !ok {
				t.Fatalf("check %s cites unknown ref %q", c.ID, ref.ID)
			}
			out = append(out, ex.Text)
		}
	}
	return out
}

func assertNoComplianceClaim(t *testing.T, text string, r *Report) {
	t.Helper()
	if leak := claimcheck.Leak(text, Disclaimer, citedExcerpts(t, r)); leak != "" {
		t.Fatalf("output claims compliance outside the disclaimer and excerpts: %q", leak)
	}
}

func TestAssertNoComplianceClaimUsesDisclaimer(t *testing.T) {
	if leak := claimcheck.Leak("Title\n"+Disclaimer+"\n", Disclaimer, nil); leak != "" {
		t.Fatalf("disclaimer counted as a claim: %q", leak)
	}
}
