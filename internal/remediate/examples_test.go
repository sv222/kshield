package remediate

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/sv222/kshield/internal/report"
)

const (
	examplesGlob      = "../../examples/hardened/*.yaml"
	examplesNamespace = "llm"
)

var exampleResidualChecks = []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003"}

func failedChecks(r *report.Report) []string {
	var out []string
	for _, c := range r.Checks {
		if c.Verdict == report.VerdictFail {
			out = append(out, c.ID)
		}
	}
	return out
}

func TestHardenedExamplesScanWithoutFail(t *testing.T) {
	files, err := filepath.Glob(examplesGlob)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d example files, want 2: %v", len(files), files)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			before, scanJSON := scanReport(t, examplesNamespace, file)
			if before.Scan.AIWorkloads != 1 {
				t.Fatalf("aiWorkloads = %d, want 1", before.Scan.AIWorkloads)
			}
			if got := failedChecks(before); !slices.Equal(got, exampleResidualChecks) {
				t.Fatalf("FAIL checks of the example alone = %v, want only the policy checks %v", got, exampleResidualChecks)
			}
			b, err := Run(Options{ScanJSON: scanJSON, Mode: modeAudit})
			if err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := Write(bundle, b); err != nil {
				t.Fatal(err)
			}
			after, _ := scanReport(t, examplesNamespace, file, filepath.Join(bundle, FilePolicies))
			if after.Summary.Fail != 0 {
				t.Fatalf("example with the generated policies has %d FAIL checks: %v", after.Summary.Fail, failedChecks(after))
			}
		})
	}
}
