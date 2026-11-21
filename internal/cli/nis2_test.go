package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/profile"
)

func TestEvidenceNis2Pack(t *testing.T) {
	prefix := keygen(t)
	p, err := profile.Load("nis2")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pack")
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	code, _, errs := run(t, "", "scan", "manifest", "-f", path, "--deterministic", "--profile", "nis2", "--evidence", dir, "--sign-key", prefix+".key")
	if code != ExitFindings || errs != "" {
		t.Fatalf("scan: code=%d stderr=%q", code, errs)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Profile struct {
			ID     string `json:"id"`
			SHA256 string `json:"sha256"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Profile.ID != "nis2" || rep.Profile.SHA256 != p.SHA256 {
		t.Fatalf("profile in pack: id %q sha %q, want nis2 %s", rep.Profile.ID, rep.Profile.SHA256, p.SHA256)
	}
	code, out := verifyOut(t, dir, "--pub-key", prefix+".pub")
	if code != ExitOK || out != "signature: valid\nevidence: OK\n" {
		t.Fatalf("verify: code=%d stdout=%q", code, out)
	}
}

func TestChecksListNis2Golden(t *testing.T) {
	golden(t, "checks-list-nis2.txt", runOK(t, "checks", "list", "--profile", "nis2"))
	golden(t, "checks-list-nis2.json", runOK(t, "checks", "list", "--profile", "nis2", "--format", "json"))
}

func TestChecksExplainNis2Golden(t *testing.T) {
	out := runOK(t, "checks", "explain", "NIS2-K8S-001", "--profile", "nis2")
	golden(t, "checks-explain-nis2-k8s-001.txt", out)
	if !strings.Contains(out, "Note:") || !strings.Contains(out, "lex specialis") { //nolint:misspell
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
