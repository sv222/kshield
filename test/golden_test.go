package test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/cli"
	"github.com/sv222/kshield/internal/pdftext"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const toxicInput = "test/corpus/baseline/toxic/input.yaml"

func TestToxicGolden(t *testing.T) {
	t.Chdir("..")
	for _, tc := range []struct{ format, golden string }{
		{"text", "test/golden/toxic.txt"},
		{"json", "test/golden/toxic.json"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"scan", "manifest", "-f", toxicInput, "-n", "ai-inference", "--deterministic", "--format", tc.format}
			code := cli.Run(args, nil, &stdout, &stderr)
			if code != cli.ExitFindings {
				t.Fatalf("exit code %d, want %d; stderr: %s", code, cli.ExitFindings, stderr.String())
			}
			if stderr.Len() > 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
			if *update {
				if err := os.MkdirAll(filepath.Dir(tc.golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(tc.golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(tc.golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stdout.Bytes(), want) {
				line, w, g := firstDiff(want, stdout.Bytes())
				t.Errorf("%s output differs from %s at line %d (run with -update and review the diff)\nwant: %q\ngot:  %q", tc.format, tc.golden, line, w, g)
			}
		})
	}
}

func TestToxicNis2Golden(t *testing.T) {
	t.Chdir("..")
	for _, tc := range []struct{ format, golden string }{
		{"text", "test/golden/toxic-nis2.txt"},
		{"json", "test/golden/toxic-nis2.json"},
		{"html", "test/golden/toxic-nis2.html"},
		{"sarif", "test/golden/toxic-nis2.sarif"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"scan", "manifest", "-f", toxicInput, "-n", "ai-inference", "--deterministic", "--format", tc.format, "--profile", "nis2"}
			code := cli.Run(args, nil, &stdout, &stderr)
			if code != cli.ExitFindings {
				t.Fatalf("exit code %d, want %d; stderr: %s", code, cli.ExitFindings, stderr.String())
			}
			if stderr.Len() > 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
			if *update {
				if err := os.MkdirAll(filepath.Dir(tc.golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(tc.golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(tc.golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stdout.Bytes(), want) {
				line, w, g := firstDiff(want, stdout.Bytes())
				t.Errorf("%s output differs from %s at line %d (run with -update and review the diff)\nwant: %q\ngot:  %q", tc.format, tc.golden, line, w, g)
			}
		})
	}
}

func TestProfileNamesDoNotLeak(t *testing.T) {
	t.Chdir("..")
	for _, tc := range []struct{ profile, absent, present string }{
		{profile: "nis2", absent: "DORA", present: "NIS2-K8S-001"},
		{profile: "dora", absent: "NIS2", present: "DORA-CH2-001"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			for _, format := range []string{"text", "json", "html", "sarif"} {
				var stdout, stderr bytes.Buffer
				args := []string{"scan", "manifest", "-f", toxicInput, "-n", "ai-inference", "--deterministic", "--format", format, "--profile", tc.profile, "--fail-on", "never"}
				code := cli.Run(args, nil, &stdout, &stderr)
				if code != cli.ExitOK || stderr.Len() > 0 {
					t.Fatalf("%s: exit %d stderr %s", format, code, stderr.String())
				}
				if !strings.Contains(stdout.String(), tc.present) {
					t.Errorf("%s: output misses %s", format, tc.present)
				}
				if strings.Contains(stdout.String(), tc.absent) {
					t.Errorf("%s: output of a %s scan contains %s", format, tc.profile, tc.absent)
				}
			}
			pdf := filepath.Join(t.TempDir(), "report.pdf")
			var stdout, stderr bytes.Buffer
			args := []string{"scan", "manifest", "-f", toxicInput, "-n", "ai-inference", "--deterministic", "--format", "pdf", "--profile", tc.profile, "--fail-on", "never", "--out", pdf}
			if code := cli.Run(args, nil, &stdout, &stderr); code != cli.ExitOK || stderr.Len() > 0 {
				t.Fatalf("pdf: exit %d stderr %s", code, stderr.String())
			}
			raw, err := os.ReadFile(pdf)
			if err != nil {
				t.Fatal(err)
			}
			pages, err := pdftext.Extract(raw)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(pages, "\n")
			if !strings.Contains(text, tc.present) {
				t.Errorf("pdf: text misses %s", tc.present)
			}
			if strings.Contains(text, tc.absent) {
				t.Errorf("pdf: text of a %s scan contains %s", tc.profile, tc.absent)
			}
		})
	}
}

func firstDiff(want, got []byte) (int, string, string) {
	wl := strings.Split(string(want), "\n")
	gl := strings.Split(string(got), "\n")
	for i := range max(len(wl), len(gl)) {
		w, g := lineAt(wl, i), lineAt(gl, i)
		if w != g {
			return i + 1, w, g
		}
	}
	return 0, "", ""
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "<EOF>"
}
