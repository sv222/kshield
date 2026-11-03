package test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/cli"
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
