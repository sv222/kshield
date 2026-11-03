package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/tools/internal/mappingreview"
)

const committedFile = "../../docs/MAPPING-REVIEW.md"

func renderDora(t *testing.T) string {
	t.Helper()
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	head, err := mappingreview.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "review.md")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--profile", "dora", "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), renderDora(t)+mappingreview.Marker+"\n") {
		t.Fatal("run output does not start with head and marker")
	}
	wantOut := "profile dora written to " + out + "\nreview sha256 " + mappingreview.ReviewSHA256(renderDora(t)) + "\n"
	if stdout.String() != wantOut {
		t.Errorf("stdout %q, want %q", stdout.String(), wantOut)
	}
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"--profile", "nope", "--out", out}, 1},
		{[]string{"--out", out, "extra"}, 2},
		{[]string{"--bad"}, 2},
	}
	for _, c := range cases {
		stderr.Reset()
		if code := run(c.args, &stdout, &stderr); code != c.code {
			t.Errorf("%v: exit %d, want %d (stderr %q)", c.args, code, c.code, stderr.String())
		}
	}
}

func TestCommittedFileUpToDate(t *testing.T) {
	b, err := os.ReadFile(committedFile)
	if err != nil {
		t.Fatalf("%v: run go run ./tools/mappingreview", err)
	}
	head, _, ok := mappingreview.Split(string(b))
	if !ok {
		t.Fatalf("%s has no marker line: run go run ./tools/mappingreview", committedFile)
	}
	if head != renderDora(t) {
		t.Fatalf("%s head is not up to date: run go run ./tools/mappingreview", committedFile)
	}
}
