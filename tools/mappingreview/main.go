package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/tools/internal/mappingreview"
)

const usage = "usage: go run ./tools/mappingreview [--profile dora] [--out docs/MAPPING-REVIEW.md]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("mappingreview", flag.ContinueOnError)
	fset.SetOutput(stderr)
	id := fset.String("profile", "dora", "profile id")
	out := fset.String("out", "docs/MAPPING-REVIEW.md", "output file")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() > 0 || *out == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	sum, err := generate(*id, *out)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mappingreview:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "profile %s written to %s\n", *id, *out)
	_, _ = fmt.Fprintf(stdout, "review sha256 %s\n", sum)
	return 0
}

func generate(id, out string) (string, error) {
	p, err := profile.Load(id)
	if err != nil {
		return "", err
	}
	head, err := mappingreview.Render(p)
	if err != nil {
		return "", err
	}
	if err := mappingreview.Update(out, head); err != nil {
		return "", err
	}
	return mappingreview.ReviewSHA256(head), nil
}
