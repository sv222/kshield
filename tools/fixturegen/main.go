package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/fixturegen"
)

type expectedFile struct {
	Namespace string          `json:"namespace"`
	Checks    string          `json:"checks"`
	Expect    []corpus.Expect `json:"expect"`
	NA        []string        `json:"na"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fixturegen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	seed := fs.Int64("seed", 0, "random seed")
	out := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fs.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "usage: fixturegen -seed N -out DIR")
		return 2
	}
	if err := write(*seed, *out); err != nil {
		_, _ = fmt.Fprintln(stderr, "fixturegen:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "seed %d written to %s\n", *seed, *out)
	return 0
}

func write(seed int64, dir string) error {
	input, spec, applied, err := fixturegen.Generate(seed)
	if err != nil {
		return err
	}
	expect := spec.Expect
	if expect == nil {
		expect = []corpus.Expect{}
	}
	exp, err := yaml.Marshal(expectedFile{Namespace: spec.Namespace, Checks: "all", Expect: expect, NA: spec.NA})
	if err != nil {
		return err
	}
	header := fmt.Sprintf("# fixturegen seed %d: %v\n", seed, applied)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, corpus.InputFile), input, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, corpus.ExpectedFile), append([]byte(header), exp...), 0o644)
}
