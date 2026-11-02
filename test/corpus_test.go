package test

import (
	"path/filepath"
	"testing"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	corpusRoot       = "corpus"
	defaultNamespace = "default"
	profileID        = "dora"
)

func TestCorpus(t *testing.T) {
	cases, err := corpus.Cases(corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range cases {
		name, err := filepath.Rel(corpusRoot, dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.ToSlash(name), func(t *testing.T) {
			runCase(t, dir)
		})
	}
}

func runCase(t *testing.T, dir string) {
	t.Helper()
	spec, err := corpus.LoadSpec(filepath.Join(dir, corpus.ExpectedFile))
	if err != nil {
		t.Fatalf("case %s: %v", dir, err)
	}
	input, err := corpus.InputPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	namespace := spec.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}
	r, err := scan.Manifest(scan.Options{
		Inputs:        []string{input},
		Namespace:     namespace,
		ProfileID:     profileID,
		Deterministic: true,
	})
	if err != nil {
		t.Fatalf("case %s: scan failed: %v", dir, err)
	}
	compareCase(t, dir, spec, r)
}

func compareCase(t *testing.T, dir string, spec corpus.Spec, r *report.Report) {
	t.Helper()
	for _, id := range corpus.UnknownChecks(r, spec.Checks) {
		t.Errorf("case %s: check %s is not in the report", dir, id)
	}
	missing, extra := corpus.Diff(spec.Expect, corpus.Actual(r, spec.Checks))
	for _, e := range missing {
		t.Errorf("case %s: missing %s", dir, e)
	}
	for _, e := range extra {
		t.Errorf("case %s: extra %s", dir, e)
	}
	for _, msg := range corpus.NAMismatches(r, spec.NA) {
		t.Errorf("case %s: %s", dir, msg)
	}
}
