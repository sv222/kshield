package test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/fixturegen"
)

func TestEveryManifestCheckIsPlanted(t *testing.T) {
	planted := map[string]bool{}
	for _, m := range fixturegen.Mutations() {
		for _, e := range m.Expect {
			planted[e.Check] = true
		}
	}
	for _, c := range check.All() {
		if c.Tier&check.Manifest == 0 || planted[c.ID] {
			continue
		}
		if !hasBadCase(t, c.ID) {
			t.Errorf("%s: no mutation plants it and no %s/bad-* case expects it", c.ID, strings.ToLower(c.ID))
		}
	}
}

func hasBadCase(t *testing.T, id string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusRoot, "unit", strings.ToLower(id), "bad-*", corpus.ExpectedFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		spec, err := corpus.LoadSpec(f)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(spec.Expect, func(e corpus.Expect) bool { return e.Check == id }) {
			return true
		}
	}
	return false
}
