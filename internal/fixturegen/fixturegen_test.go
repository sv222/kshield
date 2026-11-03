package fixturegen

import (
	"bytes"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	hardenedInput = "../../test/corpus/baseline/hardened/input.yaml"
	seedEnv       = "KSHIELD_FIXTURE_SEED"
	minMutationsN = 26
)

func TestBaseMatchesHardened(t *testing.T) {
	want, err := os.ReadFile(hardenedInput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseYAML, want) {
		t.Fatalf("base.yaml differs from %s: copy it again", hardenedInput)
	}
}

func scanInput(t *testing.T, input []byte) *report.Report {
	t.Helper()
	r, err := scan.Manifest(scan.Options{
		Inputs:        []string{"-"},
		Stdin:         bytes.NewReader(input),
		Namespace:     Namespace,
		ProfileID:     "dora",
		Deterministic: true,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return r
}

func compare(t *testing.T, input []byte, spec corpus.Spec) {
	t.Helper()
	r := scanInput(t, input)
	missing, extra := corpus.Diff(spec.Expect, corpus.Actual(r, spec.Checks))
	for _, e := range missing {
		t.Errorf("missing %s", e)
	}
	for _, e := range extra {
		t.Errorf("extra %s", e)
	}
	for _, msg := range corpus.NAMismatches(r, spec.NA) {
		t.Error(msg)
	}
}

func TestMutationList(t *testing.T) {
	ms := Mutations()
	if len(ms) < minMutationsN {
		t.Fatalf("got %d mutations, want at least %d", len(ms), minMutationsN)
	}
	names := map[string]bool{}
	for _, m := range ms {
		if names[m.Name] {
			t.Errorf("duplicate mutation %s", m.Name)
		}
		names[m.Name] = true
		if len(m.Expect) == 0 {
			t.Errorf("mutation %s declares no finding", m.Name)
		}
	}
	for _, m := range ms {
		for _, c := range m.Conflicts {
			if !names[c] {
				t.Errorf("mutation %s conflicts with unknown mutation %s", m.Name, c)
			}
		}
	}
}

func TestBaseHasNoFindings(t *testing.T) {
	input, err := build(nil)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, input, corpus.Spec{NA: clusterOnly})
}

func TestEveryMutationAlone(t *testing.T) {
	for _, m := range Mutations() {
		t.Run(m.Name, func(t *testing.T) {
			input, err := build([]Mutation{m})
			if err != nil {
				t.Fatal(err)
			}
			compare(t, input, corpus.Spec{Expect: m.Expect, NA: clusterOnly})
		})
	}
}

func TestSeeds(t *testing.T) {
	seeds := []int64{1001, 1002, 1003}
	if s := os.Getenv(seedEnv); s != "" {
		seed, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q: %v", seedEnv, s, err)
		}
		seeds = append(seeds, seed)
	}
	for _, seed := range seeds {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) {
			input, spec, applied, err := Generate(seed)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("seed %d applied %v", seed, applied)
			if spec.Namespace != Namespace || spec.Checks != nil {
				t.Errorf("spec namespace %q checks %v, want %q and all", spec.Namespace, spec.Checks, Namespace)
			}
			compare(t, input, spec)
		})
	}
}

func TestGenerateDeterministic(t *testing.T) {
	for seed := range int64(50) {
		a, specA, appliedA, err := Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		b, specB, appliedB, err := Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) || !slices.Equal(appliedA, appliedB) || !slices.Equal(specA.Expect, specB.Expect) {
			t.Fatalf("seed %d: two runs differ", seed)
		}
		if len(appliedA) < minMutations || len(appliedA) > maxMutations {
			t.Errorf("seed %d: %d mutations applied, want %d to %d", seed, len(appliedA), minMutations, maxMutations)
		}
		checkNoConflict(t, seed, appliedA)
	}
}

func checkNoConflict(t *testing.T, seed int64, applied []string) {
	t.Helper()
	byName := map[string]Mutation{}
	for _, m := range Mutations() {
		byName[m.Name] = m
	}
	for i, a := range applied {
		for _, b := range applied[i+1:] {
			if conflicts(byName[a], byName[b]) {
				t.Errorf("seed %d: applied conflicting mutations %s and %s", seed, a, b)
			}
		}
	}
}
