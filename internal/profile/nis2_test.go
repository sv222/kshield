package profile_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
)

func nis2Profile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Load("nis2")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNis2ProfileValid(t *testing.T) {
	p := nis2Profile(t)
	if p.ID != "nis2" || p.Version != 1 {
		t.Fatalf("got %+v", p)
	}
	if !slices.Contains(profile.IDs(), "nis2") || !slices.Contains(profile.IDs(), "dora") {
		t.Fatalf("IDs = %v", profile.IDs())
	}
	var inProfile []string
	for _, c := range check.All() {
		if _, ok := p.Checks[c.ID]; ok {
			inProfile = append(inProfile, c.ID)
		}
	}
	if err := p.Validate(inProfile, regtext.Has); err != nil {
		t.Fatal(err)
	}
	if len(inProfile) != len(p.Checks) {
		t.Fatalf("%d profile checks, %d known checks", len(p.Checks), len(inProfile))
	}
}

func TestNis2ExcludedChecks(t *testing.T) {
	p := nis2Profile(t)
	var excluded []string
	for _, c := range check.All() {
		if _, ok := p.Checks[c.ID]; !ok {
			excluded = append(excluded, c.ID)
		}
	}
	want := []string{"KS-WL-006", "KS-WL-013"}
	if !slices.Equal(excluded, want) {
		t.Fatalf("excluded = %v, want %v", excluded, want)
	}
}

func TestNis2DisplayIDsSequential(t *testing.T) {
	p := nis2Profile(t)
	displays := make([]string, 0, len(p.Checks))
	for _, e := range p.Checks {
		displays = append(displays, e.Display)
	}
	slices.Sort(displays)
	for i, d := range displays {
		if want := fmt.Sprintf("NIS2-K8S-%03d", i+1); d != want {
			t.Fatalf("display %d = %q, want %q", i+1, d, want)
		}
	}
}

func TestNis2RefsResolve(t *testing.T) {
	p := nis2Profile(t)
	for id, e := range p.Checks {
		for _, ref := range e.Refs {
			if !regtext.Has(ref) {
				t.Errorf("%s: ref %q has no excerpt", id, ref)
			}
		}
	}
}

func TestNis2SeveritiesMatchDora(t *testing.T) {
	p := nis2Profile(t)
	dora, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	for id, e := range p.Checks {
		de, ok := dora.Checks[id]
		if !ok {
			t.Errorf("%s: not in the dora profile", id)
			continue
		}
		if e.Severity != de.Severity {
			t.Errorf("%s: severity %q, dora has %q", id, e.Severity, de.Severity)
		}
	}
}

func TestNis2Note(t *testing.T) {
	p := nis2Profile(t)
	if want := "NIS2 applies to essential and important entities; for financial entities DORA is lex specialis (Art. 4 of the Directive)."; p.Note != want {
		t.Fatalf("note = %q, want %q", p.Note, want)
	}
	dora, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	if dora.Note != "" {
		t.Fatalf("dora note = %q", dora.Note)
	}
}
