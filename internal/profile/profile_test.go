package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

func hasRefIn(ids ...string) func(string) bool {
	return func(id string) bool { return slices.Contains(ids, id) }
}

func TestParse(t *testing.T) {
	src := []byte(`id: p
version: 3
title: Title
checks:
  KS-T-001:
    display: P-1
    severity: fail
    refs: [a, b]
  KS-T-002:
    display: P-2
    severity: info
    refs: [c]
`)
	p, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "p" || p.Version != 3 || p.Title != "Title" || len(p.Checks) != 2 {
		t.Fatalf("got %+v", p)
	}
	e := p.Checks["KS-T-001"]
	if e.Display != "P-1" || e.Severity != SevFail || !slices.Equal(e.Refs, []string{"a", "b"}) {
		t.Fatalf("got %+v", e)
	}
	if p.Checks["KS-T-002"].Severity != SevInfo {
		t.Fatalf("got %+v", p.Checks["KS-T-002"])
	}
	sum := sha256.Sum256(src)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256=%s", p.SHA256)
	}
}

func TestParseSHA256IsOfRawBytes(t *testing.T) {
	a, err := Parse([]byte("id: p\nversion: 1\nchecks: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte("id: p\nversion: 1\nchecks: {}\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 == b.SHA256 {
		t.Fatal("hash must change with the raw bytes")
	}
	if a.SHA256 != strings.ToLower(a.SHA256) || len(a.SHA256) != 64 {
		t.Fatalf("SHA256=%q", a.SHA256)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"malformed":     "id: [",
		"unknown field": "id: p\nversion: 1\nchecks: {}\nextra: 1\n",
		"unknown entry": "id: p\nversion: 1\nchecks:\n  KS-T-001:\n    display: D\n    severty: fail\n    refs: [a]\n",
		"duplicate key": "id: p\nversion: 1\nchecks:\n  KS-T-001:\n    display: D\n    severity: fail\n    refs: [a]\n  KS-T-001:\n    display: E\n    severity: fail\n    refs: [a]\n",
		"bad version":   "id: p\nversion: one\nchecks: {}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if p, err := Parse([]byte(src)); err == nil {
				t.Fatalf("want error, got %+v", p)
			}
		})
	}
}

func TestDummySecondProfile(t *testing.T) {
	b, err := os.ReadFile("testdata/dummy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate([]string{"KS-T-001"}, func(id string) bool { return id == "dummy-1" }); err != nil {
		t.Fatal(err)
	}
	if p.ID != "dummy" {
		t.Fatalf("ID=%q", p.ID)
	}
}

func valid() *Profile {
	return &Profile{
		ID: "t", Version: 1, Title: "T",
		Checks: map[string]Entry{
			"KS-T-001": {Display: "T-1", Severity: SevFail, Refs: []string{"r1"}},
			"KS-T-002": {Display: "T-2", Severity: SevWarn, Refs: []string{"r1", "r2"}},
			"KS-T-003": {Display: "T-3", Severity: SevInfo, Refs: []string{"r2"}},
		},
	}
}

var allIDs = []string{"KS-T-001", "KS-T-002", "KS-T-003"}

func TestValidateOK(t *testing.T) {
	if err := valid().Validate(allIDs, hasRefIn("r1", "r2")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Profile)
		ids    []string
		want   []string
	}{
		{
			name:   "registered check without entry",
			mutate: func(p *Profile) { delete(p.Checks, "KS-T-003") },
			ids:    allIDs,
			want:   []string{"KS-T-003", "no profile entry"},
		},
		{
			name: "entry for unknown check",
			mutate: func(p *Profile) {
				p.Checks["KS-T-099"] = Entry{Display: "T-99", Severity: SevFail, Refs: []string{"r1"}}
			},
			ids:  allIDs,
			want: []string{"KS-T-099", "unknown check"},
		},
		{
			name: "unknown ref",
			mutate: func(p *Profile) {
				p.Checks["KS-T-001"] = Entry{Display: "T-1", Severity: SevFail, Refs: []string{"r1", "nope"}}
			},
			ids:  allIDs,
			want: []string{"KS-T-001", `unknown ref "nope"`},
		},
		{
			name:   "empty refs",
			mutate: func(p *Profile) { p.Checks["KS-T-001"] = Entry{Display: "T-1", Severity: SevFail} },
			ids:    allIDs,
			want:   []string{"KS-T-001", "empty refs"},
		},
		{
			name: "duplicate display",
			mutate: func(p *Profile) {
				p.Checks["KS-T-002"] = Entry{Display: "T-1", Severity: SevWarn, Refs: []string{"r1"}}
			},
			ids:  allIDs,
			want: []string{"KS-T-002", `duplicate display "T-1"`, "KS-T-001"},
		},
		{
			name:   "bad severity",
			mutate: func(p *Profile) { p.Checks["KS-T-001"] = Entry{Display: "T-1", Severity: "boom", Refs: []string{"r1"}} },
			ids:    allIDs,
			want:   []string{"KS-T-001", `severity "boom"`},
		},
		{
			name:   "empty severity",
			mutate: func(p *Profile) { p.Checks["KS-T-001"] = Entry{Display: "T-1", Refs: []string{"r1"}} },
			ids:    allIDs,
			want:   []string{"KS-T-001", `severity ""`},
		},
		{
			name:   "empty display",
			mutate: func(p *Profile) { p.Checks["KS-T-001"] = Entry{Severity: SevFail, Refs: []string{"r1"}} },
			ids:    allIDs,
			want:   []string{"KS-T-001", "empty display"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.mutate(p)
			err := p.Validate(tc.ids, hasRefIn("r1", "r2"))
			if err == nil {
				t.Fatal("want error")
			}
			lines := strings.Split(err.Error(), "\n")
			if len(lines) != 1 {
				t.Fatalf("want exactly one problem, got %d: %q", len(lines), err)
			}
			for _, w := range tc.want {
				if !strings.Contains(lines[0], w) {
					t.Fatalf("message %q lacks %q", lines[0], w)
				}
			}
		})
	}
}

func TestValidateCollectsAllProblems(t *testing.T) {
	p := &Profile{
		ID: "t", Version: 1,
		Checks: map[string]Entry{
			"KS-T-001": {Display: "D", Severity: SevFail, Refs: []string{"bad"}},
			"KS-T-002": {Display: "D", Severity: "x", Refs: nil},
			"KS-T-077": {Display: "E", Severity: SevInfo, Refs: []string{"r1"}},
		},
	}
	err := p.Validate([]string{"KS-T-001", "KS-T-002", "KS-T-003"}, hasRefIn("r1"))
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, w := range []string{
		"KS-T-003", "no profile entry",
		"KS-T-077", "unknown check",
		`unknown ref "bad"`,
		"empty refs",
		`duplicate display "D"`,
		`severity "x"`,
	} {
		if !strings.Contains(msg, w) {
			t.Errorf("missing %q in:\n%s", w, msg)
		}
	}
	if n := len(strings.Split(msg, "\n")); n != 6 {
		t.Errorf("want 6 problems, got %d:\n%s", n, msg)
	}
}

func TestValidateIsDeterministic(t *testing.T) {
	p := &Profile{Checks: map[string]Entry{}}
	for _, id := range []string{"KS-T-009", "KS-T-001", "KS-T-005", "KS-T-003", "KS-T-007"} {
		p.Checks[id] = Entry{Display: "same", Severity: "x"}
	}
	first := p.Validate(nil, hasRefIn()).Error()
	for range 20 {
		if got := p.Validate(nil, hasRefIn()).Error(); got != first {
			t.Fatalf("order changed:\n%s\n---\n%s", first, got)
		}
	}
}

func TestValidateNoChecksNoEntries(t *testing.T) {
	p := &Profile{ID: "t", Version: 1, Checks: map[string]Entry{}}
	if err := p.Validate(nil, hasRefIn()); err != nil {
		t.Fatal(err)
	}
	var nilMap Profile
	if err := nilMap.Validate(nil, hasRefIn()); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	p, err := Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "dora" || p.Version != 1 || !strings.Contains(p.Title, "2022/2554") {
		t.Fatalf("got %+v", p)
	}
	raw, err := os.ReadFile("profiles/dora.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256=%s, file hash=%s", p.SHA256, hex.EncodeToString(sum[:]))
	}
}

func TestLoadUnknown(t *testing.T) {
	for _, id := range []string{"nope", "", "../profile", "dora/../dora", "DORA"} {
		if p, err := Load(id); err == nil {
			t.Fatalf("Load(%q) = %+v, want error", id, p)
		}
	}
}

func TestIDs(t *testing.T) {
	ids := IDs()
	if !slices.Contains(ids, "dora") {
		t.Fatalf("IDs=%v", ids)
	}
	if !slices.IsSorted(ids) {
		t.Fatalf("IDs not sorted: %v", ids)
	}
	for _, id := range ids {
		if _, err := Load(id); err != nil {
			t.Errorf("Load(%q): %v", id, err)
		}
	}
}
