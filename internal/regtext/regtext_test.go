package regtext

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	nbsp             = string(rune(0xa0))
	emSpace          = string(rune(0x2003))
	ideographicSpace = string(rune(0x3000))
)

func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func verbatimProblems(fsys fs.FS, sources []Source) []string {
	var out []string
	for _, s := range sources {
		if s.FullTextFile == "" {
			out = append(out, fmt.Sprintf("%s: no fullTextFile", s.ID))
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join("sources", s.FullTextFile))
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", s.ID, err))
			continue
		}
		full := normalize(string(b))
		for _, e := range s.Excerpts {
			text := normalize(e.Text)
			if text == "" {
				out = append(out, fmt.Sprintf("%s: excerpt %s has empty text", s.ID, e.ID))
				continue
			}
			if !strings.Contains(full, text) {
				out = append(out, fmt.Sprintf("%s: excerpt %s is not in %s", s.ID, e.ID, s.FullTextFile))
			}
		}
	}
	return out
}

const testDoraYAML = `id: dora
short: DORA
title: Test DORA
celex: "1"
url: https://example.test/dora
fetched: "2026-10-17"
fullTextFile: dora.txt
excerpts:
  - id: dora-9-4-c
    article: "9"
    paragraph: 4
    point: c
    text: Alpha   beta
  - id: dora-10-1
    article: "10"
    paragraph: "1"
    text: Gamma
  - id: dora-5
    article: "5"
    text: Delta
`

const testRTSYAML = `id: rts
short: RTS
title: Test RTS
celex: "2"
url: https://example.test/rts
fetched: ""
fullTextFile: rts.txt
excerpts:
  - id: rts-3
    article: "3"
    text: Epsilon
`

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"sources/dora.yaml": {Data: []byte(testDoraYAML)},
		"sources/dora.txt":  {Data: []byte("Preamble\nAlpha\n  beta\nGamma\nDelta\n")},
		"sources/rts.yaml":  {Data: []byte(testRTSYAML)},
		"sources/rts.txt":   {Data: []byte("Epsilon\n")},
		"sources/notes.md":  {Data: []byte("ignored")},
	}
}

func TestEmbeddedSources(t *testing.T) {
	ss := Sources()
	if len(ss) == 0 {
		t.Fatal("no embedded sources")
	}
	byID := map[string]Source{}
	for _, s := range ss {
		byID[s.ID] = s
	}
	want := []Source{
		{ID: "dora", Short: "DORA", Title: "Regulation (EU) 2022/2554 (DORA)", CELEX: "32022R2554",
			URL: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj", FullTextFile: "dora.txt"},
		{ID: "rts-2024-1774", Short: "RTS 2024/1774", Title: "Commission Delegated Regulation (EU) 2024/1774", CELEX: "32024R1774",
			URL: "https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj", FullTextFile: "rts-2024-1774.txt"},
		{ID: "nis2", Short: "NIS2", Title: "Directive (EU) 2022/2555 (NIS2)", CELEX: "32022L2555",
			URL: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", FullTextFile: "nis2.txt"},
		{ID: "cir-2024-2690", Short: "CIR (EU) 2024/2690", Title: "Commission Implementing Regulation (EU) 2024/2690", CELEX: "32024R2690",
			URL: "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj", FullTextFile: "cir-2024-2690.txt"},
	}
	for _, w := range want {
		s, ok := byID[w.ID]
		if !ok {
			t.Errorf("no source %q", w.ID)
			continue
		}
		if s.Short != w.Short || s.Title != w.Title || s.CELEX != w.CELEX || s.URL != w.URL || s.FullTextFile != w.FullTextFile {
			t.Errorf("source %s: got %+v", w.ID, s)
		}
		if s.CELEX == "" || s.URL == "" || s.Fetched == "" {
			t.Errorf("source %s: CELEX, URL and fetched must be set", w.ID)
		}
		if len(s.Excerpts) == 0 {
			t.Errorf("source %s: no excerpts", w.ID)
		}
	}
}

func TestExcerptsAreVerbatim(t *testing.T) {
	ss := Sources()
	if len(ss) == 0 {
		t.Fatal("no embedded sources")
	}
	for _, p := range verbatimProblems(sourcesFS, ss) {
		t.Error(p)
	}
}

func TestVerbatimDetectsProblems(t *testing.T) {
	fsys := fstest.MapFS{
		"sources/a.txt": {Data: []byte("one  two\n\tthree" + nbsp + "four")},
	}
	good := Source{ID: "a", FullTextFile: "a.txt", Excerpts: []Excerpt{{ID: "ok", Text: "two three\nfour"}}}
	if p := verbatimProblems(fsys, []Source{good}); len(p) != 0 {
		t.Fatalf("got %v", p)
	}
	bad := Source{ID: "a", FullTextFile: "a.txt", Excerpts: []Excerpt{{ID: "wrong", Text: "one three"}}}
	if p := verbatimProblems(fsys, []Source{bad}); len(p) != 1 || !strings.Contains(p[0], "wrong") {
		t.Fatalf("got %v", p)
	}
	empty := Source{ID: "a", FullTextFile: "a.txt", Excerpts: []Excerpt{{ID: "blank", Text: " \n"}}}
	if p := verbatimProblems(fsys, []Source{empty}); len(p) != 1 {
		t.Fatalf("got %v", p)
	}
	missing := Source{ID: "a", FullTextFile: "gone.txt"}
	if p := verbatimProblems(fsys, []Source{missing}); len(p) != 1 {
		t.Fatalf("got %v", p)
	}
	unnamed := Source{ID: "a"}
	if p := verbatimProblems(fsys, []Source{unnamed}); len(p) != 1 {
		t.Fatalf("got %v", p)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"  a \t b\n\nc  ": "a b c",
		"a" + nbsp + "b" + emSpace + "c" + ideographicSpace + "d": "a b c d",
		"a\r\nb": "a b",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabel(t *testing.T) {
	s := Source{ID: "dora", Short: "DORA"}
	cases := []struct {
		e    Excerpt
		want string
	}{
		{Excerpt{Article: "9", Paragraph: "4", Point: "c"}, "DORA Art. 9(4)(c)"},
		{Excerpt{Article: "10", Paragraph: "1"}, "DORA Art. 10(1)"},
		{Excerpt{Article: "5"}, "DORA Art. 5"},
		{Excerpt{Article: "9", Point: "c"}, "DORA Art. 9(c)"},
	}
	for _, tc := range cases {
		if got := label(s, tc.e); got != tc.want {
			t.Errorf("label = %q, want %q", got, tc.want)
		}
	}
	cir := Source{ID: "cir-2024-2690", Short: "CIR (EU) 2024/2690"}
	annex := []struct {
		e    Excerpt
		want string
	}{
		{Excerpt{Article: "Annex", Paragraph: "6.8.1"}, "CIR (EU) 2024/2690 Annex 6.8.1"},
		{Excerpt{Article: "Annex", Paragraph: "9.2", Point: "a"}, "CIR (EU) 2024/2690 Annex 9.2(a)"},
		{Excerpt{Article: "Annex", Paragraph: "3.2.1"}, "CIR (EU) 2024/2690 Annex 3.2.1"},
	}
	for _, tc := range annex {
		if got := label(cir, tc.e); got != tc.want {
			t.Errorf("annex label = %q, want %q", got, tc.want)
		}
	}
}

func TestEmbeddedLabels(t *testing.T) {
	want := map[string]string{
		"nis2-art21-1":       "NIS2 Art. 21(1)",
		"nis2-art21-2-a":     "NIS2 Art. 21(2)(a)",
		"nis2-art21-2-j":     "NIS2 Art. 21(2)(j)",
		"cir-annex-3-2-1":    "CIR (EU) 2024/2690 Annex 3.2.1",
		"cir-annex-6-3-2-b":  "CIR (EU) 2024/2690 Annex 6.3.2(b)",
		"cir-annex-6-8-1":    "CIR (EU) 2024/2690 Annex 6.8.1",
		"cir-annex-9-2-a":    "CIR (EU) 2024/2690 Annex 9.2(a)",
		"cir-annex-11-1-2-c": "CIR (EU) 2024/2690 Annex 11.1.2(c)",
		"dora-art9-4-c":      "DORA Art. 9(4)(c)",
	}
	for id, w := range want {
		if got := Label(id); got != w {
			t.Errorf("Label(%q) = %q, want %q", id, got, w)
		}
	}
}

func TestLoadIndexLookup(t *testing.T) {
	ix, err := load(testFS())
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.sources) != 2 || ix.sources[0].ID != "dora" || ix.sources[1].ID != "rts" {
		t.Fatalf("sources=%+v", ix.sources)
	}
	e, s, ok := ix.lookup("dora-9-4-c")
	if !ok || s.ID != "dora" || e.Article != "9" || e.Paragraph != "4" || e.Point != "c" || e.Text != "Alpha   beta" {
		t.Fatalf("got %+v %+v ok=%v", e, s, ok)
	}
	if s.Excerpts[0].ID != "dora-9-4-c" || len(s.Excerpts) != 3 {
		t.Fatalf("source must carry its excerpts: %+v", s)
	}
	if _, s, ok := ix.lookup("rts-3"); !ok || s.ID != "rts" {
		t.Fatalf("rts-3: %+v ok=%v", s, ok)
	}
	if ix.has("nope") || ix.has("") {
		t.Fatal("unknown id must not be found")
	}
	for id, want := range map[string]string{
		"dora-9-4-c": "DORA Art. 9(4)(c)",
		"dora-10-1":  "DORA Art. 10(1)",
		"dora-5":     "DORA Art. 5",
		"rts-3":      "RTS Art. 3",
		"unknown":    "unknown",
	} {
		if got := ix.label(id); got != want {
			t.Errorf("label(%q) = %q, want %q", id, got, want)
		}
	}
	if p := verbatimProblems(testFS(), ix.sources); len(p) != 0 {
		t.Fatalf("got %v", p)
	}
}

func TestLoadRejects(t *testing.T) {
	withSource := func(yaml string) fstest.MapFS {
		return fstest.MapFS{"sources/x.yaml": {Data: []byte(yaml)}}
	}
	head := "id: x\nshort: X\ntitle: X\nfullTextFile: x.txt\n"
	cases := map[string]struct {
		fs   fstest.MapFS
		want string
	}{
		"malformed yaml":    {withSource("id: ["), "sources/x.yaml"},
		"unknown field":     {withSource(head + "bogus: 1\n"), "sources/x.yaml"},
		"empty source id":   {withSource("short: X\n"), "empty id"},
		"empty short":       {withSource("id: x\n"), "empty short"},
		"empty excerpt id":  {withSource(head + "excerpts:\n  - article: \"1\"\n    text: t\n"), "empty id"},
		"empty article":     {withSource(head + "excerpts:\n  - id: e\n    text: t\n"), `"e"`},
		"empty text":        {withSource(head + "excerpts:\n  - id: e\n    article: \"1\"\n    text: \" \"\n"), `"e"`},
		"duplicate excerpt": {withSource(head + "excerpts:\n  - id: e\n    article: \"1\"\n    text: t\n  - id: e\n    article: \"2\"\n    text: u\n"), `duplicate excerpt id "e"`},
		"duplicate across sources": {fstest.MapFS{
			"sources/x.yaml": {Data: []byte(head + "excerpts:\n  - id: e\n    article: \"1\"\n    text: t\n")},
			"sources/y.yaml": {Data: []byte("id: y\nshort: Y\ntitle: Y\nfullTextFile: y.txt\nexcerpts:\n  - id: e\n    article: \"1\"\n    text: t\n")},
		}, `duplicate excerpt id "e"`},
		"duplicate source id": {fstest.MapFS{
			"sources/x.yaml": {Data: []byte(head)},
			"sources/y.yaml": {Data: []byte(head)},
		}, `duplicate source id "x"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ix, err := load(tc.fs)
			if err == nil {
				t.Fatalf("want error, got %+v", ix)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
		})
	}
}

func TestLoadEmptyDir(t *testing.T) {
	ix, err := load(fstest.MapFS{"sources/dora.txt": {Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.sources) != 0 || ix.has("a") {
		t.Fatalf("got %+v", ix)
	}
}

func TestPublicAPIOnEmbeddedData(t *testing.T) {
	for _, s := range Sources() {
		for _, e := range s.Excerpts {
			if !Has(e.ID) {
				t.Errorf("Has(%q) = false", e.ID)
			}
			got, src, ok := Lookup(e.ID)
			if !ok || got != e || src.ID != s.ID {
				t.Errorf("Lookup(%q) = %+v %+v %v", e.ID, got, src, ok)
			}
			want := s.Short + " Art. " + e.Article
			if e.Article == "Annex" {
				want = s.Short + " Annex " + e.Paragraph
				if e.Point != "" {
					want += "(" + e.Point + ")"
				}
			}
			if l := Label(e.ID); !strings.HasPrefix(l, want) {
				t.Errorf("Label(%q) = %q, want prefix %q", e.ID, l, want)
			}
		}
	}
	if Has("no-such-excerpt") {
		t.Fatal("Has must be false for an unknown id")
	}
	if _, _, ok := Lookup("no-such-excerpt"); ok {
		t.Fatal("Lookup must be false for an unknown id")
	}
	if got := Label("no-such-excerpt"); got != "no-such-excerpt" {
		t.Fatalf("Label = %q", got)
	}
}

func TestSourcesReturnsCopy(t *testing.T) {
	ix, err := load(testFS())
	if err != nil {
		t.Fatal(err)
	}
	cp := ix.copySources()
	cp[0].ID = "mutated"
	cp[0].Excerpts[0].Text = "mutated"
	if ix.sources[0].ID != "dora" || ix.sources[0].Excerpts[0].Text != "Alpha   beta" {
		t.Fatal("copySources must deep-copy")
	}
	_, s, _ := ix.lookup("dora-5")
	s.Excerpts[0].Text = "mutated"
	if ix.sources[0].Excerpts[0].Text != "Alpha   beta" {
		t.Fatal("lookup must return a copy of the source")
	}
}
