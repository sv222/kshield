package regtext

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"sigs.k8s.io/yaml"
)

const sourcesGlob = "sources/*.yaml"

//go:embed sources/*.yaml sources/*.txt
var sourcesFS embed.FS

type Excerpt struct {
	ID        string `json:"id"`
	Article   string `json:"article"`
	Paragraph string `json:"paragraph"`
	Point     string `json:"point"`
	Text      string `json:"text"`
}

type Source struct {
	ID           string    `json:"id"`
	Short        string    `json:"short"`
	Title        string    `json:"title"`
	CELEX        string    `json:"celex"`
	URL          string    `json:"url"`
	Fetched      string    `json:"fetched"`
	FullTextFile string    `json:"fullTextFile"`
	Excerpts     []Excerpt `json:"excerpts"`
}

type position struct {
	source  int
	excerpt int
}

type index struct {
	sources []Source
	byID    map[string]position
}

var embedded = sync.OnceValue(func() *index {
	ix, err := load(sourcesFS)
	if err != nil {
		panic("regtext: embedded sources: " + err.Error())
	}
	return ix
})

func Sources() []Source {
	return embedded().copySources()
}

func Has(id string) bool {
	return embedded().has(id)
}

func Lookup(id string) (Excerpt, Source, bool) {
	return embedded().lookup(id)
}

func Label(id string) string {
	return embedded().label(id)
}

func load(fsys fs.FS) (*index, error) {
	names, err := fs.Glob(fsys, sourcesGlob)
	if err != nil {
		return nil, err
	}
	var sources []Source
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var s Source
		if err := yaml.UnmarshalStrict(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		sources = append(sources, s)
	}
	return newIndex(sources)
}

func newIndex(sources []Source) (*index, error) {
	ix := &index{sources: sources, byID: map[string]position{}}
	seen := map[string]bool{}
	var errs []error
	for si, s := range sources {
		switch {
		case s.ID == "":
			errs = append(errs, fmt.Errorf("source %d: empty id", si))
		case seen[s.ID]:
			errs = append(errs, fmt.Errorf("duplicate source id %q", s.ID))
		case s.Short == "":
			errs = append(errs, fmt.Errorf("source %q: empty short", s.ID))
		}
		seen[s.ID] = true
		for ei, e := range s.Excerpts {
			switch {
			case e.ID == "":
				errs = append(errs, fmt.Errorf("source %q: excerpt %d: empty id", s.ID, ei))
				continue
			case e.Article == "":
				errs = append(errs, fmt.Errorf("source %q: excerpt %q: empty article", s.ID, e.ID))
			case strings.TrimSpace(e.Text) == "":
				errs = append(errs, fmt.Errorf("source %q: excerpt %q: empty text", s.ID, e.ID))
			}
			if _, dup := ix.byID[e.ID]; dup {
				errs = append(errs, fmt.Errorf("duplicate excerpt id %q", e.ID))
				continue
			}
			ix.byID[e.ID] = position{source: si, excerpt: ei}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return ix, nil
}

func (ix *index) has(id string) bool {
	_, ok := ix.byID[id]
	return ok
}

func (ix *index) lookup(id string) (Excerpt, Source, bool) {
	pos, ok := ix.byID[id]
	if !ok {
		return Excerpt{}, Source{}, false
	}
	s := ix.sources[pos.source]
	return s.Excerpts[pos.excerpt], cloneSource(s), true
}

func (ix *index) label(id string) string {
	e, s, ok := ix.lookup(id)
	if !ok {
		return id
	}
	return label(s, e)
}

func (ix *index) copySources() []Source {
	out := make([]Source, len(ix.sources))
	for i, s := range ix.sources {
		out[i] = cloneSource(s)
	}
	return out
}

func cloneSource(s Source) Source {
	s.Excerpts = slices.Clone(s.Excerpts)
	return s
}

func label(s Source, e Excerpt) string {
	var b strings.Builder
	b.WriteString(s.Short)
	b.WriteString(" Art. ")
	b.WriteString(e.Article)
	if e.Paragraph != "" {
		b.WriteString("(" + e.Paragraph + ")")
	}
	if e.Point != "" {
		b.WriteString("(" + e.Point + ")")
	}
	return b.String()
}
