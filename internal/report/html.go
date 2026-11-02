package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/sv222/kshield/internal/htmlcheck"
	"github.com/sv222/kshield/internal/regtext"
)

//go:embed html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("html").Parse(htmlSource))

type htmlPage struct {
	Title      string
	Disclaimer string
	CSP        template.HTML
	R          *Report
	Inputs     []string
	Digests    []htmlDigest
	Namespace  string
	Cluster    *htmlCluster
	HasUnknown bool
	Note       string
	Checks     []htmlCheck
	Details    []htmlCheck
}

type htmlCluster struct {
	Context    string
	Server     string
	Namespaces string
	NodeProbe  string
}

type htmlDigest struct {
	Path   string
	SHA256 string
}

type htmlCheck struct {
	ID       string
	Display  string
	Title    string
	Severity string
	Verdict  string
	Class    string
	FixLabel string
	Anchor   string
	Refs     []htmlRef
	Findings []htmlFinding
}

type htmlRef struct {
	Label string
	Short string
	CELEX string
	URL   string
	Text  string
}

type htmlFinding struct {
	Verdict   string
	Class     string
	Object    string
	Group     string
	Container string
	Path      string
	Message   string
	Source    string
}

func WriteHTML(w io.Writer, r *Report) error {
	page, err := buildHTMLPage(r)
	if err != nil {
		return err
	}
	var b strings.Builder
	if err := htmlTemplate.Execute(&b, page); err != nil {
		return err
	}
	_, err = io.WriteString(w, b.String())
	return err
}

func buildHTMLPage(r *Report) (*htmlPage, error) {
	r = forDisplay(r)
	p := &htmlPage{
		Title:      r.Profile.Title,
		Disclaimer: Disclaimer,
		CSP:        template.HTML(htmlcheck.CSPMeta),
		R:          r,
		Namespace:  r.Scan.Namespace,
	}
	if p.Title == "" {
		p.Title = r.Profile.ID
	}
	if p.Namespace == "" {
		p.Namespace = "(not set)"
	}
	if noAIWorkloads(r) {
		p.Note = noAIWorkloadsNote
	}
	if c := r.Scan.Cluster; c != nil {
		p.Cluster = &htmlCluster{Context: c.Context, Server: c.Server, Namespaces: namespacesLabel(c), NodeProbe: nodeProbeLabel(c)}
	}
	p.HasUnknown = r.Summary.Unknown > 0
	for _, in := range r.Scan.Inputs {
		p.Inputs = append(p.Inputs, inputLabel(in))
	}
	for _, d := range r.Scan.InputDigests {
		p.Digests = append(p.Digests, htmlDigest{Path: inputLabel(d.Path), SHA256: d.SHA256})
	}
	for _, c := range r.Checks {
		hc := htmlCheck{
			ID:       c.ID,
			Display:  c.Display,
			Title:    c.Title,
			Severity: c.Severity,
			Verdict:  c.Verdict,
			Class:    verdictClass(c.Verdict),
			FixLabel: fixLabel(c),
			Anchor:   strings.ToLower(c.ID),
		}
		if c.Verdict == VerdictUnknown {
			p.HasUnknown = true
		}
		if len(c.Findings) > 0 {
			for _, ref := range c.Refs {
				ex, src, ok := regtext.Lookup(ref.ID)
				if !ok {
					return nil, fmt.Errorf("report: check %s: unknown ref %q", c.ID, ref.ID)
				}
				hc.Refs = append(hc.Refs, htmlRef{Label: ref.Label, Short: src.Short, CELEX: src.CELEX, URL: src.URL, Text: ex.Text})
			}
			for _, f := range c.Findings {
				hc.Findings = append(hc.Findings, htmlFindingOf(f))
				if f.Verdict == VerdictUnknown {
					p.HasUnknown = true
				}
			}
			p.Details = append(p.Details, hc)
		}
		p.Checks = append(p.Checks, hc)
	}
	return p, nil
}

func htmlFindingOf(f Finding) htmlFinding {
	hf := htmlFinding{
		Verdict:   f.Verdict,
		Class:     verdictClass(f.Verdict),
		Object:    f.Object.String(),
		Group:     f.Group,
		Container: f.Container,
		Path:      f.Path,
		Message:   f.Message,
	}
	if f.Source != nil {
		hf.Source = fmt.Sprintf("%s:%d", inputLabel(f.Source.File), f.Source.Line)
	}
	return hf
}

func inputLabel(path string) string {
	if path == "-" {
		return "- (stdin)"
	}
	return path
}

func verdictClass(v string) string {
	switch v {
	case VerdictFail:
		return "v-fail"
	case VerdictWarn:
		return "v-warn"
	case VerdictPass:
		return "v-pass"
	case VerdictInfo:
		return "v-info"
	case VerdictNA:
		return "v-na"
	case VerdictUnknown:
		return "v-unknown"
	}
	return "v-other"
}
