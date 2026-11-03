package report

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"

	"github.com/sv222/kshield/internal/load"
)

type objectJSON struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type findingJSON struct {
	Object    objectJSON `json:"object"`
	Source    *Source    `json:"source,omitempty"`
	Group     string     `json:"group,omitempty"`
	Container string     `json:"container,omitempty"`
	Path      string     `json:"path"`
	Message   string     `json:"message"`
	Verdict   string     `json:"verdict"`
}

func (f Finding) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(findingJSON{
		Object: objectJSON{
			APIVersion: f.Object.APIVersion,
			Kind:       f.Object.Kind,
			Namespace:  f.Object.Namespace,
			Name:       f.Object.Name,
		},
		Source:    f.Source,
		Group:     f.Group,
		Container: f.Container,
		Path:      f.Path,
		Message:   f.Message,
		Verdict:   f.Verdict,
	})
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (f *Finding) UnmarshalJSON(b []byte) error {
	var w findingJSON
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*f = Finding{
		Object: load.ObjectRef{
			APIVersion: w.Object.APIVersion,
			Kind:       w.Object.Kind,
			Namespace:  w.Object.Namespace,
			Name:       w.Object.Name,
		},
		Source:    w.Source,
		Group:     w.Group,
		Container: w.Container,
		Path:      w.Path,
		Message:   w.Message,
		Verdict:   w.Verdict,
	}
	return nil
}

func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(withEmptySlices(r))
}

func withEmptySlices(r *Report) *Report {
	out := *r
	if out.Scan.Inputs == nil {
		out.Scan.Inputs = []string{}
	}
	if out.Scan.InputDigests == nil {
		out.Scan.InputDigests = []load.Digest{}
	}
	if r.Scan.Cluster != nil && r.Scan.Cluster.Namespaces == nil {
		c := *r.Scan.Cluster
		c.Namespaces = []string{}
		out.Scan.Cluster = &c
	}
	if out.Errors == nil {
		out.Errors = []string{}
	}
	out.Checks = slices.Clone(r.Checks)
	if out.Checks == nil {
		out.Checks = []CheckResult{}
	}
	for i := range out.Checks {
		if out.Checks[i].Refs == nil {
			out.Checks[i].Refs = []Ref{}
		}
		if out.Checks[i].Findings == nil {
			out.Checks[i].Findings = []Finding{}
		}
	}
	return &out
}
