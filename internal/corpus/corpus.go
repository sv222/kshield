package corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/report"
)

const (
	ExpectedFile = "expected.yaml"
	InputFile    = "input.yaml"
	RenderedFile = "rendered.yaml"
	ResidualFile = "rescan.yaml"

	ModeAudit   = "audit"
	ModeEnforce = "enforce"
	ModeBoth    = "both"

	allChecks = "all"
)

type Expect struct {
	Check     string `json:"check"`
	Object    string `json:"object"`
	Group     string `json:"group,omitempty"`
	Container string `json:"container,omitempty"`
	Verdict   string `json:"verdict"`
}

func (e Expect) String() string {
	var b strings.Builder
	b.WriteString("{check: " + e.Check + ", object: " + e.Object)
	if e.Group != "" {
		b.WriteString(", group: " + e.Group)
	}
	if e.Container != "" {
		b.WriteString(", container: " + e.Container)
	}
	b.WriteString(", verdict: " + e.Verdict + "}")
	return b.String()
}

type Spec struct {
	Namespace string
	Checks    []string
	Expect    []Expect
	NA        []string
}

func (s *Spec) UnmarshalJSON(b []byte) error {
	var raw struct {
		Namespace string          `json:"namespace"`
		Checks    json.RawMessage `json:"checks"`
		Expect    []Expect        `json:"expect"`
		NA        []string        `json:"na"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	checks, err := parseChecks(raw.Checks)
	if err != nil {
		return err
	}
	for i, e := range raw.Expect {
		if err := validateExpect(e); err != nil {
			return fmt.Errorf("expect[%d]: %w", i, err)
		}
	}
	*s = Spec{Namespace: raw.Namespace, Checks: checks, Expect: raw.Expect, NA: raw.NA}
	return nil
}

func parseChecks(raw json.RawMessage) ([]string, error) {
	const hint = "checks must be a non-empty list of check IDs, or the word all"
	if len(raw) == 0 {
		return nil, errors.New("missing checks: " + hint)
	}
	var word string
	if json.Unmarshal(raw, &word) == nil {
		if word != allChecks {
			return nil, fmt.Errorf("checks %q: %s", word, hint)
		}
		return nil, nil
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil || len(ids) == 0 {
		return nil, errors.New(hint)
	}
	return ids, nil
}

func validateExpect(e Expect) error {
	switch {
	case e.Check == "":
		return errors.New("missing check")
	case e.Object == "":
		return errors.New("missing object")
	}
	switch e.Verdict {
	case report.VerdictFail, report.VerdictUnknown, report.VerdictWarn, report.VerdictInfo:
		return nil
	}
	return fmt.Errorf("verdict %q is not FAIL, UNKNOWN, WARN or INFO", e.Verdict)
}

func LoadSpec(path string) (Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var s Spec
	if err := yaml.UnmarshalStrict(b, &s); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

type Residual struct {
	Check     string `json:"check"`
	Object    string `json:"object"`
	Container string `json:"container,omitempty"`
	Mode      string `json:"mode"`
}

func (r Residual) In(mode string) bool {
	return r.Mode == ModeBoth || r.Mode == mode
}

func validateResidual(r Residual) error {
	switch {
	case r.Check == "":
		return errors.New("missing check")
	case r.Object == "":
		return errors.New("missing object")
	}
	switch r.Mode {
	case ModeAudit, ModeEnforce, ModeBoth:
		return nil
	}
	return fmt.Errorf("mode %q is not audit, enforce or both", r.Mode)
}

func LoadResiduals(dir string) ([]Residual, error) {
	path := filepath.Join(dir, ResidualFile)
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	var raw struct {
		Residuals []Residual `json:"residuals"`
	}
	if err := yaml.UnmarshalStrict(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, r := range raw.Residuals {
		if err := validateResidual(r); err != nil {
			return nil, fmt.Errorf("%s: residuals[%d]: %w", path, i, err)
		}
	}
	return raw.Residuals, nil
}

func Actual(r *report.Report, checks []string) []Expect {
	var out []Expect
	for _, c := range r.Checks {
		if len(checks) > 0 && !slices.Contains(checks, c.ID) {
			continue
		}
		for _, f := range c.Findings {
			out = append(out, Expect{
				Check:     c.ID,
				Object:    f.Object.String(),
				Group:     f.Group,
				Container: f.Container,
				Verdict:   f.Verdict,
			})
		}
	}
	return out
}

func Diff(want, got []Expect) (missing, extra []Expect) {
	return subtract(want, got), subtract(got, want)
}

func subtract(a, b []Expect) []Expect {
	left := make(map[Expect]int, len(b))
	for _, e := range b {
		left[e]++
	}
	var out []Expect
	for _, e := range a {
		if left[e] > 0 {
			left[e]--
			continue
		}
		out = append(out, e)
	}
	return out
}

func UnknownChecks(r *report.Report, ids []string) []string {
	var out []string
	for _, id := range ids {
		if !slices.ContainsFunc(r.Checks, func(c report.CheckResult) bool { return c.ID == id }) {
			out = append(out, id)
		}
	}
	return out
}

func NAMismatches(r *report.Report, ids []string) []string {
	var out []string
	for _, id := range ids {
		i := slices.IndexFunc(r.Checks, func(c report.CheckResult) bool { return c.ID == id })
		switch {
		case i < 0:
			out = append(out, fmt.Sprintf("%s: want N/A, but the check is not in the report", id))
		case r.Checks[i].Verdict != report.VerdictNA:
			out = append(out, fmt.Sprintf("%s: want N/A, got %s", id, r.Checks[i].Verdict))
		}
	}
	return out
}

func Cases(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		info, err := os.Stat(filepath.Join(path, ExpectedFile))
		switch {
		case err == nil && info.Mode().IsRegular():
			dirs = append(dirs, path)
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dirs, nil
}

func InputPath(dir string) (string, error) {
	input := filepath.Join(dir, InputFile)
	rendered := filepath.Join(dir, RenderedFile)
	hasInput, err := exists(input)
	if err != nil {
		return "", err
	}
	hasRendered, err := exists(rendered)
	if err != nil {
		return "", err
	}
	switch {
	case hasInput && hasRendered:
		return "", fmt.Errorf("case %s: has both %s and %s, keep one", dir, InputFile, RenderedFile)
	case hasInput:
		return input, nil
	case hasRendered:
		return rendered, nil
	}
	return "", fmt.Errorf("case %s: %s has no %s or %s next to it", dir, ExpectedFile, InputFile, RenderedFile)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}
