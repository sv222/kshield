package profile

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	profilesDir = "profiles"
	fileExt     = ".yaml"
)

//go:embed profiles/*.yaml
var profilesFS embed.FS

type Severity string

const (
	SevFail Severity = "fail"
	SevWarn Severity = "warn"
	SevInfo Severity = "info"
)

type Entry struct {
	Display  string   `json:"display"`
	Severity Severity `json:"severity"`
	Refs     []string `json:"refs"`
}

type Profile struct {
	ID      string           `json:"id"`
	Version int              `json:"version"`
	Title   string           `json:"title"`
	Checks  map[string]Entry `json:"checks"`
	SHA256  string           `json:"-"`
}

func Parse(b []byte) (*Profile, error) {
	var p Profile
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	p.SHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

func Load(id string) (*Profile, error) {
	ids := IDs()
	if !slices.Contains(ids, id) {
		return nil, fmt.Errorf("unknown profile %q (available: %s)", id, strings.Join(ids, ", "))
	}
	b, err := profilesFS.ReadFile(profilesDir + "/" + id + fileExt)
	if err != nil {
		return nil, err
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", id, err)
	}
	if p.ID != id {
		return nil, fmt.Errorf("profile %s: id field is %q", id, p.ID)
	}
	return p, nil
}

func IDs() []string {
	entries, err := profilesFS.ReadDir(profilesDir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), fileExt); ok && !e.IsDir() {
			ids = append(ids, name)
		}
	}
	slices.Sort(ids)
	return ids
}

func (p *Profile) Validate(checkIDs []string, hasRef func(string) bool) error {
	var errs []error
	known := make(map[string]bool, len(checkIDs))
	for _, id := range checkIDs {
		if known[id] {
			continue
		}
		known[id] = true
		if _, ok := p.Checks[id]; !ok {
			errs = append(errs, fmt.Errorf("%s: registered check has no profile entry", id))
		}
	}
	ids := make([]string, 0, len(p.Checks))
	for id := range p.Checks {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	displayOwner := make(map[string]string, len(ids))
	for _, id := range ids {
		e := p.Checks[id]
		if !known[id] {
			errs = append(errs, fmt.Errorf("%s: profile entry for unknown check", id))
		}
		if e.Display == "" {
			errs = append(errs, fmt.Errorf("%s: empty display", id))
		} else if owner, dup := displayOwner[e.Display]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate display %q (also %s)", id, e.Display, owner))
		} else {
			displayOwner[e.Display] = id
		}
		switch e.Severity {
		case SevFail, SevWarn, SevInfo:
		default:
			errs = append(errs, fmt.Errorf("%s: severity %q is not fail, warn or info", id, e.Severity))
		}
		if len(e.Refs) == 0 {
			errs = append(errs, fmt.Errorf("%s: empty refs", id))
		}
		for _, ref := range e.Refs {
			if !hasRef(ref) {
				errs = append(errs, fmt.Errorf("%s: unknown ref %q", id, ref))
			}
		}
	}
	return errors.Join(errs...)
}
