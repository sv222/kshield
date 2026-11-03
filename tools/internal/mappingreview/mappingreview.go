package mappingreview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
)

const (
	Marker      = "<!-- kshield:signoff - everything below is kept by the generator -->"
	TableHeader = "| Date | Name | Profile sha256 | Review sha256 | Decision |"

	signOffHeading = "## Sign-off"
	tableSeparator = "|---|---|---|---|---|"
	signOffCells   = 5
	defaultTail    = "\n\n" + signOffHeading + "\n\n" + TableHeader + "\n" + tableSeparator + "\n"
	dateLayout     = "2006-01-02"
	decisionYes    = "approved"
	decisionNo     = "rejected"
)

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type SignOff struct {
	Line          int
	Date          string
	Name          string
	ProfileSHA256 string
	ReviewSHA256  string
	Decision      string
}

func Render(p *profile.Profile) (string, error) {
	catalog := check.All()
	ids := make([]string, 0, len(catalog))
	for _, c := range catalog {
		ids = append(ids, c.ID)
	}
	if err := p.Validate(ids, regtext.Has); err != nil {
		return "", fmt.Errorf("profile %s: %w", p.ID, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Mapping review - %s\n\n", p.Title)
	fmt.Fprintf(&b, "- Profile: `%s`\n", p.ID)
	fmt.Fprintf(&b, "- Version: %d\n", p.Version)
	fmt.Fprintf(&b, "- Profile sha256: `%s`\n", p.SHA256)
	fmt.Fprintf(&b, "- Checks: %d\n\n", len(catalog))
	b.WriteString("This file lists each check of the profile in catalog order, with the regulation text that the check is mapped to. ")
	b.WriteString("A mapping means that the check supports evidence for the cited requirement. ")
	b.WriteString("It is not an audit and does not state compliance with any regulation.\n\n")
	b.WriteString("The quotes are verbatim excerpts from `internal/regtext/sources`. ")
	b.WriteString("`go run ./tools/mappingreview` writes everything above the sign-off marker. Do not edit that part by hand. ")
	b.WriteString("The generator keeps everything from the marker line down as it is.\n\n")
	b.WriteString("To sign off, read every mapping and add one row to the table under Sign-off: ")
	b.WriteString("the date (YYYY-MM-DD), your name, the profile sha256 above, and the decision `approved` or `rejected`. ")
	b.WriteString("The row also carries the review sha256 that `go run ./tools/mappingreview` prints. ")
	b.WriteString("A change to the profile file changes its sha256, so it needs a new sign-off.\n\n")
	for _, c := range catalog {
		e := p.Checks[c.ID]
		fmt.Fprintf(&b, "## %s (%s)\n\n", e.Display, c.ID)
		fmt.Fprintf(&b, "- Check: `%s`\n", c.ID)
		fmt.Fprintf(&b, "- Display ID: `%s`\n", e.Display)
		fmt.Fprintf(&b, "- Title: %s\n", c.Title)
		fmt.Fprintf(&b, "- Severity: %s\n\n", e.Severity)
		for _, ref := range e.Refs {
			ex, src, ok := regtext.Lookup(ref)
			if !ok {
				return "", fmt.Errorf("%s: ref %q has no regtext excerpt", c.ID, ref)
			}
			fmt.Fprintf(&b, "### %s\n\n", regtext.Label(ref))
			fmt.Fprintf(&b, "- Ref: `%s`\n", ref)
			fmt.Fprintf(&b, "- Source: %s\n", src.Title)
			fmt.Fprintf(&b, "- CELEX: %s\n", src.CELEX)
			fmt.Fprintf(&b, "- URL: <%s>\n\n", src.URL)
			b.WriteString(quote(ex.Text))
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

func quote(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			b.WriteString(">\n")
			continue
		}
		b.WriteString("> " + line + "\n")
	}
	return b.String()
}

func Update(path, head string) error {
	if _, _, ok := Split(head); ok {
		return errors.New("generated part contains the marker line")
	}
	tail := Marker + defaultTail
	old, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		_, kept, ok := Split(string(old))
		if !ok {
			return fmt.Errorf("%s exists but has no marker line %q; add it above the sign-off part or move the file away", path, Marker)
		}
		tail = kept
	}
	return os.WriteFile(path, []byte(head+tail), 0o644)
}

func Split(s string) (head, tail string, ok bool) {
	for off := 0; ; {
		end := strings.IndexByte(s[off:], '\n')
		line := s[off:]
		if end >= 0 {
			line = s[off : off+end]
		}
		if strings.TrimSuffix(line, "\r") == Marker {
			return s[:off], s[off:], true
		}
		if end < 0 {
			return "", "", false
		}
		off += end + 1
	}
}

func ReviewSHA256(head string) string {
	sum := sha256.Sum256([]byte(head))
	return hex.EncodeToString(sum[:])
}

func ParseSignOff(tail string) ([]SignOff, error) {
	lines := strings.Split(tail, "\n")
	heading := -1
	for i, l := range lines {
		if strings.TrimSpace(l) != signOffHeading {
			continue
		}
		if heading >= 0 {
			return nil, fmt.Errorf("line %d: second %q heading", i+1, signOffHeading)
		}
		heading = i
	}
	if heading < 0 {
		return nil, fmt.Errorf("no %q heading below the marker", signOffHeading)
	}
	i := heading + 1
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}
	if i >= len(lines) || strings.TrimSpace(lines[i]) != TableHeader {
		return nil, fmt.Errorf("line %d: sign-off table header is not %q", min(i, len(lines)-1)+1, TableHeader)
	}
	i++
	if i >= len(lines) || strings.TrimSpace(lines[i]) != tableSeparator {
		return nil, fmt.Errorf("line %d: sign-off table separator is not %q", min(i, len(lines)-1)+1, tableSeparator)
	}
	var rows []SignOff
	for i++; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, "|") {
			continue
		}
		row, err := parseRow(l)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		row.Line = i + 1
		rows = append(rows, row)
	}
	return rows, nil
}

func parseRow(l string) (SignOff, error) {
	if len(l) < 2 || !strings.HasSuffix(l, "|") {
		return SignOff{}, errors.New("row does not end with |")
	}
	cells := strings.Split(l[1:len(l)-1], "|")
	if len(cells) != signOffCells {
		return SignOff{}, fmt.Errorf("row has %d cells, want %d", len(cells), signOffCells)
	}
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	r := SignOff{Date: cells[0], Name: cells[1], ProfileSHA256: cells[2], ReviewSHA256: cells[3], Decision: cells[4]}
	if d, err := time.Parse(dateLayout, r.Date); err != nil || d.Format(dateLayout) != r.Date {
		return SignOff{}, fmt.Errorf("date %q is not a real YYYY-MM-DD date", r.Date)
	}
	if r.Name == "" {
		return SignOff{}, errors.New("name is empty")
	}
	if !hashRe.MatchString(r.ProfileSHA256) {
		return SignOff{}, fmt.Errorf("profile sha256 %q is not 64 lowercase hex characters", r.ProfileSHA256)
	}
	if !hashRe.MatchString(r.ReviewSHA256) {
		return SignOff{}, fmt.Errorf("review sha256 %q is not 64 lowercase hex characters", r.ReviewSHA256)
	}
	if r.Decision != decisionYes && r.Decision != decisionNo {
		return SignOff{}, fmt.Errorf("decision %q is not %q or %q", r.Decision, decisionYes, decisionNo)
	}
	return r, nil
}
