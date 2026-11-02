package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
	"github.com/sv222/kshield/internal/report"
)

const (
	checksUsage = `usage:
  kshield checks list [--profile dora] [--format text|json]
  kshield checks explain <check-id|display-id> [--profile dora]
`
	profilesUsage = `usage: kshield profiles list [--format text|json]
`
	noValue = "-"
)

type checkRow struct {
	ID       string   `json:"id"`
	Display  string   `json:"display"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Tier     string   `json:"tier"`
	Fix      string   `json:"fix"`
	Refs     []string `json:"refs"`
}

type profileRow struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Checks  int    `json:"checks"`
	SHA256  string `json:"sha256"`
	Title   string `json:"title"`
}

func runChecks(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		write(stderr, "kshield: checks: missing subcommand (list or explain)\n\n"+checksUsage)
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return checksList(args[1:], stdout, stderr)
	case "explain":
		return checksExplain(args[1:], stdout, stderr)
	}
	write(stderr, fmt.Sprintf("kshield: checks: unknown subcommand %q\n\n%s", args[0], checksUsage))
	return ExitUsage
}

func runProfiles(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		write(stderr, "kshield: profiles: missing subcommand (list)\n\n"+profilesUsage)
		return ExitUsage
	}
	if args[0] != "list" {
		write(stderr, fmt.Sprintf("kshield: profiles: unknown subcommand %q\n\n%s", args[0], profilesUsage))
		return ExitUsage
	}
	return profilesList(args[1:], stdout, stderr)
}

func newFlagSet(name, usageText string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { write(stderr, usageText) }
	return fs
}

func parseArgs(fs *flag.FlagSet, args []string) ([]string, int, bool) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, ExitOK, false
			}
			return nil, ExitUsage, false
		}
		if fs.NArg() == 0 {
			return positional, 0, true
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func checksList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("checks list", checksUsage, stderr)
	profileID := fs.String("profile", defaultProfile, "profile id")
	format := fs.String("format", formatText, "text or json")
	positional, code, ok := parseArgs(fs, args)
	switch {
	case !ok:
		return code
	case len(positional) > 0:
		return usageError(stderr, "unexpected argument %q", positional[0])
	case *format != formatText && *format != formatJSON:
		return usageError(stderr, "unknown format %q (text or json)", *format)
	}
	p, err := profile.Load(*profileID)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	rows := checkRows(p)
	var buf bytes.Buffer
	if *format == formatJSON {
		err = writeJSONRows(&buf, rows)
	} else {
		err = writeTable(&buf, "DISPLAY\tCHECK\tSEVERITY\tTIER\tFIX\tTITLE", len(rows), func(i int) string {
			r := rows[i]
			return strings.Join([]string{r.Display, r.ID, r.Severity, r.Tier, r.Fix, r.Title}, "\t")
		})
	}
	return flush(stdout, stderr, &buf, err)
}

func checksExplain(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("checks explain", checksUsage, stderr)
	profileID := fs.String("profile", defaultProfile, "profile id")
	positional, code, ok := parseArgs(fs, args)
	switch {
	case !ok:
		return code
	case len(positional) == 0:
		return usageError(stderr, "checks explain: missing check ID or display ID")
	case len(positional) > 1:
		return usageError(stderr, "unexpected argument %q", positional[1])
	}
	p, err := profile.Load(*profileID)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	c, ok := findCheck(p, positional[0])
	if !ok {
		return usageError(stderr, "unknown check %q in profile %s (see kshield checks list)", positional[0], p.ID)
	}
	var buf bytes.Buffer
	err = writeExplain(&buf, p, c)
	return flush(stdout, stderr, &buf, err)
}

func profilesList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("profiles list", profilesUsage, stderr)
	format := fs.String("format", formatText, "text or json")
	positional, code, ok := parseArgs(fs, args)
	switch {
	case !ok:
		return code
	case len(positional) > 0:
		return usageError(stderr, "unexpected argument %q", positional[0])
	case *format != formatText && *format != formatJSON:
		return usageError(stderr, "unknown format %q (text or json)", *format)
	}
	rows := []profileRow{}
	for _, id := range profile.IDs() {
		p, err := profile.Load(id)
		if err != nil {
			return usageError(stderr, "%v", err)
		}
		rows = append(rows, profileRow{ID: p.ID, Version: p.Version, Checks: len(p.Checks), SHA256: p.SHA256, Title: p.Title})
	}
	var buf bytes.Buffer
	var err error
	if *format == formatJSON {
		err = writeJSONRows(&buf, rows)
	} else {
		err = writeTable(&buf, "ID\tVERSION\tCHECKS\tSHA256\tTITLE", len(rows), func(i int) string {
			r := rows[i]
			return fmt.Sprintf("%s\t%d\t%d\t%s\t%s", r.ID, r.Version, r.Checks, r.SHA256, r.Title)
		})
	}
	return flush(stdout, stderr, &buf, err)
}

func checkRows(p *profile.Profile) []checkRow {
	all := check.All()
	rows := make([]checkRow, 0, len(all))
	for _, c := range all {
		row := checkRow{ID: c.ID, Display: noValue, Title: c.Title, Severity: noValue, Tier: tierText(c.Tier), Fix: string(c.Fix), Refs: []string{}}
		if e, ok := p.Checks[c.ID]; ok {
			row.Display = e.Display
			row.Severity = string(e.Severity)
			row.Refs = append(row.Refs, e.Refs...)
		}
		rows = append(rows, row)
	}
	return rows
}

func findCheck(p *profile.Profile, id string) (check.Check, bool) {
	for _, c := range check.All() {
		if strings.EqualFold(c.ID, id) {
			return c, true
		}
		if e, ok := p.Checks[c.ID]; ok && e.Display != "" && strings.EqualFold(e.Display, id) {
			return c, true
		}
	}
	return check.Check{}, false
}

func writeExplain(w *bytes.Buffer, p *profile.Profile, c check.Check) error {
	e, inProfile := p.Checks[c.ID]
	display, severity := noValue, noValue
	if inProfile {
		display, severity = e.Display, string(e.Severity)
	}
	fmt.Fprintf(w, "%s (%s)\n", c.ID, display)
	fmt.Fprintf(w, "%-10s%s\n", "Title:", c.Title)
	fmt.Fprintf(w, "%-10s%s\n", "Tier:", tierText(c.Tier))
	fmt.Fprintf(w, "%-10s%s\n", "Fix:", c.Fix)
	fmt.Fprintf(w, "%-10s%s\n", "Severity:", severity)
	fmt.Fprintf(w, "%-10s%s v%d\n", "Profile:", p.ID, p.Version)
	fmt.Fprintf(w, "\n%s\n", report.Disclaimer)
	if len(e.Refs) == 0 {
		w.WriteString("\nReferences: none in this profile\n")
		return nil
	}
	w.WriteString("\nReferences:\n")
	for _, ref := range e.Refs {
		ex, src, ok := regtext.Lookup(ref)
		if !ok {
			return fmt.Errorf("check %s cites unknown ref %q", c.ID, ref)
		}
		fmt.Fprintf(w, "\n%s\n", regtext.Label(ref))
		fmt.Fprintf(w, "Source: %s, CELEX %s\n", src.Short, src.CELEX)
		fmt.Fprintf(w, "URL: %s\n", src.URL)
		for _, line := range strings.Split(strings.TrimSpace(ex.Text), "\n") {
			if line = strings.TrimRight(line, " \t"); line == "" {
				w.WriteString("\n")
				continue
			}
			w.WriteString("  " + line + "\n")
		}
	}
	return nil
}

func tierText(t check.Tier) string {
	switch t {
	case check.Manifest:
		return "manifest"
	case check.Cluster:
		return "cluster"
	case check.Both:
		return "manifest+cluster"
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

func writeTable(w io.Writer, header string, n int, row func(int) string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, header); err != nil {
		return err
	}
	for i := range n {
		if _, err := fmt.Fprintln(tw, row(i)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeJSONRows(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func flush(stdout, stderr io.Writer, buf *bytes.Buffer, err error) int {
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		return usageError(stderr, "%v", err)
	}
	return ExitOK
}
