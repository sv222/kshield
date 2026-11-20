package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSHA = "21ff65dc97b806b1107b54f3c342b89e7d377b26"

func TestLoadChartSources(t *testing.T) {
	cases := []struct {
		name  string
		chart string
		err   string
	}{
		{"repo chart", `{name: a, namespace: ns, repo: "https://r.example.com", chart: c, version: "1", variants: [{name: v, values: v.yaml}]}`, ""},
		{"git chart", `{name: a, namespace: ns, git: "https://github.com/x/y.git", ref: ` + goodSHA + `, path: deploy/gcp, variants: [{name: v, values: v.yaml}]}`, ""},
		{"neither", `{name: a, namespace: ns, variants: [{name: v, values: v.yaml}]}`, "either repo, chart and version, or git, ref and path"},
		{"both", `{name: a, namespace: ns, repo: "https://r.example.com", chart: c, version: "1", git: "https://github.com/x/y.git", ref: ` + goodSHA + `, path: p, variants: [{name: v, values: v.yaml}]}`, "either repo, chart and version, or git, ref and path"},
		{"repo without version", `{name: a, namespace: ns, repo: "https://r.example.com", chart: c, variants: [{name: v, values: v.yaml}]}`, "repo, chart and version are required"},
		{"git with a branch", `{name: a, namespace: ns, git: "https://github.com/x/y.git", ref: main, path: p, variants: [{name: v, values: v.yaml}]}`, "full commit sha"},
		{"git over http", `{name: a, namespace: ns, git: "http://github.com/x/y.git", ref: ` + goodSHA + `, path: p, variants: [{name: v, values: v.yaml}]}`, "https URL"},
		{"git path escapes", `{name: a, namespace: ns, git: "https://github.com/x/y.git", ref: ` + goodSHA + `, path: ../p, variants: [{name: v, values: v.yaml}]}`, "relative path"},
		{"no variants", `{name: a, namespace: ns, repo: "https://r.example.com", chart: c, version: "1"}`, "variants are required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "charts.yaml")
			if err := os.WriteFile(path, []byte("charts:\n  - "+c.chart+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := load(path)
			switch {
			case c.err == "" && err != nil:
				t.Fatal(err)
			case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
				t.Fatalf("err = %v, want %q", err, c.err)
			}
		})
	}
}
