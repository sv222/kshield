package test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/scan"
)

func TestQdrantAPIKeyChartOnlyFailsTLS(t *testing.T) {
	r, err := scan.Manifest(scan.Options{
		Inputs:        []string{filepath.Join(corpusRoot, "charts", "qdrant", "apikey", corpus.RenderedFile)},
		Namespace:     "ai-inference",
		ProfileID:     profileID,
		Deterministic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, c := range r.Checks {
		if c.ID != "KS-AI-008" {
			continue
		}
		for _, f := range c.Findings {
			msgs = append(msgs, f.Message)
		}
	}
	if len(msgs) != 1 {
		t.Fatalf("want exactly one KS-AI-008 finding, got %q", msgs)
	}
	if !strings.Contains(msgs[0], "TLS") || strings.Contains(strings.ToLower(msgs[0]), "api key") {
		t.Fatalf("want the TLS finding, not the API key one: %q", msgs[0])
	}
}
