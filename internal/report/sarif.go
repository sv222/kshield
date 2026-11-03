package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

const (
	sarifVersion     = "2.1.0"
	sarifSchema      = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifFingerprint = "kshield/v1"

	LivePodPrefix = "live pod "
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

var sarifLevels = map[string]string{
	VerdictFail: "error",
	VerdictWarn: "warning",
	VerdictInfo: "note",
}

func WriteSARIF(w io.Writer, r *Report) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:    "kshield",
			Version: r.Tool.Version,
			Rules:   make([]sarifRule, 0, len(r.Checks)),
		}},
		Invocations: []sarifInvocation{sarifInvocationOf(r)},
		Results:     []sarifResult{},
	}
	for i, c := range r.Checks {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               c.ID,
			Name:             c.Display,
			ShortDescription: sarifText{Text: c.Title},
			Properties:       sarifRuleProps{Tags: []string{c.Fix, c.Severity}},
		})
		if _, ok := sarifLevels[c.Verdict]; !ok && c.Verdict != VerdictUnknown {
			continue
		}
		for _, f := range c.Findings {
			level, ok := sarifLevels[f.Verdict]
			if !ok {
				continue
			}
			run.Results = append(run.Results, sarifFinding(c.ID, i, level, f))
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}})
}

func sarifInvocationOf(r *Report) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: !r.Summary.Incomplete}
	for _, e := range r.Errors {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{Level: "error", Message: sarifText{Text: e}})
	}
	return inv
}

func sarifFinding(checkID string, index int, level string, f Finding) sarifResult {
	obj := f.Object.String()
	loc := sarifLocation{LogicalLocations: []sarifLogical{{FullyQualifiedName: obj}}}
	if f.Source != nil {
		loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: sarifArtifact{URI: sarifURI(f.Source.File)}}
		if f.Source.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Source.Line}
		}
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{checkID, obj, f.Group, f.Container, f.Path, stableMessage(f.Message)}, "|")))
	return sarifResult{
		RuleID:              checkID,
		RuleIndex:           index,
		Level:               level,
		Message:             sarifText{Text: f.Message + " (" + obj + ")"},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{sarifFingerprint: hex.EncodeToString(sum[:])},
	}
}

func stableMessage(msg string) string {
	rest, ok := strings.CutPrefix(msg, LivePodPrefix)
	if !ok {
		return msg
	}
	if _, tail, found := strings.Cut(rest, ": "); found {
		return tail
	}
	return msg
}

func sarifURI(file string) string {
	if file == "-" {
		return "stdin"
	}
	return (&url.URL{Path: file}).String()
}
