package report

import "github.com/sv222/kshield/internal/load"

const (
	SchemaVersion = "kshield.report/v1"
	ModeManifest  = "manifest"
	ModeCluster   = "cluster"
)

const Disclaimer = "This report supports evidence for the requirements it cites. It is not an audit and does not state compliance with any regulation."

const (
	VerdictPass    = "PASS"
	VerdictFail    = "FAIL"
	VerdictWarn    = "WARN"
	VerdictInfo    = "INFO"
	VerdictNA      = "N/A"
	VerdictUnknown = "UNKNOWN"
)

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ProfileInfo struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Title   string `json:"title"`
	SHA256  string `json:"sha256"`
}

type ScanInfo struct {
	Mode         string        `json:"mode"`
	Inputs       []string      `json:"inputs"`
	InputDigests []load.Digest `json:"inputDigests"`
	Namespace    string        `json:"namespace"`
	StartedAt    string        `json:"startedAt"`
	Objects      int           `json:"objects"`
	AIWorkloads  int           `json:"aiWorkloads"`
	Cluster      *ClusterInfo  `json:"cluster,omitempty"`
}

type ClusterInfo struct {
	Context        string   `json:"context"`
	Server         string   `json:"server"`
	Namespaces     []string `json:"namespaces"`
	NodeProbe      bool     `json:"nodeProbe"`
	ProbeNamespace string   `json:"probeNamespace,omitempty"`
}

type Summary struct {
	Pass       int  `json:"pass"`
	Fail       int  `json:"fail"`
	Warn       int  `json:"warn"`
	Info       int  `json:"info"`
	NA         int  `json:"na"`
	Unknown    int  `json:"unknown,omitempty"`
	Incomplete bool `json:"incomplete"`
}

type Ref struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Source string `json:"source"`
	URL    string `json:"url"`
}

type Source struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type Finding struct {
	Object    load.ObjectRef
	Source    *Source
	Group     string
	Container string
	Path      string
	Message   string
	Verdict   string
}

type CheckResult struct {
	ID       string    `json:"id"`
	Display  string    `json:"display"`
	Title    string    `json:"title"`
	Verdict  string    `json:"verdict"`
	Severity string    `json:"severity"`
	Fix      string    `json:"fix"`
	Refs     []Ref     `json:"refs"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	SchemaVersion string        `json:"schemaVersion"`
	Tool          Tool          `json:"tool"`
	Profile       ProfileInfo   `json:"profile"`
	Scan          ScanInfo      `json:"scan"`
	Summary       Summary       `json:"summary"`
	Checks        []CheckResult `json:"checks"`
	Errors        []string      `json:"errors"`
}
