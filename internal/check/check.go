package check

import (
	"cmp"
	"slices"
	"sync"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

type Tier int

const (
	Manifest Tier = 1
	Cluster  Tier = 2
	Both     Tier = Manifest | Cluster
)

type Fix string

const (
	FixPatch  Fix = "patch"
	FixPolicy Fix = "policy"
	FixManual Fix = "manual"
)

type Strength int

const (
	Violation Strength = iota
	Suspect
	Unknown
)

type Finding struct {
	Object    load.ObjectRef
	Group     string
	Container string
	Path      string
	Message   string
	Strength  Strength
}

type Result struct {
	Applicable bool
	Findings   []Finding
}

type ClusterFacts struct {
	ProbeRan bool
	Nodes    []NodeFacts
}

type NodeFacts struct {
	Node         load.ObjectRef
	LSM          []string
	BPFLSMConfig string
	Unknown      string
}

type Input struct {
	Objects   []load.Object
	Workloads []model.Workload
	Cluster   *ClusterFacts

	once  sync.Once
	index *inputIndex
}

func (in *Input) idx() *inputIndex {
	in.once.Do(func() { in.index = buildIndex(in.Objects) })
	return in.index
}

type Check struct {
	ID    string
	Title string
	Tier  Tier
	Fix   Fix
	Run   func(*Input) Result
}

func Evaluate(c Check, in *Input) Result {
	if in.Cluster == nil && c.Tier == Cluster {
		return Result{Applicable: false}
	}
	if in.Cluster != nil && c.Tier == Manifest {
		return Result{Applicable: false}
	}
	r := c.Run(in)
	slices.SortStableFunc(r.Findings, CompareFindings)
	return r
}

func CompareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(a.Object.String(), b.Object.String()),
		cmp.Compare(a.Group, b.Group),
		cmp.Compare(a.Path, b.Path),
		cmp.Compare(a.Container, b.Container),
		cmp.Compare(a.Message, b.Message),
		cmp.Compare(a.Strength, b.Strength),
	)
}

func AIWorkloads(in *Input) []model.Workload {
	var out []model.Workload
	for _, w := range in.Workloads {
		if w.IsAI() {
			out = append(out, w)
		}
	}
	return out
}
