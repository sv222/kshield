package fixturegen

import (
	"bytes"
	_ "embed"
	"fmt"
	"math/rand/v2"
	"slices"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/load"
)

//go:embed base.yaml
var baseYAML []byte

const (
	Namespace    = "ai-inference"
	minMutations = 3
	maxMutations = 8
	docSeparator = "---\n"
)

var clusterOnly = []string{"KS-NET-003", "KS-PRE-001", "KS-PRE-002", "KS-PRE-003", "KS-PRE-004"}

type Mutation struct {
	Name      string
	Conflicts []string
	Apply     func(objs []map[string]any) error
	Expect    []corpus.Expect
}

func Generate(seed int64) (input []byte, spec corpus.Spec, applied []string, err error) {
	r := rand.New(rand.NewPCG(uint64(seed), 0))
	k := minMutations + r.IntN(maxMutations-minMutations+1)
	ms := Mutations()
	r.Shuffle(len(ms), func(i, j int) { ms[i], ms[j] = ms[j], ms[i] })
	var picked []Mutation
	for _, m := range ms {
		if len(picked) == k {
			break
		}
		if slices.ContainsFunc(picked, func(p Mutation) bool { return conflicts(m, p) }) {
			continue
		}
		picked = append(picked, m)
	}
	input, err = build(picked)
	if err != nil {
		return nil, corpus.Spec{}, nil, err
	}
	spec = corpus.Spec{Namespace: Namespace, NA: slices.Clone(clusterOnly)}
	for _, m := range picked {
		applied = append(applied, m.Name)
		spec.Expect = append(spec.Expect, m.Expect...)
	}
	return input, spec, applied, nil
}

func conflicts(a, b Mutation) bool {
	return slices.Contains(a.Conflicts, b.Name) || slices.Contains(b.Conflicts, a.Name)
}

func build(ms []Mutation) ([]byte, error) {
	objs, err := parseBase()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if err := m.Apply(objs); err != nil {
			return nil, fmt.Errorf("mutation %s: %w", m.Name, err)
		}
	}
	var b bytes.Buffer
	for _, o := range objs {
		if len(o) == 0 {
			continue
		}
		out, err := yaml.Marshal(o)
		if err != nil {
			return nil, err
		}
		if b.Len() > 0 {
			b.WriteString(docSeparator)
		}
		b.Write(out)
	}
	return b.Bytes(), nil
}

func parseBase() ([]map[string]any, error) {
	loaded, err := load.Read([]string{"-"}, load.Options{Stdin: bytes.NewReader(baseYAML)})
	if err != nil {
		return nil, fmt.Errorf("base.yaml: %w", err)
	}
	objs := make([]map[string]any, len(loaded))
	for i, o := range loaded {
		objs[i] = o.U.Object
	}
	return objs, nil
}
