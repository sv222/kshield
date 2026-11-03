package remediate

import (
	"fmt"
	"slices"
	"strings"
)

var stableKeys = map[string][]string{
	"containers":          {"name"},
	"initContainers":      {"name"},
	"ephemeralContainers": {"name"},
	"volumes":             {"name"},
	"env":                 {"name"},
	"imagePullSecrets":    {"name"},
	"volumeMounts":        {"mountPath"},
	"workerGroupSpecs":    {"groupName"},
	"ports":               {"port", "containerPort"},
}

var positional = map[string]bool{"args": true, "command": true}

func render6902(orig map[string]any, ops, guards []Op) ([]Op, error) {
	var tests, edits, appends, removes []Op
	seen := map[string]bool{}
	for _, g := range guards {
		if !seen[g.Path] {
			seen[g.Path] = true
			tests = append(tests, g)
		}
	}
	for _, op := range ops {
		segs, _ := splitPath(op.Path)
		for i := 1; i < len(segs); i++ {
			n, ok := index(segs[i])
			if !ok {
				continue
			}
			list, _ := lookup(orig, segs[:i])
			l, ok := list.([]any)
			if !ok || n >= len(l) {
				continue
			}
			for _, tst := range itemTests(decode(segs[i-1]), joinPath(segs[:i+1]), l[n]) {
				if seen[tst.Path] {
					continue
				}
				v, err := jsonValue(tst.Value)
				if err != nil {
					return nil, fmt.Errorf("test %s: %w", tst.Path, err)
				}
				seen[tst.Path] = true
				tests = append(tests, Op{Op: OpTest, Path: tst.Path, Value: v})
			}
		}
	}
	for _, op := range ops {
		segs, _ := splitPath(op.Path)
		switch {
		case op.Op == OpTest:
			if !seen[op.Path] {
				seen[op.Path] = true
				tests = append(tests, op)
			}
		case op.Op == OpRemove && isIndex(segs[len(segs)-1]):
			removes = append(removes, op)
		case op.Op == OpAdd && slices.ContainsFunc(ops, func(w Op) bool {
			return (w.Op == OpAdd || w.Op == OpReplace) && w.Path+"/-" == op.Path
		}):
			appends = append(appends, op)
		default:
			edits = append(edits, op)
		}
	}
	slices.SortStableFunc(removes, func(a, b Op) int {
		return comparePaths(b.Path, a.Path)
	})
	if len(edits)+len(appends)+len(removes) == 0 && len(guards) == 0 {
		return nil, nil
	}
	return slices.Concat(tests, edits, appends, removes), nil
}

func itemTests(list, path string, elem any) []Op {
	key := stableKey(list, elem)
	if key == "" {
		return []Op{{Op: OpTest, Path: path, Value: elem}}
	}
	fields := []string{key}
	if list == "ports" {
		fields = append(fields, "protocol")
	}
	var out []Op
	for _, f := range fields {
		if v, ok := keyOf(elem, f); ok {
			out = append(out, Op{Op: OpTest, Path: path + "/" + encode(f), Value: v})
		}
	}
	return out
}

func stableKey(list string, elem any) string {
	for _, k := range stableKeys[list] {
		if _, ok := keyOf(elem, k); ok {
			return k
		}
	}
	return ""
}

func comparePaths(a, b string) int {
	as := strings.Split(a, "/")
	bs := strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aok := index(as[i])
		bn, bok := index(bs[i])
		switch {
		case aok && bok:
			if an != bn {
				return an - bn
			}
		case as[i] != bs[i]:
			return strings.Compare(as[i], bs[i])
		}
	}
	return len(as) - len(bs)
}
