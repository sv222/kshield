package remediate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/sv222/kshield/internal/load"
)

const (
	OpAdd     = "add"
	OpReplace = "replace"
	OpRemove  = "remove"
	OpTest    = "test"
)

type Op struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func (o Op) MarshalJSON() ([]byte, error) {
	if o.Op == OpRemove {
		return json.Marshal(struct {
			Op   string `json:"op"`
			Path string `json:"path"`
		}{o.Op, o.Path})
	}
	type plain Op
	return json.Marshal(plain(o))
}

type Target struct {
	Ref      load.ObjectRef
	Original map[string]any
	Ops      []Op
}

func Set(obj map[string]any, path string, value any) Op {
	segs, err := splitPath(path)
	if err != nil {
		return Op{Op: OpAdd, Path: path, Value: value}
	}
	var node any = obj
	for i, s := range segs {
		next, ok := child(node, s)
		if !ok || (next == nil && i < len(segs)-1) {
			return Op{Op: OpAdd, Path: joinPath(segs[:i+1]), Value: nest(segs[i+1:], value)}
		}
		node = next
	}
	return Op{Op: OpReplace, Path: path, Value: value}
}

func Remove(path string) Op {
	return Op{Op: OpRemove, Path: path}
}

func BuiltinWorkload(kind, apiVersion string) bool {
	return podSpecRoot(kind, apiVersion) != nil
}

func podSpecRoot(kind, apiVersion string) []string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		group = ""
	}
	switch {
	case kind == "Pod" && group == "":
		return []string{"spec"}
	case group == "apps" && (kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "ReplicaSet"):
		return []string{"spec", "template", "spec"}
	case group == "batch" && kind == "Job":
		return []string{"spec", "template", "spec"}
	case group == "batch" && kind == "CronJob":
		return []string{"spec", "jobTemplate", "spec", "template", "spec"}
	}
	return nil
}

func Render(t Target) (map[string]any, []Op, error) {
	smp, j, err := renderTarget(t)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", t.Ref, err)
	}
	return smp, j, nil
}

func renderTarget(t Target) (map[string]any, []Op, error) {
	ops, err := normalize(t.Ops)
	if err != nil {
		return nil, nil, err
	}
	for _, op := range ops {
		if err := validate(t.Original, op); err != nil {
			return nil, nil, err
		}
	}
	if ops, err = combine(t.Original, ops); err != nil {
		return nil, nil, err
	}
	if err := checkConflicts(t.Original, ops); err != nil {
		return nil, nil, err
	}
	root := podSpecRoot(t.Ref.Kind, t.Ref.APIVersion)
	var smpOps, jsonOps []Op
	for _, op := range ops {
		if root != nil && fitsSMP(t.Original, root, op) {
			smpOps = append(smpOps, op)
		} else {
			jsonOps = append(jsonOps, op)
		}
	}
	smpOps, jsonOps = routeTaintedLists(t.Original, root, smpOps, jsonOps)
	smp, guards, err := renderSMP(t, root, smpOps)
	if err != nil {
		return nil, nil, err
	}
	j, err := render6902(t.Original, jsonOps, guards)
	if err != nil {
		return nil, nil, err
	}
	return smp, j, nil
}

func under(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, parent+"/")
}

func normalize(in []Op) ([]Op, error) {
	out := make([]Op, 0, len(in))
	for _, op := range in {
		switch op.Op {
		case OpAdd, OpReplace, OpRemove, OpTest:
		default:
			return nil, fmt.Errorf("unsupported op %q at %s", op.Op, op.Path)
		}
		if _, err := splitPath(op.Path); err != nil {
			return nil, err
		}
		v, err := jsonValue(op.Value)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", op.Op, op.Path, err)
		}
		if op.Op == OpRemove {
			v = nil
		}
		out = append(out, Op{Op: op.Op, Path: op.Path, Value: v})
	}
	return out, nil
}

func jsonValue(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out any
	if err := d.Decode(&out); err != nil {
		return nil, err
	}
	return numbers(out), nil
}

func numbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = numbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = numbers(e)
		}
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		f, _ := x.Float64()
		return f
	}
	return v
}

func validate(orig map[string]any, op Op) error {
	segs, _ := splitPath(op.Path)
	if len(segs) == 0 {
		return fmt.Errorf("%s %s: the root cannot be patched", op.Op, op.Path)
	}
	parent, ok := lookup(orig, segs[:len(segs)-1])
	if !ok {
		return fmt.Errorf("%s %s: parent does not exist", op.Op, op.Path)
	}
	last := segs[len(segs)-1]
	if op.Op == OpAdd {
		switch p := parent.(type) {
		case map[string]any:
			return nil
		case []any:
			if last == "-" {
				return nil
			}
			if n, ok := index(last); ok && n <= len(p) {
				return nil
			}
		}
		return fmt.Errorf("%s %s: cannot add here", op.Op, op.Path)
	}
	if _, ok := child(parent, last); !ok {
		return fmt.Errorf("%s %s: path does not exist", op.Op, op.Path)
	}
	return nil
}

func splitPath(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path %q is not a JSON pointer", path)
	}
	if path == "/" {
		return []string{""}, nil
	}
	return strings.Split(path[1:], "/"), nil
}

func joinPath(segs []string) string {
	return "/" + strings.Join(segs, "/")
}

func decode(seg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
}

func encode(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func index(seg string) (int, bool) {
	if seg == "" || (len(seg) > 1 && seg[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(seg)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func isIndex(seg string) bool {
	if seg == "-" {
		return true
	}
	_, ok := index(seg)
	return ok
}

func child(node any, seg string) (any, bool) {
	switch n := node.(type) {
	case map[string]any:
		v, ok := n[decode(seg)]
		return v, ok
	case []any:
		i, ok := index(seg)
		if !ok || i >= len(n) {
			return nil, false
		}
		return n[i], true
	}
	return nil, false
}

func lookup(obj any, segs []string) (any, bool) {
	node := obj
	for _, s := range segs {
		next, ok := child(node, s)
		if !ok {
			return nil, false
		}
		node = next
	}
	return node, true
}

func nest(segs []string, value any) any {
	v := value
	for i := len(segs) - 1; i >= 0; i-- {
		if isIndex(segs[i]) {
			v = []any{v}
		} else {
			v = map[string]any{decode(segs[i]): v}
		}
	}
	return v
}

func merge(dst, src any) (any, error) {
	dm, dok := dst.(map[string]any)
	sm, sok := src.(map[string]any)
	if dok && sok {
		for k, sv := range sm {
			dv, ok := dm[k]
			if !ok {
				dm[k] = sv
				continue
			}
			mv, err := merge(dv, sv)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			dm[k] = mv
		}
		return dm, nil
	}
	if reflect.DeepEqual(dst, src) {
		return dst, nil
	}
	return nil, fmt.Errorf("conflicting values %v and %v", dst, src)
}
