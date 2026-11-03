package remediate

import (
	"fmt"
	"slices"
	"strconv"
)

var mergeKeys = map[string]string{
	"containers":     "name",
	"initContainers": "name",
	"volumes":        "name",
	"env":            "name",
	"volumeMounts":   "mountPath",
}

func fitsSMP(orig map[string]any, root []string, op Op) bool {
	if op.Op == OpTest {
		return false
	}
	segs, _ := splitPath(op.Path)
	if len(segs) <= len(root) || !slices.Equal(segs[:len(root)], root) {
		return false
	}
	rest := segs[len(root):]
	node, _ := lookup(orig, root)
	for i := 0; i < len(rest); i++ {
		name := decode(rest[i])
		if name == "args" || name == "command" {
			return false
		}
		last := i == len(rest)-1
		if isIndex(rest[i]) {
			return false
		}
		if !last && isIndex(rest[i+1]) {
			key, ok := mergeKeys[name]
			if !ok {
				return false
			}
			list, _ := child(node, rest[i])
			l, _ := list.([]any)
			if n, ok := index(rest[i+1]); ok && n < len(l) {
				if _, ok := keyOf(l[n], key); !ok {
					return false
				}
				if i+1 == len(rest)-1 {
					return op.Op == OpRemove
				}
				if i+2 == len(rest)-1 && decode(rest[i+2]) == key {
					return false
				}
				node = l[n]
				i++
				continue
			}
			if i+1 != len(rest)-1 || op.Op != OpAdd {
				return false
			}
			_, ok = keyOf(op.Value, key)
			return ok
		}
		if last {
			existing, exists := child(node, rest[i])
			if op.Op == OpRemove {
				return true
			}
			if key, ok := mergeKeys[name]; ok {
				if exists && existing != nil {
					return false
				}
				items, ok := op.Value.([]any)
				if !ok {
					return false
				}
				for _, it := range items {
					if _, ok := keyOf(it, key); !ok {
						return false
					}
				}
				return true
			}
			if exists && existing != nil {
				switch op.Value.(type) {
				case map[string]any, []any:
					return false
				}
			}
			return true
		}
		node, _ = child(node, rest[i])
	}
	return false
}

func routeTaintedLists(orig map[string]any, root []string, smpOps, jsonOps []Op) ([]Op, []Op) {
	for {
		lists := append(taintedLists(root, jsonOps), sharedItems(orig, root, smpOps)...)
		var keep []Op
		moved := false
		for _, op := range smpOps {
			if slices.ContainsFunc(lists, func(l string) bool { return under(op.Path, l) }) {
				jsonOps = append(jsonOps, op)
				moved = true
				continue
			}
			keep = append(keep, op)
		}
		smpOps = keep
		if !moved {
			return smpOps, jsonOps
		}
	}
}

func taintedLists(root []string, ops []Op) []string {
	var lists []string
	for _, op := range ops {
		if op.Op == OpTest {
			continue
		}
		segs, _ := splitPath(op.Path)
		if len(segs) <= len(root) || !slices.Equal(segs[:len(root)], root) {
			continue
		}
		rest := segs[len(root):]
		n := len(rest)
		_, keyed := mergeKeys[decode(rest[n-1])]
		switch {
		case keyed:
			lists = append(lists, joinPath(segs))
		case n >= 2 && isIndex(rest[n-1]) && mergeKeys[decode(rest[n-2])] != "":
			lists = append(lists, joinPath(segs[:len(segs)-1]))
		case n >= 3 && isIndex(rest[n-2]) && mergeKeys[decode(rest[n-3])] == decode(rest[n-1]):
			lists = append(lists, joinPath(segs[:len(segs)-2]))
		}
	}
	return lists
}

func sharedItems(orig map[string]any, root []string, ops []Op) []string {
	var lists []string
	owners := map[string]string{}
	for k, op := range ops {
		segs, _ := splitPath(op.Path)
		for i := len(root); i+1 < len(segs); i++ {
			key, ok := mergeKeys[decode(segs[i])]
			if !ok || !isIndex(segs[i+1]) {
				continue
			}
			list := joinPath(segs[:i+1])
			node, _ := lookup(orig, segs[:i+1])
			l, _ := node.([]any)
			owner, item := "new"+strconv.Itoa(k), op.Value
			if n, ok := index(segs[i+1]); ok && n < len(l) {
				owner, item = segs[i+1], l[n]
			}
			kv, _ := keyOf(item, key)
			id := list + "\x00" + fmt.Sprint(kv)
			if prev, ok := owners[id]; (ok && prev != owner) || repeatsKey(l, key) {
				if !slices.Contains(lists, list) {
					lists = append(lists, list)
				}
			}
			owners[id] = owner
		}
	}
	return lists
}

func repeatsKey(l []any, key string) bool {
	seen := map[string]bool{}
	for _, it := range l {
		kv, ok := keyOf(it, key)
		if !ok {
			continue
		}
		if seen[fmt.Sprint(kv)] {
			return true
		}
		seen[fmt.Sprint(kv)] = true
	}
	return false
}

func keyOf(item any, key string) (any, bool) {
	m, ok := item.(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	switch v.(type) {
	case map[string]any, []any:
		return nil, false
	}
	return v, true
}

func renderSMP(t Target, root []string, ops []Op) (map[string]any, []Op, error) {
	if len(ops) == 0 {
		return nil, nil, nil
	}
	md := map[string]any{"name": t.Ref.Name}
	if t.Ref.Namespace != "" {
		md["namespace"] = t.Ref.Namespace
	}
	doc := map[string]any{"apiVersion": t.Ref.APIVersion, "kind": t.Ref.Kind, "metadata": md}
	spec := doc
	for _, r := range root {
		m := map[string]any{}
		spec[r] = m
		spec = m
	}
	origSpec, _ := lookup(t.Original, root)
	var guards []Op
	for _, op := range ops {
		segs, _ := splitPath(op.Path)
		if err := applySMP(spec, origSpec, slices.Clone(root), segs[len(root):], op, &guards); err != nil {
			return nil, nil, fmt.Errorf("%s %s: %w", op.Op, op.Path, err)
		}
	}
	return doc, guards, nil
}

func applySMP(patch map[string]any, orig any, path, rest []string, op Op, guards *[]Op) error {
	for i := 0; i < len(rest); i++ {
		name := decode(rest[i])
		if i+1 < len(rest) && isIndex(rest[i+1]) {
			key := mergeKeys[name]
			list, _ := child(orig, rest[i])
			l, _ := list.([]any)
			listPath := append(slices.Clone(path), rest[i])
			var elem, kv any
			if n, ok := index(rest[i+1]); ok && n < len(l) {
				elem = l[n]
				kv, _ = keyOf(elem, key)
			} else {
				kv, _ = keyOf(op.Value, key)
			}
			item, err := listItem(patch, name, key, kv, l, listPath, guards)
			if err != nil {
				return err
			}
			if i+1 == len(rest)-1 {
				if op.Op == OpRemove {
					item["$patch"] = "delete"
					return nil
				}
				_, err := merge(item, op.Value)
				return err
			}
			patch = item
			orig = elem
			path = append(listPath, rest[i+1])
			i++
			continue
		}
		if i == len(rest)-1 {
			return setSMP(patch, name, op)
		}
		m, ok := patch[name].(map[string]any)
		if !ok {
			m = map[string]any{}
			patch[name] = m
		}
		patch = m
		orig, _ = child(orig, rest[i])
		path = append(path, rest[i])
	}
	return nil
}

func setSMP(patch map[string]any, name string, op Op) error {
	if op.Op == OpRemove {
		patch[name] = nil
		return nil
	}
	if key, ok := mergeKeys[name]; ok {
		items, _ := op.Value.([]any)
		for _, it := range items {
			kv, _ := keyOf(it, key)
			item, err := listItem(patch, name, key, kv, nil, nil, nil)
			if err != nil {
				return err
			}
			if _, err := merge(item, it); err != nil {
				return err
			}
		}
		return nil
	}
	existing, ok := patch[name]
	if !ok {
		patch[name] = op.Value
		return nil
	}
	v, err := merge(existing, op.Value)
	if err != nil {
		return err
	}
	patch[name] = v
	return nil
}

func listItem(patch map[string]any, name, key string, kv any, orig []any, listPath []string, guards *[]Op) (map[string]any, error) {
	list, ok := patch[name].([]any)
	if !ok {
		var err error
		list, err = keysOnly(orig, key, listPath, guards)
		if err != nil {
			return nil, err
		}
		patch[name] = list
	}
	for _, it := range list {
		m := it.(map[string]any)
		if m[key] == kv {
			return m, nil
		}
	}
	item := map[string]any{key: kv}
	patch[name] = append(list, item)
	return item, nil
}

func keysOnly(orig []any, key string, listPath []string, guards *[]Op) ([]any, error) {
	list := []any{}
	for j, it := range orig {
		kv, ok := keyOf(it, key)
		if !ok {
			continue
		}
		v, err := jsonValue(kv)
		if err != nil {
			return nil, err
		}
		*guards = append(*guards, Op{Op: OpTest, Path: joinPath(listPath) + "/" + strconv.Itoa(j) + "/" + encode(key), Value: v})
		list = append(list, map[string]any{key: kv})
	}
	return list, nil
}
