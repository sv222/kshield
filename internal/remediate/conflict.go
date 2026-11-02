package remediate

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

func combine(orig map[string]any, in []Op) ([]Op, error) {
	var out []Op
	for _, op := range in {
		segs, _ := splitPath(op.Path)
		last := segs[len(segs)-1]
		isAppend := op.Op == OpAdd && last == "-"
		repeatable := op.Op == OpAdd && (positional[decode(last)] || len(segs) >= 2 && positional[decode(segs[len(segs)-2])])
		if !repeatable && slices.ContainsFunc(out, func(o Op) bool {
			return o.Op == op.Op && o.Path == op.Path && reflect.DeepEqual(o.Value, op.Value)
		}) {
			continue
		}
		j := slices.IndexFunc(out, func(o Op) bool { return o.Path == op.Path })
		if j < 0 || isAppend {
			out = append(out, op)
			continue
		}
		prev := &out[j]
		existing, _ := lookup(orig, segs)
		if prev.Op != OpAdd || op.Op != OpAdd || existing != nil || isIndex(last) {
			return nil, fmt.Errorf("conflicting ops on %s: %s and %s", op.Path, prev.Op, op.Op)
		}
		v, err := mergeAdds(prev.Value, op.Value, positional[decode(last)])
		if err != nil {
			return nil, fmt.Errorf("conflicting adds on %s: %w", op.Path, err)
		}
		prev.Value = v
	}
	var kept []Op
	for _, op := range out {
		if op.Op == OpRemove && slices.ContainsFunc(out, func(r Op) bool {
			return r.Op == OpRemove && strings.HasPrefix(op.Path, r.Path+"/")
		}) {
			continue
		}
		kept = append(kept, op)
	}
	return kept, nil
}

func mergeAdds(prev, next any, keepRepeats bool) (any, error) {
	pl, pok := prev.([]any)
	nl, nok := next.([]any)
	if !pok || !nok {
		return merge(prev, next)
	}
	for _, it := range nl {
		if keepRepeats || !slices.ContainsFunc(pl, func(p any) bool { return reflect.DeepEqual(p, it) }) {
			pl = append(pl, it)
		}
	}
	return pl, nil
}

func checkConflicts(orig map[string]any, ops []Op) error {
	if err := checkInserts(orig, ops); err != nil {
		return err
	}
	for _, a := range ops {
		if a.Op == OpTest {
			continue
		}
		for _, b := range ops {
			if b.Op == OpTest || !strings.HasPrefix(b.Path, a.Path+"/") {
				continue
			}
			_, wholeList := a.Value.([]any)
			switch {
			case a.Op == OpRemove:
				return fmt.Errorf("%s %s is under removed %s", b.Op, b.Path, a.Path)
			case b.Op == OpAdd && b.Path == a.Path+"/-" && wholeList:
			default:
				seg, _, _ := strings.Cut(strings.TrimPrefix(b.Path, a.Path+"/"), "/")
				through := "a field"
				if isIndex(seg) {
					through = "an index"
				}
				return fmt.Errorf("%s %s goes through %s of %s, which %s %s writes whole", b.Op, b.Path, through, a.Path, a.Op, a.Path)
			}
		}
	}
	return checkKeys(orig, ops)
}

func checkInserts(orig map[string]any, ops []Op) error {
	for _, ins := range ops {
		if ins.Op != OpAdd {
			continue
		}
		segs, _ := splitPath(ins.Path)
		n, ok := index(segs[len(segs)-1])
		if !ok {
			continue
		}
		list, _ := lookup(orig, segs[:len(segs)-1])
		if l, _ := list.([]any); n >= len(l) {
			continue
		}
		parent := joinPath(segs[:len(segs)-1])
		for _, op := range ops {
			if op.Op != OpTest && op.Path != ins.Path && under(op.Path, parent) {
				return fmt.Errorf("add %s inserts into %s, which %s %s also edits", ins.Path, parent, op.Op, op.Path)
			}
		}
	}
	return nil
}

type keyedItem struct {
	elem  any
	op    *Op
	added bool
}

func checkKeys(orig map[string]any, ops []Op) error {
	var lists []string
	for _, op := range ops {
		if l, ok := rekeyedList(op); ok && !slices.Contains(lists, l) {
			lists = append(lists, l)
		}
	}
	for _, l := range lists {
		if err := checkListKeys(orig, ops, l); err != nil {
			return err
		}
	}
	return nil
}

func rekeyedList(op Op) (string, bool) {
	segs, _ := splitPath(op.Path)
	n := len(segs)
	_, whole := op.Value.([]any)
	switch {
	case op.Op == OpTest:
	case op.Op != OpRemove && whole && stableKeys[decode(segs[n-1])] != nil:
		return op.Path, true
	case n >= 2 && op.Op != OpRemove && isIndex(segs[n-1]) && stableKeys[decode(segs[n-2])] != nil:
		return joinPath(segs[:n-1]), true
	case n >= 3 && isIndex(segs[n-2]) && slices.Contains(idFields(decode(segs[n-3])), decode(segs[n-1])):
		return joinPath(segs[:n-2]), true
	}
	return "", false
}

func idFields(list string) []string {
	if list == "ports" {
		return append(slices.Clone(stableKeys[list]), "protocol")
	}
	return stableKeys[list]
}

func checkListKeys(orig map[string]any, ops []Op, list string) error {
	segs, _ := splitPath(list)
	name := decode(segs[len(segs)-1])
	node, _ := lookup(orig, segs)
	l, _ := node.([]any)
	slots := make([]*keyedItem, len(l))
	for i, it := range l {
		slots[i] = &keyedItem{elem: it}
	}
	var added []*keyedItem
	for k := range ops {
		op := &ops[k]
		if op.Op == OpTest {
			continue
		}
		if op.Path == list {
			if items, ok := op.Value.([]any); ok && op.Op != OpRemove {
				slots = nil
				for _, it := range items {
					added = append(added, &keyedItem{elem: it, op: op, added: true})
				}
			}
			continue
		}
		if !strings.HasPrefix(op.Path, list+"/") {
			continue
		}
		rest := strings.Split(strings.TrimPrefix(op.Path, list+"/"), "/")
		n, ok := index(rest[0])
		switch {
		case len(rest) == 1 && op.Op == OpAdd:
			added = append(added, &keyedItem{elem: op.Value, op: op, added: true})
		case !ok || n >= len(slots) || slots[n] == nil || len(rest) > 2:
		case len(rest) == 1 && op.Op == OpRemove:
			slots[n] = nil
		case len(rest) == 1:
			slots[n] = changed(name, slots[n], op.Value, op)
		default:
			m, ok := slots[n].elem.(map[string]any)
			if !ok {
				continue
			}
			c := maps.Clone(m)
			if op.Op == OpRemove {
				delete(c, decode(rest[1]))
			} else {
				c[decode(rest[1])] = op.Value
			}
			slots[n] = changed(name, slots[n], c, op)
		}
	}
	seen := map[string]*keyedItem{}
	for _, it := range slices.Concat(slots, added) {
		if it == nil {
			continue
		}
		label, id, ok := itemID(name, it.elem)
		if !ok {
			continue
		}
		prev, dup := seen[id]
		if !dup {
			seen[id] = it
			continue
		}
		switch {
		case prev.op == nil && it.op == nil:
		case prev.added && it.added:
			return fmt.Errorf("two items with %s %s added to %s", label, id, list)
		case it.op != nil:
			return fmt.Errorf("%s %s: an item with %s %s is already in the list", it.op.Op, it.op.Path, label, id)
		default:
			return fmt.Errorf("%s %s: an item with %s %s is already in the list", prev.op.Op, prev.op.Path, label, id)
		}
	}
	return nil
}

func changed(list string, old *keyedItem, elem any, op *Op) *keyedItem {
	_, oldID, _ := itemID(list, old.elem)
	_, newID, _ := itemID(list, elem)
	if old.op == nil && oldID == newID {
		return &keyedItem{elem: elem}
	}
	return &keyedItem{elem: elem, op: op}
}

func itemID(list string, elem any) (string, string, bool) {
	key := stableKey(list, elem)
	if key == "" {
		return "", "", false
	}
	id := fmt.Sprint(elem.(map[string]any)[key])
	if list == "ports" {
		protocol, ok := keyOf(elem, "protocol")
		if !ok {
			protocol = "TCP"
		}
		id += "/" + fmt.Sprint(protocol)
	}
	return key, id, true
}
