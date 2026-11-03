package cluster

import (
	"cmp"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const maxOwnerLinks = 10

const (
	phaseSucceeded = "Succeeded"
	phaseFailed    = "Failed"
)

type Resolved struct {
	Objects []load.Object
	Live    map[load.ObjectRef][]load.Object
}

type graph struct {
	objs  []load.Object
	byUID map[types.UID]int
}

func Resolve(objs []load.Object) Resolved {
	g := graph{objs: objs, byUID: make(map[types.UID]int, len(objs))}
	for i, o := range objs {
		if o.U == nil {
			continue
		}
		if uid := o.U.GetUID(); uid != "" {
			if _, dup := g.byUID[uid]; !dup {
				g.byUID[uid] = i
			}
		}
	}
	out := Resolved{Objects: []load.Object{}, Live: map[load.ObjectRef][]load.Object{}}
	for i, o := range objs {
		_, owned := g.owner(i)
		switch {
		case owned && isPod(o):
			if running(o) {
				key := objs[g.anchor(g.owners(i))].Ref
				out.Live[key] = append(out.Live[key], o)
			}
		case owned && workload(o) && !check.IsPrerequisite(o) && g.anchor(g.chain(i)) != i:
		default:
			out.Objects = append(out.Objects, o)
		}
	}
	slices.SortStableFunc(out.Objects, func(a, b load.Object) int {
		return cmp.Or(
			cmp.Compare(a.Ref.Namespace, b.Ref.Namespace),
			cmp.Compare(a.Ref.Kind, b.Ref.Kind),
			cmp.Compare(a.Ref.Name, b.Ref.Name),
		)
	})
	for _, pods := range out.Live {
		slices.SortStableFunc(pods, func(a, b load.Object) int { return cmp.Compare(a.Ref.Name, b.Ref.Name) })
	}
	return out
}

func (g graph) owner(i int) (int, bool) {
	if g.objs[i].U == nil {
		return 0, false
	}
	for _, ref := range g.objs[i].U.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			j, ok := g.byUID[ref.UID]
			return j, ok
		}
	}
	return 0, false
}

func (g graph) chain(i int) []int {
	path := []int{i}
	for range maxOwnerLinks {
		j, ok := g.owner(i)
		if !ok {
			return path
		}
		if k := slices.Index(path, j); k >= 0 {
			return path[:k+1]
		}
		path = append(path, j)
		i = j
	}
	return path
}

func (g graph) owners(i int) []int {
	path := g.chain(i)
	if len(path) > 1 {
		return path[1:]
	}
	return path
}

func (g graph) anchor(path []int) int {
	for _, j := range slices.Backward(path) {
		if workload(g.objs[j]) {
			return j
		}
	}
	return path[len(path)-1]
}

func workload(o load.Object) bool {
	return model.WorkloadKind(o.Ref.APIVersion, o.Ref.Kind)
}

func isPod(o load.Object) bool {
	return o.Ref.APIVersion == "v1" && o.Ref.Kind == "Pod"
}

func running(o load.Object) bool {
	phase, _, _ := unstructured.NestedString(o.U.Object, "status", "phase")
	return phase != phaseSucceeded && phase != phaseFailed
}
