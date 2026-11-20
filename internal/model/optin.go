package model

import (
	"fmt"
	"strings"

	k8slabels "k8s.io/apimachinery/pkg/labels"
)

const OptInKey = "kshield.io/ai"

const optInValue = "true"

type ExtractOption func(*extractConfig)

type extractConfig struct {
	selector k8slabels.Selector
}

func ParseSelector(s string) (k8slabels.Selector, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	sel, err := k8slabels.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid workload selector %q: %w", s, err)
	}
	return sel, nil
}

func WithSelector(sel k8slabels.Selector) ExtractOption {
	return func(c *extractConfig) { c.selector = sel }
}

func markOptIn(w *Workload, objectLabels, objectAnnotations map[string]string, sel k8slabels.Selector) {
	if !optedIn(w, objectLabels, objectAnnotations, sel) {
		return
	}
	w.OptIn = true
	if len(w.Stacks) > 0 {
		return
	}
	w.Stacks = []Stack{Custom}
	var engines []int
	for i, c := range w.Containers {
		if !c.Init {
			engines = append(engines, i)
		}
	}
	if len(engines) == 1 {
		w.Containers[engines[0]].Stack = Custom
	}
}

func optedIn(w *Workload, objectLabels, objectAnnotations map[string]string, sel k8slabels.Selector) bool {
	for _, m := range []map[string]string{w.Labels, w.Annotations, objectLabels, objectAnnotations} {
		if m[OptInKey] == optInValue {
			return true
		}
	}
	if sel == nil || sel.Empty() {
		return false
	}
	return sel.Matches(k8slabels.Set(w.Labels)) || sel.Matches(k8slabels.Set(objectLabels))
}
