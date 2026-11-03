package model

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/sv222/kshield/internal/load"
)

func WorkloadKind(apiVersion, kind string) bool {
	o := &load.Object{
		Ref: load.ObjectRef{APIVersion: apiVersion, Kind: kind},
		U:   &unstructured.Unstructured{Object: map[string]any{}},
	}
	sites, err := sitesOf(o)
	return err == nil && len(sites) > 0
}

func PodGroup(owner load.ObjectRef, podLabels map[string]string) string {
	switch schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind).Group {
	case groupRay:
		if podLabels[rayNodeTypeLabel] == rayHeadNodeType {
			return groupHead
		}
		return podLabels[rayGroupLabel]
	case groupKServe:
		return podLabels[kserveComponentLabel]
	}
	return ""
}
