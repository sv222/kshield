package model

import (
	"testing"

	"github.com/sv222/kshield/internal/load"
)

func TestWorkloadKind(t *testing.T) {
	cases := []struct {
		apiVersion, kind string
		want             bool
	}{
		{"v1", "Pod", true},
		{"apps/v1", "Deployment", true},
		{"apps/v1", "StatefulSet", true},
		{"apps/v1", "DaemonSet", true},
		{"apps/v1", "ReplicaSet", true},
		{"batch/v1", "Job", true},
		{"batch/v1", "CronJob", true},
		{"ray.io/v1", "RayCluster", true},
		{"ray.io/v1", "RayService", true},
		{"ray.io/v1", "RayJob", true},
		{"serving.kserve.io/v1beta1", "InferenceService", true},
		{"serving.kserve.io/v1alpha1", "ServingRuntime", true},
		{"serving.kserve.io/v1alpha1", "ClusterServingRuntime", true},
		{"v1", "Service", false},
		{"v1", "ConfigMap", false},
		{"extensions/v1beta1", "Deployment", false},
		{"leaderworkerset.x-k8s.io/v1", "LeaderWorkerSet", false},
	}
	for _, tc := range cases {
		if got := WorkloadKind(tc.apiVersion, tc.kind); got != tc.want {
			t.Errorf("WorkloadKind(%s, %s) = %v, want %v", tc.apiVersion, tc.kind, got, tc.want)
		}
	}
}

func TestPodGroup(t *testing.T) {
	ray := load.ObjectRef{APIVersion: "ray.io/v1", Kind: "RayService"}
	isvc := load.ObjectRef{APIVersion: "serving.kserve.io/v1beta1", Kind: "InferenceService"}
	deploy := load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment"}
	cases := []struct {
		owner  load.ObjectRef
		labels map[string]string
		want   string
	}{
		{ray, map[string]string{"ray.io/node-type": "head", "ray.io/group": "headgroup"}, "head"},
		{ray, map[string]string{"ray.io/node-type": "worker", "ray.io/group": "gpu"}, "gpu"},
		{ray, nil, ""},
		{isvc, map[string]string{"component": "predictor"}, "predictor"},
		{isvc, map[string]string{"ray.io/node-type": "head"}, ""},
		{deploy, map[string]string{"component": "predictor", "ray.io/group": "gpu"}, ""},
	}
	for _, tc := range cases {
		if got := PodGroup(tc.owner, tc.labels); got != tc.want {
			t.Errorf("PodGroup(%s, %v) = %q, want %q", tc.owner.Kind, tc.labels, got, tc.want)
		}
	}
}
