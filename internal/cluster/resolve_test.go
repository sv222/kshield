package cluster

import (
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/sv222/kshield/internal/load"
)

type owner struct {
	apiVersion, kind, name, uid string
	controller                  bool
}

func object(apiVersion, kind, name, uid string, owners ...owner) load.Object {
	meta := map[string]any{"name": name, "namespace": "ai"}
	if uid != "" {
		meta["uid"] = uid
	}
	if len(owners) > 0 {
		refs := make([]any, 0, len(owners))
		for _, o := range owners {
			refs = append(refs, map[string]any{"apiVersion": o.apiVersion, "kind": o.kind, "name": o.name, "uid": o.uid, "controller": o.controller})
		}
		meta["ownerReferences"] = refs
	}
	return load.Object{
		Ref: load.ObjectRef{APIVersion: apiVersion, Kind: kind, Namespace: "ai", Name: name},
		U:   &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": meta}},
	}
}

func pod(name, uid, phase string, owners ...owner) load.Object {
	o := object("v1", "Pod", name, uid, owners...)
	if phase != "" {
		o.U.Object["status"] = map[string]any{"phase": phase}
	}
	return o
}

func ctl(o load.Object) owner {
	return owner{o.Ref.APIVersion, o.Ref.Kind, o.Ref.Name, string(o.U.GetUID()), true}
}

func refs(objs []load.Object) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.Ref.String())
	}
	return out
}

func liveRefs(live map[load.ObjectRef][]load.Object) map[string][]string {
	out := make(map[string][]string, len(live))
	for k, v := range live {
		out[k.String()] = refs(v)
	}
	return out
}

func TestResolveChains(t *testing.T) {
	deploy := object("apps/v1", "Deployment", "vllm", "d1")
	rsNew := object("apps/v1", "ReplicaSet", "vllm-new", "rs1", ctl(deploy))
	rsOld := object("apps/v1", "ReplicaSet", "vllm-old", "rs2", ctl(deploy))
	podB := pod("vllm-new-b", "p1", "Running", ctl(rsNew))
	podA := pod("vllm-new-a", "p2", "Pending", ctl(rsNew))
	podDone := pod("vllm-old-c", "p3", "Succeeded", ctl(rsOld))
	podFailed := pod("vllm-old-d", "p4", "Failed", ctl(rsOld))
	podNoPhase := pod("vllm-old-e", "p5", "", ctl(rsOld))

	cron := object("batch/v1", "CronJob", "eval", "c1")
	job := object("batch/v1", "Job", "eval-1", "j1", ctl(cron))
	jobPod := pod("eval-1-x", "p6", "Running", ctl(job))

	rs := object("ray.io/v1", "RayService", "llm", "r1")
	rc := object("ray.io/v1", "RayCluster", "llm-rc", "r2", ctl(rs))
	rayPod := pod("llm-rc-head", "p7", "Running", ctl(rc))

	isvc := object("serving.kserve.io/v1beta1", "InferenceService", "llm", "i1")
	isvcDeploy := object("apps/v1", "Deployment", "llm-predictor", "i2", ctl(isvc))
	isvcRS := object("apps/v1", "ReplicaSet", "llm-predictor-1", "i3", ctl(isvcDeploy))
	isvcPod := pod("llm-predictor-1-x", "p8", "Running", ctl(isvcRS))

	svc := object("v1", "Service", "llm-head-svc", "s1", ctl(rc))

	orphan := pod("vllm-lws-0", "p9", "Running", owner{"leaderworkerset.x-k8s.io/v1", "LeaderWorkerSet", "vllm-lws", "missing", true})
	bare := pod("vllm-debug", "p10", "Running", owner{"apps/v1", "Deployment", "vllm", "d1", false})

	cycA := object("apps/v1", "ReplicaSet", "cyc-a", "ca", owner{"apps/v1", "ReplicaSet", "cyc-b", "cb", true})
	cycB := object("apps/v1", "ReplicaSet", "cyc-b", "cb", owner{"apps/v1", "ReplicaSet", "cyc-a", "ca", true})
	cycPod := pod("cyc-a-x", "p11", "Running", owner{"apps/v1", "ReplicaSet", "cyc-a", "ca", true})
	cycChild := object("apps/v1", "ReplicaSet", "cyc-child", "cc", owner{"apps/v1", "ReplicaSet", "cyc-a", "ca", true})

	mismatch := pod("vllm-new-z", "p12", "Running", owner{"apps/v1", "ReplicaSet", "vllm-new", "other-uid", true})

	lws := object("leaderworkerset.x-k8s.io/v1", "LeaderWorkerSet", "group", "l1")
	lwsSts := object("apps/v1", "StatefulSet", "group-0", "l2", ctl(lws))

	in := []load.Object{
		podB, svc, deploy, rsNew, rsOld, podA, podDone, podFailed, podNoPhase,
		cron, job, jobPod, rs, rc, rayPod, isvc, isvcDeploy, isvcRS, isvcPod,
		orphan, bare, cycA, cycB, cycPod, cycChild, mismatch, lws, lwsSts,
	}
	got := Resolve(in)

	wantObjects := []string{
		"CronJob/ai/eval",
		"Deployment/ai/vllm",
		"InferenceService/ai/llm",
		"LeaderWorkerSet/ai/group",
		"Pod/ai/vllm-debug",
		"Pod/ai/vllm-lws-0",
		"Pod/ai/vllm-new-z",
		"RayService/ai/llm",
		"ReplicaSet/ai/cyc-a",
		"ReplicaSet/ai/cyc-b",
		"Service/ai/llm-head-svc",
		"StatefulSet/ai/group-0",
	}
	if g := refs(got.Objects); !slices.Equal(g, wantObjects) {
		t.Errorf("Objects:\n got %v\nwant %v", g, wantObjects)
	}
	wantLive := map[string][]string{
		"Deployment/ai/vllm":      {"Pod/ai/vllm-new-a", "Pod/ai/vllm-new-b", "Pod/ai/vllm-old-e"},
		"CronJob/ai/eval":         {"Pod/ai/eval-1-x"},
		"RayService/ai/llm":       {"Pod/ai/llm-rc-head"},
		"InferenceService/ai/llm": {"Pod/ai/llm-predictor-1-x"},
		"ReplicaSet/ai/cyc-a":     {"Pod/ai/cyc-a-x"},
	}
	gotLive := liveRefs(got.Live)
	if len(gotLive) != len(wantLive) {
		t.Errorf("Live has %d owners, want %d: %v", len(gotLive), len(wantLive), gotLive)
	}
	for k, w := range wantLive {
		if g := gotLive[k]; !slices.Equal(g, w) {
			t.Errorf("Live[%s] = %v, want %v", k, g, w)
		}
	}
}

func TestResolveSortsObjects(t *testing.T) {
	a := object("v1", "Service", "b", "")
	a.Ref.Namespace = "z"
	b := object("v1", "Service", "a", "")
	c := object("apps/v1", "Deployment", "c", "")
	got := refs(Resolve([]load.Object{a, b, c}).Objects)
	want := []string{"Deployment/ai/c", "Service/ai/a", "Service/z/b"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveStopsAfterTenLinks(t *testing.T) {
	chain := []load.Object{object("apps/v1", "Deployment", "d00", "u00")}
	for i := 1; i <= 12; i++ {
		name := "d" + string(rune('0'+i/10)) + string(rune('0'+i%10))
		chain = append(chain, object("apps/v1", "Deployment", name, "u"+name[1:], ctl(chain[i-1])))
	}
	p := pod("p", "pu", "Running", ctl(chain[12]))
	got := Resolve(append(chain, p))
	if g := liveRefs(got.Live); !slices.Equal(g["Deployment/ai/d03"], []string{"Pod/ai/p"}) || len(g) != 1 {
		t.Errorf("Live = %v, want the pod under Deployment/ai/d03 (10 links up)", g)
	}
	if g := refs(got.Objects); !slices.Equal(g, []string{"Deployment/ai/d00"}) {
		t.Errorf("Objects = %v", g)
	}
}

func TestResolveEmpty(t *testing.T) {
	got := Resolve(nil)
	if got.Objects == nil || len(got.Objects) != 0 || got.Live == nil || len(got.Live) != 0 {
		t.Errorf("got %+v, want empty non-nil", got)
	}
}

func withLabels(o load.Object, labels map[string]string) load.Object {
	o.U.SetLabels(labels)
	return o
}

func TestResolveKeepsPrerequisites(t *testing.T) {
	op := object("apps/v1", "Deployment", "operator", "op")
	cr := object("example.io/v1", "Installation", "default", "cr")
	cilium := withLabels(object("apps/v1", "DaemonSet", "cilium", "ds1", ctl(op)),
		map[string]string{"k8s-app": "cilium", "app.kubernetes.io/name": "cilium-agent"})
	kyverno := withLabels(object("apps/v1", "Deployment", "kyverno-admission-controller", "kd", ctl(op)),
		map[string]string{"app.kubernetes.io/component": "admission-controller", "app.kubernetes.io/part-of": "kyverno"})
	tetragon := withLabels(object("apps/v1", "DaemonSet", "tetragon", "td", ctl(op)),
		map[string]string{"app.kubernetes.io/name": "tetragon", "app.kubernetes.io/component": "agent"})
	plain := object("apps/v1", "DaemonSet", "plain", "pd", ctl(op))
	byCR := object("apps/v1", "StatefulSet", "by-cr", "st", ctl(cr))
	got := Resolve([]load.Object{op, cr, cilium, kyverno, tetragon, plain, byCR})
	want := []string{
		"DaemonSet/ai/cilium",
		"DaemonSet/ai/tetragon",
		"Deployment/ai/kyverno-admission-controller",
		"Deployment/ai/operator",
		"Installation/ai/default",
		"StatefulSet/ai/by-cr",
	}
	if g := refs(got.Objects); !slices.Equal(g, want) {
		t.Errorf("Objects:\n got %v\nwant %v", g, want)
	}
}

func knativeChain(top ...owner) []load.Object {
	ksvc := object("serving.knative.dev/v1", "Service", "app", "k1", top...)
	cfg := object("serving.knative.dev/v1", "Configuration", "app", "k2", ctl(ksvc))
	rev := object("serving.knative.dev/v1", "Revision", "app-00001", "k3", ctl(cfg))
	deploy := object("apps/v1", "Deployment", "app-00001-deployment", "k4", ctl(rev))
	rs := object("apps/v1", "ReplicaSet", "app-00001-deployment-x", "k5", ctl(deploy))
	p := pod("app-00001-deployment-x-1", "k6", "Running", ctl(rs))
	return []load.Object{ksvc, cfg, rev, deploy, rs, p}
}

func TestResolveKnativeApp(t *testing.T) {
	got := Resolve(knativeChain())
	wantObjects := []string{
		"Configuration/ai/app",
		"Deployment/ai/app-00001-deployment",
		"Revision/ai/app-00001",
		"Service/ai/app",
	}
	if g := refs(got.Objects); !slices.Equal(g, wantObjects) {
		t.Errorf("Objects:\n got %v\nwant %v", g, wantObjects)
	}
	gotLive := liveRefs(got.Live)
	if len(gotLive) != 1 || !slices.Equal(gotLive["Deployment/ai/app-00001-deployment"], []string{"Pod/ai/app-00001-deployment-x-1"}) {
		t.Errorf("Live = %v", gotLive)
	}
}

func TestResolveKnativeUnderInferenceService(t *testing.T) {
	isvc := object("serving.kserve.io/v1beta1", "InferenceService", "llm", "i1")
	got := Resolve(append([]load.Object{isvc}, knativeChain(ctl(isvc))...))
	wantObjects := []string{
		"Configuration/ai/app",
		"InferenceService/ai/llm",
		"Revision/ai/app-00001",
		"Service/ai/app",
	}
	if g := refs(got.Objects); !slices.Equal(g, wantObjects) {
		t.Errorf("Objects:\n got %v\nwant %v", g, wantObjects)
	}
	gotLive := liveRefs(got.Live)
	if len(gotLive) != 1 || !slices.Equal(gotLive["InferenceService/ai/llm"], []string{"Pod/ai/app-00001-deployment-x-1"}) {
		t.Errorf("Live = %v", gotLive)
	}
}

func TestResolveSelfOwnedPod(t *testing.T) {
	p := pod("self", "s1", "Running", owner{"v1", "Pod", "self", "s1", true})
	got := Resolve([]load.Object{p})
	if g := liveRefs(got.Live); !slices.Equal(g["Pod/ai/self"], []string{"Pod/ai/self"}) || len(got.Objects) != 0 {
		t.Errorf("Live = %v, Objects = %v", g, refs(got.Objects))
	}
}
