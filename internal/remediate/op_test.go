package remediate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/load"
)

const deploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai
spec:
  template:
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        args: ["serve", "m", "--port", "--trust-remote-code", "8000", "--load-format=pt"]
`

const shmDeploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shm
  namespace: ai
spec:
  template:
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        volumeMounts:
        - name: shm
          mountPath: /dev/shm
      volumes:
      - name: shm
        hostPath:
          path: /dev/shm
`

const rayClusterYAML = `
apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: rc
  namespace: ai
spec:
  headGroupSpec:
    template:
      spec:
        containers:
        - name: ray-head
          image: rayproject/ray:2.50.0
  workerGroupSpecs:
  - groupName: cpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.50.0
  - groupName: gpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.50.0
`

const (
	podSpec    = "/spec/template/spec"
	vllmPath   = podSpec + "/containers/0"
	gpuGroup   = "/spec/workerGroupSpecs/1"
	gpuWorker  = gpuGroup + "/template/spec/containers/0"
	shmVolume  = podSpec + "/volumes/0"
	tmpVolume  = `{"name":"kshield-tmp","emptyDir":{}}`
	memoryShm  = `{"medium":"Memory","sizeLimit":"8Gi"}`
	vllmTarget = `"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"vllm","namespace":"ai"}`
)

func parseObj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func parseJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	return v
}

func canon(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return parseJSON(t, string(b))
}

func assertJSON(t *testing.T, got any, want string) {
	t.Helper()
	if !reflect.DeepEqual(canon(t, got), parseJSON(t, want)) {
		b, _ := json.Marshal(got)
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func at(t *testing.T, obj any, path string) any {
	t.Helper()
	node := obj
	for _, s := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		switch n := node.(type) {
		case map[string]any:
			v, ok := n[s]
			if !ok {
				return nil
			}
			node = v
		case []any:
			i := 0
			for _, c := range s {
				i = i*10 + int(c-'0')
			}
			if i >= len(n) {
				return nil
			}
			node = n[i]
		default:
			return nil
		}
	}
	return node
}

func target(t *testing.T, s string, ops ...Op) Target {
	t.Helper()
	obj := parseObj(t, s)
	md := obj["metadata"].(map[string]any)
	ns, _ := md["namespace"].(string)
	return Target{
		Ref:      load.ObjectRef{APIVersion: obj["apiVersion"].(string), Kind: obj["kind"].(string), Namespace: ns, Name: md["name"].(string)},
		Original: obj,
		Ops:      ops,
	}
}

func TestSetAddsMissingParent(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	got := Set(obj, vllmPath+"/securityContext/runAsNonRoot", true)
	assertJSON(t, got, `{"op":"add","path":"`+vllmPath+`/securityContext","value":{"runAsNonRoot":true}}`)
}

func TestSetReplacesExisting(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	got := Set(obj, vllmPath+"/image", "vllm/vllm-openai:v0.31.1")
	assertJSON(t, got, `{"op":"replace","path":"`+vllmPath+`/image","value":"vllm/vllm-openai:v0.31.1"}`)
}

func TestSetAppendsToMissingList(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	got := Set(obj, podSpec+"/volumes/-", parseJSON(t, tmpVolume))
	assertJSON(t, got, `{"op":"add","path":"`+podSpec+`/volumes","value":[`+tmpVolume+`]}`)
	got = Set(obj, vllmPath+"/args/-", "--x")
	assertJSON(t, got, `{"op":"add","path":"`+vllmPath+`/args/-","value":"--x"}`)
}

func TestRemove(t *testing.T) {
	assertJSON(t, Remove(vllmPath+"/args/3"), `{"op":"remove","path":"`+vllmPath+`/args/3"}`)
}

func TestBuiltinWorkload(t *testing.T) {
	cases := []struct {
		kind, apiVersion string
		want             bool
	}{
		{"Pod", "v1", true},
		{"Deployment", "apps/v1", true},
		{"StatefulSet", "apps/v1", true},
		{"DaemonSet", "apps/v1", true},
		{"ReplicaSet", "apps/v1", true},
		{"Job", "batch/v1", true},
		{"CronJob", "batch/v1", true},
		{"Deployment", "extensions/v1beta1", false},
		{"Pod", "example.com/v1", false},
		{"Service", "v1", false},
		{"RayCluster", "ray.io/v1", false},
		{"InferenceService", "serving.kserve.io/v1beta1", false},
	}
	for _, c := range cases {
		if got := BuiltinWorkload(c.kind, c.apiVersion); got != c.want {
			t.Errorf("BuiltinWorkload(%q, %q) = %v, want %v", c.kind, c.apiVersion, got, c.want)
		}
	}
}

func TestRenderSMPDeployment(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	tg := target(t, deploymentYAML,
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
		Set(obj, podSpec+"/volumes/-", parseJSON(t, tmpVolume)),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[{"op":"test","path":"`+vllmPath+`/name","value":"vllm"}]`)
	assertJSON(t, smp, `{`+vllmTarget+`,"spec":{"template":{"spec":{"containers":[{"name":"vllm","securityContext":{"runAsNonRoot":true}}],"volumes":[`+tmpVolume+`]}}}}`)
}

func TestRenderSMPMergesOps(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	tg := target(t, deploymentYAML,
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
		Set(obj, vllmPath+"/securityContext/allowPrivilegeEscalation", false),
		Set(obj, vllmPath+"/env/-", map[string]any{"name": "HOME", "value": "/kshield/cache"}),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[{"op":"test","path":"`+vllmPath+`/name","value":"vllm"}]`)
	assertJSON(t, smp, `{`+vllmTarget+`,"spec":{"template":{"spec":{"containers":[{"name":"vllm","env":[{"name":"HOME","value":"/kshield/cache"}],"securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true}}]}}}}`)
}

func TestRenderSMPRemoveField(t *testing.T) {
	obj := parseObj(t, shmDeploymentYAML)
	tg := target(t, shmDeploymentYAML,
		Remove(shmVolume+"/hostPath"),
		Set(obj, shmVolume+"/emptyDir", parseJSON(t, memoryShm)),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[{"op":"test","path":"`+shmVolume+`/name","value":"shm"}]`)
	assertJSON(t, smp, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"shm","namespace":"ai"},"spec":{"template":{"spec":{"volumes":[{"name":"shm","hostPath":null,"emptyDir":`+memoryShm+`}]}}}}`)
}

func TestRenderSMPDeleteItem(t *testing.T) {
	tg := target(t, shmDeploymentYAML,
		Remove(podSpec+"/containers/0/volumeMounts/0"),
		Remove(shmVolume),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+vllmPath+`/volumeMounts/0/mountPath","value":"/dev/shm"},
		{"op":"test","path":"`+shmVolume+`/name","value":"shm"}
	]`)
	assertJSON(t, smp, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"shm","namespace":"ai"},"spec":{"template":{"spec":{"containers":[{"name":"vllm","volumeMounts":[{"mountPath":"/dev/shm","$patch":"delete"}]}],"volumes":[{"name":"shm","$patch":"delete"}]}}}}`)
}

func TestRenderSMPPodAndCronJobRoots(t *testing.T) {
	pod := `
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
  - name: c
`
	obj := parseObj(t, pod)
	smp, j, err := Render(target(t, pod, Set(obj, "/spec/hostPID", false)))
	if err != nil || len(j) != 0 {
		t.Fatalf("err %v, 6902 %v", err, j)
	}
	assertJSON(t, smp, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"hostPID":false}}`)

	cron := `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cj
  namespace: ai
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: c
`
	obj = parseObj(t, cron)
	root := "/spec/jobTemplate/spec/template/spec"
	smp, j, err = Render(target(t, cron, Set(obj, root+"/automountServiceAccountToken", false), Set(obj, "/spec/suspend", true)))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"cj","namespace":"ai"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"automountServiceAccountToken":false}}}}}}`)
	assertJSON(t, j, `[{"op":"add","path":"/spec/suspend","value":true}]`)
}

func TestRender6902RayCluster(t *testing.T) {
	obj := parseObj(t, rayClusterYAML)
	tg := target(t, rayClusterYAML, Set(obj, gpuWorker+"/securityContext", map[string]any{"runAsNonRoot": true}))
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+gpuGroup+`/groupName","value":"gpu"},
		{"op":"test","path":"`+gpuWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+gpuWorker+`/securityContext","value":{"runAsNonRoot":true}}
	]`)
}

func TestRender6902ArgsRemoval(t *testing.T) {
	tg := target(t, deploymentYAML, Remove(vllmPath+"/args/3"), Remove(vllmPath+"/args/5"))
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+vllmPath+`/args/3","value":"--trust-remote-code"},
		{"op":"test","path":"`+vllmPath+`/args/5","value":"--load-format=pt"},
		{"op":"remove","path":"`+vllmPath+`/args/5"},
		{"op":"remove","path":"`+vllmPath+`/args/3"}
	]`)
}

func TestRenderMixedSMPAnd6902(t *testing.T) {
	obj := parseObj(t, deploymentYAML)
	tg := target(t, deploymentYAML,
		Remove(vllmPath+"/args/3"),
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
		Set(obj, vllmPath+"/args/5", "--load-format=safetensors"),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, `{`+vllmTarget+`,"spec":{"template":{"spec":{"containers":[{"name":"vllm","securityContext":{"runAsNonRoot":true}}]}}}}`)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+vllmPath+`/args/3","value":"--trust-remote-code"},
		{"op":"test","path":"`+vllmPath+`/args/5","value":"--load-format=pt"},
		{"op":"replace","path":"`+vllmPath+`/args/5","value":"--load-format=safetensors"},
		{"op":"remove","path":"`+vllmPath+`/args/3"}
	]`)
}

func TestRenderDedupesTests(t *testing.T) {
	obj := parseObj(t, rayClusterYAML)
	tg := target(t, rayClusterYAML,
		Set(obj, gpuWorker+"/securityContext/runAsNonRoot", true),
		Set(obj, gpuWorker+"/env/-", map[string]any{"name": "HOME", "value": "/kshield/cache"}),
	)
	_, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+gpuGroup+`/groupName","value":"gpu"},
		{"op":"test","path":"`+gpuWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+gpuWorker+`/securityContext","value":{"runAsNonRoot":true}},
		{"op":"add","path":"`+gpuWorker+`/env","value":[{"name":"HOME","value":"/kshield/cache"}]}
	]`)
}

func TestRender6902MergesAddsOfMissingParent(t *testing.T) {
	obj := parseObj(t, rayClusterYAML)
	tg := target(t, rayClusterYAML,
		Set(obj, gpuWorker+"/securityContext/runAsNonRoot", true),
		Set(obj, gpuWorker+"/securityContext/capabilities/drop", []string{"ALL"}),
		Set(obj, gpuWorker+"/volumeMounts/-", map[string]any{"name": "a", "mountPath": "/a"}),
		Set(obj, gpuWorker+"/volumeMounts/-", map[string]any{"name": "b", "mountPath": "/b"}),
		Set(obj, gpuWorker+"/securityContext/runAsNonRoot", true),
	)
	_, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+gpuGroup+`/groupName","value":"gpu"},
		{"op":"test","path":"`+gpuWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+gpuWorker+`/securityContext","value":{"runAsNonRoot":true,"capabilities":{"drop":["ALL"]}}},
		{"op":"add","path":"`+gpuWorker+`/volumeMounts","value":[{"name":"a","mountPath":"/a"},{"name":"b","mountPath":"/b"}]}
	]`)
}

func TestRender6902TestsWholeElementAndPort(t *testing.T) {
	svc := `
apiVersion: v1
kind: Service
metadata:
  name: s
  namespace: ai
spec:
  type: NodePort
  ports:
  - port: 8000
    nodePort: 30080
`
	_, j, err := Render(target(t, svc, Remove("/spec/ports/0/nodePort")))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[{"op":"test","path":"/spec/ports/0/port","value":8000},{"op":"remove","path":"/spec/ports/0/nodePort"}]`)

	np := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: ai
spec:
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/8
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
`
	_, j, err = Render(target(t, np, Remove("/spec/egress/1")))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[{"op":"test","path":"/spec/egress/1","value":{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}},{"op":"remove","path":"/spec/egress/1"}]`)
}

func TestRenderRemovesDeepestFirst(t *testing.T) {
	two := `
apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: rc
spec:
  workerGroupSpecs:
  - groupName: gpu
    template:
      spec:
        containers:
        - name: a
          args: ["x1", "x2"]
        - name: b
`
	base := "/spec/workerGroupSpecs/0/template/spec/containers"
	_, j, err := Render(target(t, two, Remove(base+"/0"), Remove(base+"/0/args/0"), Remove(base+"/1")))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/workerGroupSpecs/0/groupName","value":"gpu"},
		{"op":"test","path":"`+base+`/0/name","value":"a"},
		{"op":"test","path":"`+base+`/1/name","value":"b"},
		{"op":"remove","path":"`+base+`/1"},
		{"op":"remove","path":"`+base+`/0"}
	]`)
}

func TestRenderErrors(t *testing.T) {
	cases := map[string]Op{
		"missing path":   Remove(gpuWorker + "/securityContext"),
		"missing parent": {Op: "add", Path: gpuWorker + "/securityContext/runAsNonRoot", Value: true},
		"bad op":         {Op: "move", Path: gpuWorker + "/name"},
		"bad path":       {Op: "remove", Path: "spec"},
	}
	for name, op := range cases {
		if _, _, err := Render(target(t, rayClusterYAML, op)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	smp, j, err := Render(target(t, deploymentYAML))
	if err != nil || smp != nil || j != nil {
		t.Fatalf("smp %v, 6902 %v, err %v", smp, j, err)
	}
}

const initOrderYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ordered
  namespace: ai
spec:
  selector:
    matchLabels:
      app: ordered
  template:
    metadata:
      labels:
        app: ordered
    spec:
      initContainers:
      - name: i1
        image: busybox:1.37.0
      - name: i2
        image: busybox:1.37.0
      - name: i3
        image: busybox:1.37.0
      containers:
      - name: c1
        image: busybox:1.37.0
        env:
        - name: A
          value: "1"
        - name: B
          value: "2"
      - name: c2
        image: busybox:1.37.0
`

func TestRenderSMPKeepsListOrder(t *testing.T) {
	obj := parseObj(t, initOrderYAML)
	tg := target(t, initOrderYAML,
		Set(obj, podSpec+"/initContainers/1/securityContext/runAsNonRoot", true),
		Set(obj, podSpec+"/containers/1/securityContext/runAsNonRoot", true),
		Set(obj, podSpec+"/containers/0/env/-", map[string]any{"name": "HOME", "value": "/kshield/cache"}),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, at(t, smp, podSpec), `{
		"initContainers":[{"name":"i1"},{"name":"i2","securityContext":{"runAsNonRoot":true}},{"name":"i3"}],
		"containers":[{"name":"c1","env":[{"name":"A"},{"name":"B"},{"name":"HOME","value":"/kshield/cache"}]},{"name":"c2","securityContext":{"runAsNonRoot":true}}]
	}`)
	assertJSON(t, j, `[
		{"op":"test","path":"`+podSpec+`/initContainers/0/name","value":"i1"},
		{"op":"test","path":"`+podSpec+`/initContainers/1/name","value":"i2"},
		{"op":"test","path":"`+podSpec+`/initContainers/2/name","value":"i3"},
		{"op":"test","path":"`+podSpec+`/containers/0/name","value":"c1"},
		{"op":"test","path":"`+podSpec+`/containers/1/name","value":"c2"},
		{"op":"test","path":"`+podSpec+`/containers/0/env/0/name","value":"A"},
		{"op":"test","path":"`+podSpec+`/containers/0/env/1/name","value":"B"}
	]`)
}

const (
	rayListsWorker     = "/spec/workerGroupSpecs/0/template/spec/containers/0"
	rayListsContainers = `        - name: ray-worker
          image: rayproject/ray:2.50.0
          args: ["--block"]
          env:
          - name: A
            value: "1"
        - name: sidecar
          image: busybox:1.37.0
`
	rayListsSwapped = `        - name: sidecar
          image: busybox:1.37.0
        - name: ray-worker
          image: rayproject/ray:2.50.0
          args: ["--block"]
          env:
          - name: A
            value: "1"
`
	rayListsYAML = `
apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: rl
  namespace: ai
spec:
  workerGroupSpecs:
  - groupName: gpu
    template:
      spec:
        containers:
` + rayListsContainers
)

func TestRender6902AppendsToExistingLists(t *testing.T) {
	obj := parseObj(t, rayListsYAML)
	home := map[string]any{"name": "HOME", "value": "/kshield/cache"}
	tg := target(t, rayListsYAML,
		Set(obj, rayListsWorker+"/env/-", home),
		Set(obj, rayListsWorker+"/env/-", map[string]any{"name": "HF_HOME", "value": "/kshield/cache/huggingface"}),
		Set(obj, rayListsWorker+"/args/-", "--load-format"),
		Set(obj, rayListsWorker+"/args/-", "safetensors"),
		Set(obj, rayListsWorker+"/env/-", home),
	)
	_, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/workerGroupSpecs/0/groupName","value":"gpu"},
		{"op":"test","path":"`+rayListsWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+rayListsWorker+`/env/-","value":{"name":"HOME","value":"/kshield/cache"}},
		{"op":"add","path":"`+rayListsWorker+`/env/-","value":{"name":"HF_HOME","value":"/kshield/cache/huggingface"}},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"--load-format"},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"safetensors"}
	]`)
}

func TestRenderListReplaceGoesTo6902(t *testing.T) {
	dep := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai
spec:
  template:
    spec:
      containers:
      - name: vllm
        ports:
        - containerPort: 8000
        securityContext:
          capabilities:
            drop: ["NET_RAW"]
`
	obj := parseObj(t, dep)
	tg := target(t, dep,
		Set(obj, vllmPath+"/ports", []any{map[string]any{"containerPort": 9000}}),
		Set(obj, vllmPath+"/securityContext/capabilities/drop", []string{"ALL"}),
	)
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"replace","path":"`+vllmPath+`/ports","value":[{"containerPort":9000}]},
		{"op":"replace","path":"`+vllmPath+`/securityContext/capabilities/drop","value":["ALL"]}
	]`)
}

func TestOpMarshalKeepsNullValue(t *testing.T) {
	b, err := json.Marshal([]Op{
		{Op: OpAdd, Path: "/a", Value: nil},
		{Op: OpReplace, Path: "/b", Value: nil},
		{Op: OpTest, Path: "/c", Value: nil},
		{Op: OpRemove, Path: "/d", Value: "ignored"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"op":"add","path":"/a","value":null},{"op":"replace","path":"/b","value":null},{"op":"test","path":"/c","value":null},{"op":"remove","path":"/d"}]`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	y, err := yaml.Marshal([]Op{{Op: OpAdd, Path: "/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(y) != "- op: add\n  path: /a\n  value: null\n" {
		t.Fatalf("yaml: %q", y)
	}
}

const envDeploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envd
  namespace: ai
spec:
  selector:
    matchLabels:
      app: envd
  template:
    metadata:
      labels:
        app: envd
    spec:
      initContainers:
      - name: i1
        image: busybox:1.37.0
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        env:
        - name: A
          value: "1"
        - name: B
          value: "2"
`

const (
	envPath    = vllmPath + "/env"
	envTarget  = `"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"envd","namespace":"ai"}`
	homeEnv    = `{"name":"HOME","value":"/kshield/cache"}`
	envSMPOnly = `{` + envTarget + `,"spec":{"template":{"spec":{"containers":[{"name":"vllm","securityContext":{"runAsNonRoot":true}}]}}}}`
)

func renameTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, envDeploymentYAML)
	return target(t, envDeploymentYAML,
		Set(obj, envPath+"/1", map[string]any{"name": "B2", "value": "2"}),
		Set(obj, envPath+"/-", parseJSON(t, homeEnv)),
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
	)
}

func replaceListTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, envDeploymentYAML)
	return target(t, envDeploymentYAML,
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
		Set(obj, envPath+"/-", parseJSON(t, homeEnv)),
		Set(obj, envPath, []any{map[string]any{"name": "C", "value": "3"}}),
	)
}

func TestRenderKeyedItemRenameRoutesListTo6902(t *testing.T) {
	smp, j, err := Render(renameTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, envSMPOnly)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+envPath+`/1/name","value":"B"},
		{"op":"replace","path":"`+envPath+`/1","value":{"name":"B2","value":"2"}},
		{"op":"add","path":"`+envPath+`/-","value":`+homeEnv+`}
	]`)
}

func TestRenderWholeListReplaceRoutesListTo6902(t *testing.T) {
	smp, j, err := Render(replaceListTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, envSMPOnly)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"replace","path":"`+envPath+`","value":[{"name":"C","value":"3"}]},
		{"op":"add","path":"`+envPath+`/-","value":`+homeEnv+`}
	]`)
}

func TestRenderInsertAtExistingIndex(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	insert := Op{Op: OpAdd, Path: podSpec + "/initContainers/0", Value: map[string]any{"name": "i0", "image": "busybox:1.37.0"}}
	smp, j, err := Render(target(t, envDeploymentYAML, insert, Set(obj, vllmPath+"/securityContext/runAsNonRoot", true)))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, envSMPOnly)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+podSpec+`/initContainers/0/name","value":"i1"},
		{"op":"add","path":"`+podSpec+`/initContainers/0","value":{"name":"i0","image":"busybox:1.37.0"}}
	]`)
	_, _, err = Render(target(t, envDeploymentYAML, insert, Set(obj, podSpec+"/initContainers/0/securityContext/runAsNonRoot", true)))
	if err == nil || !strings.Contains(err.Error(), "inserts into") {
		t.Fatalf("insert with an edit of the same list: err %v", err)
	}
}

func TestRender6902DuplicateKeyAppendsFail(t *testing.T) {
	obj := parseObj(t, rayListsYAML)
	_, _, err := Render(target(t, rayListsYAML,
		Set(obj, rayListsWorker+"/env/-", parseJSON(t, homeEnv)),
		Set(obj, rayListsWorker+"/env/-", map[string]any{"name": "HOME", "value": "/other"}),
	))
	if err == nil || !strings.Contains(err.Error(), "two items with name HOME") {
		t.Fatalf("err %v", err)
	}
	obj = parseObj(t, rayClusterYAML)
	_, _, err = Render(target(t, rayClusterYAML,
		Set(obj, gpuWorker+"/volumeMounts/-", map[string]any{"name": "a", "mountPath": "/a"}),
		Set(obj, gpuWorker+"/volumeMounts/-", map[string]any{"name": "b", "mountPath": "/a"}),
	))
	if err == nil || !strings.Contains(err.Error(), "two items with mountPath /a") {
		t.Fatalf("err %v", err)
	}
}

func TestRender6902KeepsRepeatedArgs(t *testing.T) {
	obj := parseObj(t, rayListsYAML)
	_, j, err := Render(target(t, rayListsYAML,
		Set(obj, rayListsWorker+"/args/-", "--a"),
		Set(obj, rayListsWorker+"/args/-", "1"),
		Set(obj, rayListsWorker+"/args/-", "--b"),
		Set(obj, rayListsWorker+"/args/-", "1"),
	))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/workerGroupSpecs/0/groupName","value":"gpu"},
		{"op":"test","path":"`+rayListsWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"--a"},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"1"},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"--b"},
		{"op":"add","path":"`+rayListsWorker+`/args/-","value":"1"}
	]`)
	obj = parseObj(t, rayClusterYAML)
	_, j, err = Render(target(t, rayClusterYAML,
		Set(obj, gpuWorker+"/args/-", "--a"),
		Set(obj, gpuWorker+"/args/-", "1"),
		Set(obj, gpuWorker+"/args/-", "--b"),
		Set(obj, gpuWorker+"/args/-", "1"),
	))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+gpuGroup+`/groupName","value":"gpu"},
		{"op":"test","path":"`+gpuWorker+`/name","value":"ray-worker"},
		{"op":"add","path":"`+gpuWorker+`/args","value":["--a","1","--b","1"]}
	]`)
}

func TestRenderEditThroughReplacedListFails(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	cd := []any{map[string]any{"name": "C", "value": "3"}, map[string]any{"name": "D", "value": "4"}}
	cases := map[string]Op{
		"set item field": Set(obj, envPath+"/0/value", "x"),
		"remove item":    Remove(envPath + "/0"),
	}
	for name, op := range cases {
		_, _, err := Render(target(t, envDeploymentYAML, Set(obj, envPath, cd), op))
		if err == nil || !strings.Contains(err.Error(), "goes through an index") {
			t.Fatalf("%s: err %v", name, err)
		}
	}
	_, j, err := Render(target(t, envDeploymentYAML, Set(obj, envPath, cd), Set(obj, envPath+"/-", parseJSON(t, homeEnv))))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"replace","path":"`+envPath+`","value":[{"name":"C","value":"3"},{"name":"D","value":"4"}]},
		{"op":"add","path":"`+envPath+`/-","value":`+homeEnv+`}
	]`)
}

func TestRender6902AppendClashesWithListKeys(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	rename := Set(obj, envPath+"/1", map[string]any{"name": "B2", "value": "2"})
	_, _, err := Render(target(t, envDeploymentYAML, rename, Set(obj, envPath+"/-", map[string]any{"name": "A", "value": "9"})))
	if err == nil || !strings.Contains(err.Error(), "name A is already in the list") {
		t.Fatalf("append A after rename: err %v", err)
	}
	_, _, err = Render(target(t, envDeploymentYAML, rename, Set(obj, envPath+"/-", map[string]any{"name": "B2", "value": "9"})))
	if err == nil || !strings.Contains(err.Error(), "name B2 is already in the list") {
		t.Fatalf("append B2 after rename: err %v", err)
	}
	_, j, err := Render(target(t, envDeploymentYAML, rename, Set(obj, envPath+"/-", map[string]any{"name": "B", "value": "9"})))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j[len(j)-1], `{"op":"add","path":"`+envPath+`/-","value":{"name":"B","value":"9"}}`)
	_, _, err = Render(target(t, envDeploymentYAML,
		Set(obj, envPath+"/0/name", "A2"),
		Set(obj, envPath+"/-", map[string]any{"name": "A2", "value": "9"}),
	))
	if err == nil || !strings.Contains(err.Error(), "name A2 is already in the list") {
		t.Fatalf("append A2 after key rename: err %v", err)
	}
	ray := parseObj(t, rayListsYAML)
	_, _, err = Render(target(t, rayListsYAML, Set(ray, rayListsWorker+"/env/-", map[string]any{"name": "A", "value": "9"})))
	if err == nil || !strings.Contains(err.Error(), "name A is already in the list") {
		t.Fatalf("CR append A: err %v", err)
	}
}

func TestRenderMergeKeyRenameGoesTo6902(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	smp, j, err := Render(target(t, envDeploymentYAML, Set(obj, envPath+"/0/name", "A2")))
	if err != nil {
		t.Fatal(err)
	}
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+envPath+`/0/name","value":"A"},
		{"op":"replace","path":"`+envPath+`/0/name","value":"A2"}
	]`)
}

func TestRenderEditUnderRemovedPathFails(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	_, _, err := Render(target(t, envDeploymentYAML, Remove(envPath), Set(obj, envPath+"/-", parseJSON(t, homeEnv))))
	if err == nil || !strings.Contains(err.Error(), "under removed") {
		t.Fatalf("err %v", err)
	}
}

const dnsServiceYAML = `
apiVersion: v1
kind: Service
metadata:
  name: dns
  namespace: ai
spec:
  ports:
  - name: dns-tcp
    port: 53
`

func intTarget(t *testing.T, s string, ops ...Op) Target {
	t.Helper()
	tg := target(t, s, ops...)
	v, err := jsonValue(tg.Original)
	if err != nil {
		t.Fatal(err)
	}
	tg.Original = v.(map[string]any)
	return tg
}

func TestRenderEditUnderWrittenAncestorFails(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	container := Set(obj, vllmPath, map[string]any{"name": "vllm", "image": "vllm/vllm-openai:v0.31.0", "env": []any{
		map[string]any{"name": "C", "value": "3"},
		map[string]any{"name": "D", "value": "4"},
	}})
	cases := map[string][]Op{
		"P1 set env item field":      {container, Set(obj, envPath+"/0/value", "x")},
		"P1 set before the write":    {Set(obj, envPath+"/0/value", "x"), container},
		"P2 remove env item":         {container, Remove(envPath + "/0")},
		"P3 append into written env": {container, Set(obj, envPath+"/-", map[string]any{"name": "C", "value": "9"})},
	}
	for name, ops := range cases {
		_, _, err := Render(target(t, envDeploymentYAML, ops...))
		if err == nil || !strings.Contains(err.Error(), "which replace "+vllmPath+" writes whole") {
			t.Errorf("%s: err %v", name, err)
		}
	}
	ray := parseObj(t, rayClusterYAML)
	_, _, err := Render(target(t, rayClusterYAML,
		Set(ray, gpuWorker+"/image", "rayproject/ray:2.50.1"),
		Set(ray, gpuWorker, map[string]any{"name": "ray-worker", "image": "rayproject/ray:2.50.0", "securityContext": map[string]any{"runAsNonRoot": true}}),
	))
	if err == nil || !strings.Contains(err.Error(), "which replace "+gpuWorker+" writes whole") {
		t.Errorf("O2 field edit before the map write: err %v", err)
	}
}

func TestRenderPortKeysIncludeProtocol(t *testing.T) {
	udp := map[string]any{"name": "dns-udp", "port": 53, "protocol": "UDP"}
	tcp := map[string]any{"name": "dns-tcp2", "port": 53, "protocol": "TCP"}
	for name, tg := range map[string]func(ops ...Op) Target{
		"float base": func(ops ...Op) Target { return target(t, dnsServiceYAML, ops...) },
		"int base":   func(ops ...Op) Target { return intTarget(t, dnsServiceYAML, ops...) },
	} {
		obj := tg().Original
		_, j, err := Render(tg(Set(obj, "/spec/ports/-", udp)))
		if err != nil {
			t.Fatalf("%s: append 53/UDP: %v", name, err)
		}
		assertJSON(t, j, `[{"op":"add","path":"/spec/ports/-","value":{"name":"dns-udp","port":53,"protocol":"UDP"}}]`)
		_, _, err = Render(tg(Set(obj, "/spec/ports/-", tcp)))
		if err == nil || !strings.Contains(err.Error(), "port 53/TCP is already in the list") {
			t.Errorf("%s: append 53/TCP: err %v", name, err)
		}
		_, _, err = Render(tg(Set(obj, "/spec/ports/-", udp), Set(obj, "/spec/ports/-", map[string]any{"name": "dns-udp2", "port": 53, "protocol": "UDP"})))
		if err == nil || !strings.Contains(err.Error(), "two items with port 53/UDP added") {
			t.Errorf("%s: two 53/UDP appends: err %v", name, err)
		}
	}
}

func removedKeyReaddedTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, envDeploymentYAML)
	return target(t, envDeploymentYAML,
		Remove(envPath+"/0"),
		Set(obj, envPath+"/-", map[string]any{"name": "A", "value": "9"}),
		Set(obj, vllmPath+"/securityContext/runAsNonRoot", true),
	)
}

func TestRenderRemovedKeyReaddedGoesTo6902(t *testing.T) {
	smp, j, err := Render(removedKeyReaddedTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, envSMPOnly)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+envPath+`/0/name","value":"A"},
		{"op":"add","path":"`+envPath+`/-","value":{"name":"A","value":"9"}},
		{"op":"remove","path":"`+envPath+`/0"}
	]`)
}

func TestRenderDuplicateMergeKeysGoTo6902(t *testing.T) {
	dup := strings.Replace(envDeploymentYAML, "        - name: B\n", "        - name: A\n", 1)
	if dup == envDeploymentYAML {
		t.Fatal("replace did not apply")
	}
	obj := parseObj(t, dup)
	smp, j, err := Render(target(t, dup, Set(obj, envPath+"/1/value", "x"), Set(obj, vllmPath+"/securityContext/runAsNonRoot", true)))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, smp, envSMPOnly)
	assertJSON(t, j, `[
		{"op":"test","path":"`+vllmPath+`/name","value":"vllm"},
		{"op":"test","path":"`+envPath+`/1/name","value":"A"},
		{"op":"replace","path":"`+envPath+`/1/value","value":"x"}
	]`)
}

func TestRenderSMPAppendOfExistingKeyFails(t *testing.T) {
	obj := parseObj(t, envDeploymentYAML)
	_, _, err := Render(target(t, envDeploymentYAML, Set(obj, envPath+"/-", map[string]any{"name": "A", "value": "9"})))
	if err == nil || !strings.Contains(err.Error(), "name A is already in the list") {
		t.Fatalf("err %v", err)
	}
}

func appendBeforeWholeWriteTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, rayListsYAML)
	return target(t, rayListsYAML,
		Set(obj, rayListsWorker+"/env/-", parseJSON(t, homeEnv)),
		Set(obj, rayListsWorker+"/env", []any{map[string]any{"name": "C", "value": "3"}}),
	)
}

func TestRender6902AppendsAfterWholeWrite(t *testing.T) {
	_, j, err := Render(appendBeforeWholeWriteTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/workerGroupSpecs/0/groupName","value":"gpu"},
		{"op":"test","path":"`+rayListsWorker+`/name","value":"ray-worker"},
		{"op":"replace","path":"`+rayListsWorker+`/env","value":[{"name":"C","value":"3"}]},
		{"op":"add","path":"`+rayListsWorker+`/env/-","value":`+homeEnv+`}
	]`)
}

func TestRenderSamePathConflicts(t *testing.T) {
	cases := map[string]Target{
		"two adds on an existing map": target(t, shmDeploymentYAML,
			Op{Op: OpAdd, Path: shmVolume + "/hostPath", Value: map[string]any{"path": "/a"}},
			Op{Op: OpAdd, Path: shmVolume + "/hostPath", Value: map[string]any{"type": "Directory"}},
		),
		"two inserts at one args index": target(t, deploymentYAML,
			Op{Op: OpAdd, Path: vllmPath + "/args/0", Value: "--a"},
			Op{Op: OpAdd, Path: vllmPath + "/args/0", Value: "--b"},
		),
		"two identical inserts at one args index": target(t, deploymentYAML,
			Op{Op: OpAdd, Path: vllmPath + "/args/0", Value: "--x"},
			Op{Op: OpAdd, Path: vllmPath + "/args/0", Value: "--x"},
		),
	}
	for name, tg := range cases {
		_, _, err := Render(tg)
		if err == nil || !strings.Contains(err.Error(), "conflicting ops on") {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

type nestedRemove struct {
	base, kind, name, path string
	outer, inner           Op
}

func nestedRemoves() map[string]nestedRemove {
	return map[string]nestedRemove{
		"SMP hostPath": {secondDeploymentYAML, "Deployment", "shm", shmVolume + "/hostPath", Remove(shmVolume + "/hostPath"), Remove(shmVolume + "/hostPath/path")},
		"SMP env":      {secondDeploymentYAML, "Deployment", "shm", vllmPath + "/env", Remove(vllmPath + "/env"), Remove(vllmPath + "/env/0")},
		"CR env":       {rayListsYAML, "RayCluster", "rl", rayListsWorker + "/env", Remove(rayListsWorker + "/env"), Remove(rayListsWorker + "/env/0")},
	}
}

func TestRenderDropsRemoveUnderRemove(t *testing.T) {
	for name, c := range nestedRemoves() {
		wantSMP, wantJ, err := Render(target(t, c.base, c.outer))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, ops := range [][]Op{{c.outer, c.inner}, {c.inner, c.outer}} {
			smp, j, err := Render(target(t, c.base, ops...))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !reflect.DeepEqual(canon(t, smp), canon(t, wantSMP)) || !reflect.DeepEqual(canon(t, j), canon(t, wantJ)) {
				gs, _ := json.Marshal(smp)
				gj, _ := json.Marshal(j)
				t.Errorf("%s, %s first: smp %s, 6902 %s", name, ops[0].Path, gs, gj)
			}
		}
	}
	smp, _, err := Render(target(t, secondDeploymentYAML, Remove(shmVolume+"/hostPath/path"), Remove(shmVolume+"/hostPath")))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, at(t, smp, podSpec+"/volumes"), `[{"name":"shm","hostPath":null}]`)
}

func TestRender6902PortTestsIncludeProtocol(t *testing.T) {
	_, j, err := Render(target(t, dnsNodePortYAML, Remove("/spec/ports/1/nodePort")))
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/ports/1/port","value":53},
		{"op":"test","path":"/spec/ports/1/protocol","value":"UDP"},
		{"op":"remove","path":"/spec/ports/1/nodePort"}
	]`)
}

const dnsNodePortYAML = `
apiVersion: v1
kind: Service
metadata:
  name: dns
  namespace: ai
spec:
  type: NodePort
  selector:
    app: dns
  ports:
  - name: dns-tcp
    port: 53
    protocol: TCP
    nodePort: 30053
  - name: dns-udp
    port: 53
    protocol: UDP
    nodePort: 30054
`

func TestRenderSMPRemoveUnderRemovedItem(t *testing.T) {
	for _, ops := range [][]Op{
		{Remove(shmVolume + "/hostPath"), Remove(shmVolume)},
		{Remove(shmVolume), Remove(shmVolume + "/hostPath")},
	} {
		smp, _, err := Render(target(t, shmDeploymentYAML, ops...))
		if err != nil {
			t.Fatal(err)
		}
		assertJSON(t, at(t, smp, podSpec+"/volumes"), `[{"name":"shm","$patch":"delete"}]`)
	}
}
