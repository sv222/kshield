package remediate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
)

const secondDeploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shm
  namespace: ai
spec:
  selector:
    matchLabels:
      app: shm
  template:
    metadata:
      labels:
        app: shm
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        securityContext:
          capabilities:
            drop: ["NET_RAW"]
        env:
        - name: KEEP
          value: "1"
        - name: DROP
          value: "2"
        volumeMounts:
        - name: shm
          mountPath: /dev/shm
      volumes:
      - name: shm
        hostPath:
          path: /dev/shm
`

const firstDeploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai
spec:
  selector:
    matchLabels:
      app: vllm
  template:
    metadata:
      labels:
        app: vllm
    spec:
      containers:
      - name: sidecar
        image: busybox:1.37.0
      - name: vllm
        image: vllm/vllm-openai:v0.31.0
        args: ["serve", "m", "--trust-remote-code", "--port", "8000"]
`

const swappedRayClusterYAML = `
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
  - groupName: gpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.50.0
  - groupName: cpu
    template:
      spec:
        containers:
        - name: ray-worker
          image: rayproject/ray:2.50.0
`

func kbuild(t *testing.T, files map[string]string) ([]map[string]any, error) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), dir)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, r := range m.Resources() {
		b, err := r.AsYAML()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, parseObj(t, string(b)))
	}
	return out, nil
}

func byName(t *testing.T, objs []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, o := range objs {
		if o["kind"] == kind && o["metadata"].(map[string]any)["name"] == name {
			return o
		}
	}
	t.Fatalf("%s/%s not in output", kind, name)
	return nil
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func render(t *testing.T, tg Target) (map[string]any, []Op) {
	t.Helper()
	smp, j, err := Render(tg)
	if err != nil {
		t.Fatal(err)
	}
	return smp, j
}

func buildPatched(t *testing.T, base string, tgs ...Target) ([]map[string]any, error) {
	t.Helper()
	files := map[string]string{"base.yaml": base}
	k := "resources:\n- base.yaml\npatches:\n"
	var smps []string
	for i, tg := range tgs {
		smp, j := render(t, tg)
		if len(j) > 0 {
			name := fmt.Sprintf("p%d-6902.yaml", i)
			files[name] = marshal(t, j)
			group, version, found := strings.Cut(tg.Ref.APIVersion, "/")
			if !found {
				group, version = "", group
			}
			k += fmt.Sprintf("- path: %s\n  target:\n    group: %q\n    version: %s\n    kind: %s\n    name: %s\n", name, group, version, tg.Ref.Kind, tg.Ref.Name)
			if tg.Ref.Namespace != "" {
				k += "    namespace: " + tg.Ref.Namespace + "\n"
			}
		}
		if smp != nil {
			smps = append(smps, marshal(t, smp))
		}
	}
	if len(smps) > 0 {
		files["workload-patch.yaml"] = strings.Join(smps, "---\n")
		k += "- path: workload-patch.yaml\n"
	}
	files["kustomization.yaml"] = k
	return kbuild(t, files)
}

func assertTestFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("build succeeded on a changed base")
	}
	if !strings.Contains(err.Error(), "test") {
		t.Fatalf("error does not mention test: %v", err)
	}
}

func TestKustomizeMultiDocSMP(t *testing.T) {
	a := parseObj(t, firstDeploymentYAML)
	ta := target(t, firstDeploymentYAML,
		Set(a, podSpec+"/containers/1/securityContext/runAsNonRoot", true),
		Set(a, podSpec+"/volumes/-", parseJSON(t, tmpVolume)),
	)
	b := parseObj(t, secondDeploymentYAML)
	tb := target(t, secondDeploymentYAML,
		Remove(shmVolume+"/hostPath"),
		Set(b, shmVolume+"/emptyDir", parseJSON(t, memoryShm)),
		Set(b, vllmPath+"/securityContext/capabilities/drop", []string{"ALL"}),
		Remove(vllmPath+"/env/1"),
	)
	if smp, _ := render(t, ta); smp == nil {
		t.Fatal("no SMP for vllm")
	}
	if smp, _ := render(t, tb); smp == nil {
		t.Fatal("no SMP for shm")
	}
	objs, err := buildPatched(t, firstDeploymentYAML+"---\n"+secondDeploymentYAML, ta, tb)
	if err != nil {
		t.Fatal(err)
	}
	gotA := byName(t, objs, "Deployment", "vllm")
	assertJSON(t, at(t, gotA, podSpec+"/containers/0"), `{"name":"sidecar","image":"busybox:1.37.0"}`)
	assertJSON(t, at(t, gotA, podSpec+"/containers/1/securityContext"), `{"runAsNonRoot":true}`)
	assertJSON(t, at(t, gotA, podSpec+"/containers/1/args"), `["serve","m","--trust-remote-code","--port","8000"]`)
	assertJSON(t, at(t, gotA, podSpec+"/volumes"), `[`+tmpVolume+`]`)
	gotB := byName(t, objs, "Deployment", "shm")
	assertJSON(t, at(t, gotB, podSpec+"/volumes"), `[{"name":"shm","emptyDir":`+memoryShm+`}]`)
	assertJSON(t, at(t, gotB, vllmPath+"/securityContext"), `{"capabilities":{"drop":["ALL"]}}`)
	assertJSON(t, at(t, gotB, vllmPath+"/env"), `[{"name":"KEEP","value":"1"}]`)
	assertJSON(t, at(t, gotB, vllmPath+"/volumeMounts"), `[{"name":"shm","mountPath":"/dev/shm"}]`)
}

func TestKustomizeSMPDeleteItem(t *testing.T) {
	objs, err := buildPatched(t, secondDeploymentYAML, target(t, secondDeploymentYAML, Remove(vllmPath+"/volumeMounts/0"), Remove(shmVolume)))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "shm")
	if v := at(t, got, podSpec+"/volumes"); v != nil && len(v.([]any)) != 0 {
		t.Fatalf("volumes: %v", v)
	}
	if v := at(t, got, vllmPath+"/volumeMounts"); v != nil && len(v.([]any)) != 0 {
		t.Fatalf("volumeMounts: %v", v)
	}
}

func TestKustomizeSMPAnd6902SameTarget(t *testing.T) {
	a := parseObj(t, firstDeploymentYAML)
	tg := target(t, firstDeploymentYAML,
		Set(a, podSpec+"/containers/1/securityContext/runAsNonRoot", true),
		Remove(podSpec+"/containers/1/args/2"),
	)
	if smp, j := render(t, tg); smp == nil || len(j) == 0 {
		t.Fatalf("smp %v, 6902 %v", smp, j)
	}
	objs, err := buildPatched(t, firstDeploymentYAML, tg)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "vllm")
	assertJSON(t, at(t, got, podSpec+"/containers/1/args"), `["serve","m","--port","8000"]`)
	assertJSON(t, at(t, got, podSpec+"/containers/1/securityContext"), `{"runAsNonRoot":true}`)
}

func rayTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, rayClusterYAML)
	tg := target(t, rayClusterYAML, Set(obj, gpuWorker+"/securityContext/runAsNonRoot", true))
	if smp, _ := render(t, tg); smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	return tg
}

func TestKustomize6902RayClusterApplies(t *testing.T) {
	objs, err := buildPatched(t, rayClusterYAML, rayTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "RayCluster", "rc")
	assertJSON(t, at(t, got, "/spec/workerGroupSpecs/1/groupName"), `"gpu"`)
	assertJSON(t, at(t, got, gpuWorker+"/securityContext"), `{"runAsNonRoot":true}`)
	if v := at(t, got, "/spec/workerGroupSpecs/0/template/spec/containers/0/securityContext"); v != nil {
		t.Fatalf("cpu group patched: %v", v)
	}
}

func TestKustomize6902ReorderedFails(t *testing.T) {
	_, err := buildPatched(t, swappedRayClusterYAML, rayTarget(t))
	assertTestFailure(t, err)
}

func TestKustomize6902ReorderedContainersFails(t *testing.T) {
	obj := parseObj(t, rayListsYAML)
	tg := target(t, rayListsYAML, Set(obj, rayListsWorker+"/securityContext/runAsNonRoot", true))
	if _, err := buildPatched(t, rayListsYAML, tg); err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(rayListsYAML, rayListsContainers, rayListsSwapped, 1)
	if swapped == rayListsYAML {
		t.Fatal("swap did not apply")
	}
	_, err := buildPatched(t, swapped, tg)
	assertTestFailure(t, err)
}

func TestKustomize6902ReorderedArgsFails(t *testing.T) {
	tg := target(t, firstDeploymentYAML, Remove(podSpec+"/containers/1/args/2"))
	if _, err := buildPatched(t, firstDeploymentYAML, tg); err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(firstDeploymentYAML, `["serve", "m", "--trust-remote-code",`, `["serve", "--trust-remote-code", "m",`, 1)
	if swapped == firstDeploymentYAML {
		t.Fatal("swap did not apply")
	}
	_, err := buildPatched(t, swapped, tg)
	assertTestFailure(t, err)
}

func TestKustomize6902AppendsToExistingLists(t *testing.T) {
	obj := parseObj(t, rayListsYAML)
	objs, err := buildPatched(t, rayListsYAML, target(t, rayListsYAML,
		Set(obj, rayListsWorker+"/env/-", map[string]any{"name": "HOME", "value": "/kshield/cache"}),
		Set(obj, rayListsWorker+"/env/-", map[string]any{"name": "HF_HOME", "value": "/kshield/cache/huggingface"}),
		Set(obj, rayListsWorker+"/args/-", "--load-format"),
		Set(obj, rayListsWorker+"/args/-", "safetensors"),
	))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "RayCluster", "rl")
	assertJSON(t, at(t, got, rayListsWorker+"/env"), `[{"name":"A","value":"1"},{"name":"HOME","value":"/kshield/cache"},{"name":"HF_HOME","value":"/kshield/cache/huggingface"}]`)
	assertJSON(t, at(t, got, rayListsWorker+"/args"), `["--block","--load-format","safetensors"]`)
}

func initOrderTarget(t *testing.T) Target {
	t.Helper()
	obj := parseObj(t, initOrderYAML)
	return target(t, initOrderYAML,
		Set(obj, podSpec+"/initContainers/1/securityContext/runAsNonRoot", true),
		Set(obj, podSpec+"/containers/1/securityContext/runAsNonRoot", true),
		Set(obj, podSpec+"/containers/0/env/-", map[string]any{"name": "HOME", "value": "/kshield/cache"}),
	)
}

func TestKustomizeSMPKeepsListOrder(t *testing.T) {
	objs, err := buildPatched(t, initOrderYAML, initOrderTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "ordered")
	var names []any
	for _, c := range at(t, got, podSpec+"/initContainers").([]any) {
		names = append(names, c.(map[string]any)["name"])
	}
	for _, c := range at(t, got, podSpec+"/containers").([]any) {
		names = append(names, c.(map[string]any)["name"])
	}
	assertJSON(t, names, `["i1","i2","i3","c1","c2"]`)
	assertJSON(t, at(t, got, podSpec+"/containers/0/env"), `[{"name":"A","value":"1"},{"name":"B","value":"2"},{"name":"HOME","value":"/kshield/cache"}]`)
	assertJSON(t, at(t, got, podSpec+"/initContainers/1/securityContext"), `{"runAsNonRoot":true}`)
}

func TestKustomizeKeyedItemRenameNoStub(t *testing.T) {
	objs, err := buildPatched(t, envDeploymentYAML, renameTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "envd")
	assertJSON(t, at(t, got, envPath), `[{"name":"A","value":"1"},{"name":"B2","value":"2"},`+homeEnv+`]`)
	assertJSON(t, at(t, got, vllmPath+"/securityContext"), `{"runAsNonRoot":true}`)
}

func TestKustomizeWholeListReplaceNoStub(t *testing.T) {
	objs, err := buildPatched(t, envDeploymentYAML, replaceListTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "envd")
	assertJSON(t, at(t, got, envPath), `[{"name":"C","value":"3"},`+homeEnv+`]`)
	assertJSON(t, at(t, got, vllmPath+"/securityContext"), `{"runAsNonRoot":true}`)
}

func TestKustomizeRemovedKeyReadded(t *testing.T) {
	objs, err := buildPatched(t, envDeploymentYAML, removedKeyReaddedTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "Deployment", "envd")
	assertJSON(t, at(t, got, envPath), `[{"name":"B","value":"2"},{"name":"A","value":"9"}]`)
	assertJSON(t, at(t, got, vllmPath+"/securityContext"), `{"runAsNonRoot":true}`)
}

func TestKustomize6902AppendAfterWholeWrite(t *testing.T) {
	objs, err := buildPatched(t, rayListsYAML, appendBeforeWholeWriteTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, objs, "RayCluster", "rl")
	assertJSON(t, at(t, got, rayListsWorker+"/env"), `[{"name":"C","value":"3"},`+homeEnv+`]`)
}

func TestKustomizeRemoveUnderRemove(t *testing.T) {
	for name, c := range nestedRemoves() {
		for _, ops := range [][]Op{{c.outer, c.inner}, {c.inner, c.outer}} {
			objs, err := buildPatched(t, c.base, target(t, c.base, ops...))
			if err != nil {
				t.Errorf("%s, %s first: %v", name, ops[0].Path, err)
				continue
			}
			if v := at(t, byName(t, objs, c.kind, c.name), c.path); v != nil {
				t.Errorf("%s, %s first: %s still set: %v", name, ops[0].Path, c.path, v)
			}
		}
	}
}

func TestKustomize6902ReorderedPortsFails(t *testing.T) {
	tg := target(t, dnsNodePortYAML, Remove("/spec/ports/1/nodePort"))
	objs, err := buildPatched(t, dnsNodePortYAML, tg)
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, at(t, byName(t, objs, "Service", "dns"), "/spec/ports"), `[
		{"name":"dns-tcp","port":53,"protocol":"TCP","nodePort":30053},
		{"name":"dns-udp","port":53,"protocol":"UDP"}
	]`)
	tcp := "  - name: dns-tcp\n    port: 53\n    protocol: TCP\n    nodePort: 30053\n"
	udp := "  - name: dns-udp\n    port: 53\n    protocol: UDP\n    nodePort: 30054\n"
	swapped := strings.Replace(dnsNodePortYAML, tcp+udp, udp+tcp, 1)
	if swapped == dnsNodePortYAML {
		t.Fatal("swap did not apply")
	}
	_, err = buildPatched(t, swapped, tg)
	assertTestFailure(t, err)
}

func TestKustomizeSMPDriftFails(t *testing.T) {
	cases := map[string]string{
		"env item removed":       "        - name: B\n          value: \"2\"\n",
		"init container removed": "      - name: i3\n        image: busybox:1.37.0\n",
	}
	for name, cut := range cases {
		drifted := strings.Replace(initOrderYAML, cut, "", 1)
		if drifted == initOrderYAML {
			t.Fatalf("%s: cut did not apply", name)
		}
		_, err := buildPatched(t, drifted, initOrderTarget(t))
		if err == nil {
			t.Fatalf("%s: build succeeded", name)
		}
		if !strings.Contains(err.Error(), "test") {
			t.Fatalf("%s: error does not mention test: %v", name, err)
		}
	}
}
