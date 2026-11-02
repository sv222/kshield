package remediate

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	wlPod  = "/spec/template/spec"
	wlC0   = wlPod + "/containers/0"
	wlC1   = wlPod + "/containers/1"
	wlInit = wlPod + "/initContainers/0"
	wlVLLM = `{"name":"vllm","image":"vllm/vllm-openai:v0.31.0"}`
)

var wlChecks = []string{
	"KS-WL-001", "KS-WL-002", "KS-WL-003", "KS-WL-004", "KS-WL-005",
	"KS-WL-006", "KS-WL-007", "KS-WL-008", "KS-WL-009", "KS-WL-010",
}

func toYAML(t *testing.T, s string) string {
	t.Helper()
	b, err := yaml.JSONToYAML([]byte(s))
	if err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	return string(b)
}

func deploymentWith(t *testing.T, pod string) string {
	t.Helper()
	return toYAML(t, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app","namespace":"ai"},
		"spec":{"selector":{"matchLabels":{"app":"app"}},"template":{"metadata":{"labels":{"app":"app"}},"spec":`+pod+`}}}`)
}

func joinDocs(t *testing.T, docs ...string) string {
	t.Helper()
	return strings.Join(docs, "---\n")
}

func loadInput(t *testing.T, y string) *check.Input {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(y)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	return &check.Input{Objects: objs, Workloads: ws}
}

func findingsOf(t *testing.T, in *check.Input, id string) []check.Finding {
	t.Helper()
	c, ok := check.ByID(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	return check.Evaluate(c, in).Findings
}

func workloadOf(t *testing.T, in *check.Input, f check.Finding) model.Workload {
	t.Helper()
	for _, w := range in.Workloads {
		if w.Owner == f.Object && w.Group == f.Group && strings.HasPrefix(f.Path, w.SpecPath+"/") {
			return w
		}
	}
	t.Fatalf("no workload for %s %s", f.Object, f.Path)
	return model.Workload{}
}

type fixRun struct {
	base      string
	in        *check.Input
	ops       map[load.ObjectRef][]Op
	raw       map[load.ObjectRef][]Op
	residuals []Residual
}

func runFixers(t *testing.T, base string, ids ...string) fixRun {
	t.Helper()
	r := newRun(t, base)
	fixers := Fixers()
	for _, id := range ids {
		fx, ok := fixers[id]
		if !ok {
			t.Fatalf("no fixer for %s", id)
		}
		for _, f := range findingsOf(t, r.in, id) {
			ops, res := fx(workloadOf(t, r.in, f), f, r.in, "audit")
			if res != nil {
				if len(ops) > 0 {
					t.Fatalf("%s: residual with ops %v", id, ops)
				}
				r.residuals = append(r.residuals, *res)
				continue
			}
			r.add(t, f.Object, ops)
		}
	}
	return r
}

func newRun(t *testing.T, base string) fixRun {
	t.Helper()
	return fixRun{base: base, in: loadInput(t, base), ops: map[load.ObjectRef][]Op{}, raw: map[load.ObjectRef][]Op{}}
}

func (r fixRun) add(t *testing.T, ref load.ObjectRef, ops []Op) {
	t.Helper()
	r.raw[ref] = append(r.raw[ref], ops...)
	for _, op := range ops {
		if !slices.ContainsFunc(r.ops[ref], func(o Op) bool { return opJSON(t, o) == opJSON(t, op) }) {
			r.ops[ref] = append(r.ops[ref], op)
		}
	}
}

func opJSON(t *testing.T, o Op) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r fixRun) only(t *testing.T) []Op {
	t.Helper()
	if len(r.ops) > 1 {
		t.Fatalf("ops on %d objects", len(r.ops))
	}
	for _, ops := range r.ops {
		return ops
	}
	return nil
}

func (r fixRun) patched(t *testing.T) []map[string]any {
	t.Helper()
	return r.build(t, r.ops)
}

func (r fixRun) build(t *testing.T, byRef map[load.ObjectRef][]Op) []map[string]any {
	t.Helper()
	var tgs []Target
	for _, o := range r.in.Objects {
		if ops := byRef[o.Ref]; len(ops) > 0 {
			tgs = append(tgs, Target{Ref: o.Ref, Original: o.U.Object, Ops: ops})
		}
	}
	objs, err := buildPatched(t, r.base, tgs...)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func (r fixRun) rescan(t *testing.T) *check.Input {
	t.Helper()
	return reload(t, r.patched(t))
}

func reload(t *testing.T, objs []map[string]any) *check.Input {
	t.Helper()
	var docs []string
	for _, o := range objs {
		docs = append(docs, marshal(t, o))
	}
	return loadInput(t, joinDocs(t, docs...))
}

func assertNoFindings(t *testing.T, in *check.Input, ids ...string) {
	t.Helper()
	for _, id := range ids {
		for _, f := range findingsOf(t, in, id) {
			t.Errorf("%s still fails: %s %s %s: %s", id, f.Object, f.Group, f.Path, f.Message)
		}
	}
}

func assertResidual(t *testing.T, r fixRun, id string, n int, reason string) {
	t.Helper()
	got := 0
	for _, res := range r.residuals {
		if res.Check != id {
			continue
		}
		got++
		if res.Reason != reason {
			t.Errorf("%s reason %q, want %q", id, res.Reason, reason)
		}
		if res.Finding.Object.Kind == "" || res.Finding.Path == "" {
			t.Errorf("%s residual without finding: %+v", id, res.Finding)
		}
	}
	if got != n {
		t.Fatalf("%s: %d residuals, want %d: %+v", id, got, n, r.residuals)
	}
}

func TestWLFixes(t *testing.T) {
	cases := []struct {
		name, check, pod, want string
	}{
		{"WL-001 bare", "KS-WL-001", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsNonRoot":true}},
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsUser":1000}},
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsGroup":1000}}]`},
		{"WL-001 root uid and PVC", "KS-WL-001", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"runAsUser":0}}],
			"volumes":[{"name":"models","persistentVolumeClaim":{"claimName":"models"}}]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext/runAsNonRoot","value":true},
			{"op":"replace","path":"` + wlC0 + `/securityContext/runAsUser","value":1000},
			{"op":"add","path":"` + wlC0 + `/securityContext/runAsGroup","value":1000},
			{"op":"add","path":"` + wlPod + `/securityContext","value":{"fsGroup":1000}}]`},
		{"WL-001 keeps group and fsGroup", "KS-WL-001", `{"securityContext":{"runAsGroup":2000,"fsGroup":3000},"containers":[` + wlVLLM + `],
			"volumes":[{"name":"models","persistentVolumeClaim":{"claimName":"models"}}]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsNonRoot":true}},
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsUser":1000}}]`},
		{"WL-002 bare", "KS-WL-002", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"allowPrivilegeEscalation":false}}]`},
		{"WL-002 privileged", "KS-WL-002", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true}}]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext/allowPrivilegeEscalation","value":false},
			{"op":"replace","path":"` + wlC0 + `/securityContext/privileged","value":false}]`},
		{"WL-003 bare", "KS-WL-003", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"capabilities":{"drop":["ALL"]}}}]`},
		{"WL-003 filter add", "KS-WL-003", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
			"securityContext":{"capabilities":{"drop":["NET_RAW"],"add":["SYS_ADMIN","NET_BIND_SERVICE"]}}}]}`, `[
			{"op":"replace","path":"` + wlC0 + `/securityContext/capabilities/drop","value":["ALL"]},
			{"op":"replace","path":"` + wlC0 + `/securityContext/capabilities/add","value":["NET_BIND_SERVICE"]}]`},
		{"WL-003 remove add", "KS-WL-003", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
			"securityContext":{"capabilities":{"drop":["all"],"add":["SYS_ADMIN"]}}}]}`, `[
			{"op":"remove","path":"` + wlC0 + `/securityContext/capabilities/add"}]`},
		{"WL-004", "KS-WL-004", `{"hostIPC":true,"hostPID":true,"hostNetwork":true,"containers":[` + wlVLLM + `]}`, `[
			{"op":"replace","path":"` + wlPod + `/hostIPC","value":false},
			{"op":"replace","path":"` + wlPod + `/hostNetwork","value":false},
			{"op":"replace","path":"` + wlPod + `/hostPID","value":false}]`},
		{"WL-005", "KS-WL-005", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","resources":{"limits":{"memory":"16Gi"}},
			"volumeMounts":[{"name":"shm","mountPath":"/dev/shm/"}]}],"volumes":[{"name":"shm","hostPath":{"path":"/dev/shm","type":"Directory"}}]}`, `[
			{"op":"remove","path":"` + wlPod + `/volumes/0/hostPath"},
			{"op":"add","path":"` + wlPod + `/volumes/0/emptyDir","value":{"medium":"Memory","sizeLimit":"16Gi"}}]`},
		{"WL-006", "KS-WL-006", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
			"volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]}],"volumes":[{"name":"shm","emptyDir":{"medium":"Memory"}}]}`, `[
			{"op":"add","path":"` + wlPod + `/volumes/0/emptyDir/sizeLimit","value":"8Gi"}]`},
		{"WL-007", "KS-WL-007", `{"shareProcessNamespace":true,"containers":[` + wlVLLM + `]}`, `[
			{"op":"replace","path":"` + wlPod + `/shareProcessNamespace","value":false}]`},
		{"WL-008", "KS-WL-008", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"readOnlyRootFilesystem":true}},
			{"op":"add","path":"` + wlPod + `/volumes","value":[{"name":"kshield-tmp","emptyDir":{}}]},
			{"op":"add","path":"` + wlC0 + `/volumeMounts","value":[{"name":"kshield-tmp","mountPath":"/tmp"}]},
			{"op":"add","path":"` + wlPod + `/volumes","value":[{"name":"kshield-cache","emptyDir":{}}]},
			{"op":"add","path":"` + wlC0 + `/volumeMounts","value":[{"name":"kshield-cache","mountPath":"/kshield/cache"}]},
			{"op":"add","path":"` + wlC0 + `/env","value":[{"name":"HOME","value":"/kshield/cache"}]},
			{"op":"add","path":"` + wlC0 + `/env","value":[{"name":"HF_HOME","value":"/kshield/cache/huggingface"}]},
			{"op":"add","path":"` + wlC0 + `/env","value":[{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}]}]`},
		{"WL-008 false", "KS-WL-008", `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"readOnlyRootFilesystem":false},
			"env":[{"name":"HOME","value":"/kshield/cache/home"}],"volumeMounts":[{"name":"t","mountPath":"/tmp"},{"name":"c","mountPath":"/kshield/cache"}]}],
			"volumes":[{"name":"t","emptyDir":{}},{"name":"c","emptyDir":{}}]}`, `[
			{"op":"replace","path":"` + wlC0 + `/securityContext/readOnlyRootFilesystem","value":true},
			{"op":"add","path":"` + wlC0 + `/env/-","value":{"name":"HF_HOME","value":"/kshield/cache/huggingface"}},
			{"op":"add","path":"` + wlC0 + `/env/-","value":{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}}]`},
		{"WL-009 bare", "KS-WL-009", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlC0 + `/securityContext","value":{"seccompProfile":{"type":"RuntimeDefault"}}}]`},
		{"WL-009 unconfined", "KS-WL-009", `{"securityContext":{"seccompProfile":{"type":"Unconfined"}},
			"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"seccompProfile":{"type":"Unconfined"}}}]}`, `[
			{"op":"replace","path":"` + wlC0 + `/securityContext/seccompProfile/type","value":"RuntimeDefault"}]`},
		{"WL-010 unset", "KS-WL-010", `{"containers":[` + wlVLLM + `]}`, `[
			{"op":"add","path":"` + wlPod + `/automountServiceAccountToken","value":false}]`},
		{"WL-010 true", "KS-WL-010", `{"automountServiceAccountToken":true,"containers":[` + wlVLLM + `]}`, `[
			{"op":"replace","path":"` + wlPod + `/automountServiceAccountToken","value":false}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := deploymentWith(t, c.pod)
			if len(findingsOf(t, loadInput(t, base), c.check)) == 0 {
				t.Fatal("input has no finding")
			}
			r := runFixers(t, base, c.check)
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			assertJSON(t, r.only(t), c.want)
			assertNoFindings(t, r.rescan(t), c.check)
		})
	}
}

func TestWL001KeepsNonZeroUID(t *testing.T) {
	cases := map[string]struct{ pod, want, uidPath string }{
		"container": {
			`{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"runAsUser":1500}}]}`,
			`[{"op":"add","path":"` + wlC0 + `/securityContext/runAsNonRoot","value":true}]`,
			wlC0 + "/securityContext/runAsUser",
		},
		"pod": {
			`{"securityContext":{"runAsUser":1500},"containers":[` + wlVLLM + `]}`,
			`[{"op":"add","path":"` + wlC0 + `/securityContext","value":{"runAsNonRoot":true}}]`,
			wlPod + "/securityContext/runAsUser",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, c.pod)
			r := newRun(t, base)
			w := r.in.Workloads[0]
			f := check.Finding{Object: w.Owner, Container: "vllm", Path: wlC0 + "/securityContext/runAsNonRoot", Message: "container may run as root"}
			ops, res := Fixers()["KS-WL-001"](w, f, r.in, "audit")
			if res != nil {
				t.Fatalf("residual: %+v", res)
			}
			assertJSON(t, ops, c.want)
			r.add(t, w.Owner, ops)
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, c.uidPath), `1500`)
			assertJSON(t, at(t, got, wlC0+"/securityContext/runAsNonRoot"), `true`)
			assertNoFindings(t, r.rescan(t), "KS-WL-001")
		})
	}
}

func TestWL001StackUID(t *testing.T) {
	cases := map[string]struct{ image, want string }{
		"milvus": {"milvusdb/milvus:v3.0.3", `{"runAsNonRoot":true,"runAsUser":999,"runAsGroup":999}`},
		"vllm":   {"vllm/vllm-openai:v0.31.0", `{"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, `{"containers":[{"name":"db","image":"`+c.image+`","args":["milvus","run","standalone"]}]}`)
			r := runFixers(t, base, "KS-WL-001")
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, wlC0+"/securityContext"), c.want)
			assertNoFindings(t, r.rescan(t), "KS-WL-001")
		})
	}
	base := toYAML(t, `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"milvus","namespace":"ai"},
		"spec":{"serviceName":"milvus","selector":{"matchLabels":{"app":"milvus"}},
		"template":{"metadata":{"labels":{"app":"milvus"}},"spec":{"containers":[{"name":"milvus","image":"milvusdb/milvus:v3.0.3",
			"volumeMounts":[{"name":"data","mountPath":"/var/lib/milvus"}]}]}},
		"volumeClaimTemplates":[{"metadata":{"name":"data"},"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}}]}}`)
	r := runFixers(t, base, "KS-WL-001")
	got := byName(t, r.patched(t), "StatefulSet", "milvus")
	assertJSON(t, at(t, got, wlPod+"/securityContext"), `{"fsGroup":999}`)
}

func TestWL001StackUIDWithSidecar(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"milvus","namespace":"ai"},
		"spec":{"serviceName":"milvus","selector":{"matchLabels":{"app":"milvus"}},
		"template":{"metadata":{"labels":{"app":"milvus"}},"spec":{"containers":[
			{"name":"milvus","image":"milvusdb/milvus:v3.0.3","volumeMounts":[{"name":"data","mountPath":"/var/lib/milvus"}]},
			{"name":"sidecar","image":"busybox:1.38.0"}]}},
		"volumeClaimTemplates":[{"metadata":{"name":"data"},"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}}]}}`)
	r := runFixers(t, base, "KS-WL-001")
	got := byName(t, r.patched(t), "StatefulSet", "milvus")
	assertJSON(t, at(t, got, wlPod+"/securityContext"), `{"fsGroup":999}`)
	assertJSON(t, at(t, got, wlC0+"/securityContext"), `{"runAsNonRoot":true,"runAsUser":999,"runAsGroup":999}`)
	assertJSON(t, at(t, got, wlPod+"/containers/1/securityContext"), `{"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000}`)
	assertNoFindings(t, r.rescan(t), "KS-WL-001")
}

func TestWL001StatefulSetClaimTemplates(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"qdrant","namespace":"ai"},
		"spec":{"serviceName":"qdrant","selector":{"matchLabels":{"app":"qdrant"}},
		"template":{"metadata":{"labels":{"app":"qdrant"}},"spec":{"containers":[{"name":"qdrant","image":"qdrant/qdrant:v1.15.5",
			"volumeMounts":[{"name":"storage","mountPath":"/qdrant/storage"}]}]}},
		"volumeClaimTemplates":[{"metadata":{"name":"storage"},"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}}]}}`)
	r := runFixers(t, base, "KS-WL-001")
	got := byName(t, r.patched(t), "StatefulSet", "qdrant")
	assertJSON(t, at(t, got, wlPod+"/securityContext"), `{"fsGroup":1000}`)
	assertNoFindings(t, r.rescan(t), "KS-WL-001")
}

func TestWL002GPUResidual(t *testing.T) {
	const reason = "privileged is used for GPU access; move to the NVIDIA device plugin first"
	cases := map[string]string{
		"hostPath": `{"containers":[
			{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true},
				"volumeMounts":[{"name":"nvidia","mountPath":"/dev/nvidia0"}]},
			{"name":"proxy","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true}}],
			"volumes":[{"name":"nvidia","hostPath":{"path":"/dev/nvidia0"}}]}`,
		"env": `{"containers":[
			{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true},
				"env":[{"name":"NVIDIA_VISIBLE_DEVICES","value":"all"}]},
			{"name":"proxy","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true}}]}`,
	}
	for name, pod := range cases {
		t.Run(name, func(t *testing.T) {
			r := runFixers(t, deploymentWith(t, pod), "KS-WL-002")
			assertResidual(t, r, "KS-WL-002", 2, reason)
			for _, res := range r.residuals {
				if res.Finding.Container != "vllm" {
					t.Errorf("residual for %s", res.Finding.Container)
				}
			}
			assertJSON(t, r.only(t), `[
				{"op":"add","path":"`+wlC1+`/securityContext/allowPrivilegeEscalation","value":false},
				{"op":"replace","path":"`+wlC1+`/securityContext/privileged","value":false}]`)
			left := findingsOf(t, r.rescan(t), "KS-WL-002")
			if len(left) != 2 || left[0].Container != "vllm" || left[1].Container != "vllm" {
				t.Fatalf("left: %+v", left)
			}
		})
	}
}

func TestWL005DevResidual(t *testing.T) {
	cases := map[string]struct{ pod, reason string }{
		"dev": {
			`{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"dev","mountPath":"/dev"}]}],
				"volumes":[{"name":"dev","hostPath":{"path":"/dev"}}]}`,
			"hostPath /dev also carries devices; replace it by hand",
		},
		"mount elsewhere": {
			`{"containers":[
				{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]},
				{"name":"side","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"shm","mountPath":"/shared"}]}],
				"volumes":[{"name":"shm","hostPath":{"path":"/dev/shm"}}]}`,
			`volume "shm" is also mounted outside /dev/shm; replace it by hand`,
		},
		"below shm": {
			`{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]}],
				"volumes":[{"name":"shm","hostPath":{"path":"/dev/shm/vllm"}}]}`,
			"hostPath /dev/shm/vllm is not /dev/shm itself; replace it by hand",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runFixers(t, deploymentWith(t, c.pod), "KS-WL-005")
			assertResidual(t, r, "KS-WL-005", 1, c.reason)
			if len(r.ops) > 0 {
				t.Fatalf("ops: %v", r.ops)
			}
		})
	}
}

func TestWL006SizeFromLimit(t *testing.T) {
	cases := map[string]struct{ pod, want string }{
		"largest limit": {`{"containers":[
				{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","resources":{"limits":{"memory":"24Gi"}},"volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]},
				{"name":"side","image":"vllm/vllm-openai:v0.31.0","resources":{"limits":{"memory":"4Gi"}},"volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]},
				{"name":"other","image":"vllm/vllm-openai:v0.31.0","resources":{"limits":{"memory":"64Gi"}}}],
				"volumes":[{"name":"shm","emptyDir":{"medium":"Memory"}}]}`, `"24Gi"`},
		"no limit": {`{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]}],
				"volumes":[{"name":"shm","emptyDir":{"medium":"Memory"}}]}`, `"8Gi"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runFixers(t, deploymentWith(t, c.pod), "KS-WL-006")
			assertJSON(t, r.only(t), `[{"op":"add","path":"`+wlPod+`/volumes/0/emptyDir/sizeLimit","value":`+c.want+`}]`)
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, wlPod+"/volumes/0/emptyDir/sizeLimit"), c.want)
			assertNoFindings(t, r.rescan(t), "KS-WL-006")
		})
	}
}

func TestWL008ExistingTmpAndHFHome(t *testing.T) {
	base := deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
		"env":[{"name":"HF_HOME","value":"/models/hf"}],
		"volumeMounts":[{"name":"scratch","mountPath":"/tmp"},{"name":"models","mountPath":"/models"}]}],
		"volumes":[{"name":"scratch","emptyDir":{}},{"name":"models","emptyDir":{}}]}`)
	r := runFixers(t, base, "KS-WL-008")
	assertJSON(t, r.only(t), `[
		{"op":"add","path":"`+wlC0+`/securityContext","value":{"readOnlyRootFilesystem":true}},
		{"op":"add","path":"`+wlPod+`/volumes/-","value":{"name":"kshield-cache","emptyDir":{}}},
		{"op":"add","path":"`+wlC0+`/volumeMounts/-","value":{"name":"kshield-cache","mountPath":"/kshield/cache"}},
		{"op":"add","path":"`+wlC0+`/env/-","value":{"name":"HOME","value":"/kshield/cache"}},
		{"op":"add","path":"`+wlC0+`/env/-","value":{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}}]`)
	got := byName(t, r.patched(t), "Deployment", "app")
	assertJSON(t, at(t, got, wlC0+"/volumeMounts"), `[{"name":"scratch","mountPath":"/tmp"},{"name":"models","mountPath":"/models"},{"name":"kshield-cache","mountPath":"/kshield/cache"}]`)
	assertJSON(t, at(t, got, wlC0+"/env"), `[{"name":"HF_HOME","value":"/models/hf"},{"name":"HOME","value":"/kshield/cache"},{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}]`)
	assertNoFindings(t, r.rescan(t), "KS-WL-008")
}

func TestWL008CacheEnvOnReadOnlyRoot(t *testing.T) {
	residual := func(name, value string) string {
		return name + " points at " + value + ", which becomes read-only; mount a volume there or unset it first"
	}
	cases := map[string]struct{ env, mounts, volumes, reason string }{
		"HF_HOME without mount": {`[{"name":"HF_HOME","value":"/models/hf"}]`, `[]`, `[]`, residual("HF_HOME", "/models/hf")},
		"HOME at root dir":      {`[{"name":"HOME","value":"/root"}]`, `[]`, `[]`, residual("HOME", "/root")},
		"read-only mount": {`[{"name":"XDG_CACHE_HOME","value":"/models/xdg"}]`, `[{"name":"models","mountPath":"/models","readOnly":true}]`,
			`[{"name":"models","emptyDir":{}}]`, residual("XDG_CACHE_HOME", "/models/xdg")},
		"two vars": {`[{"name":"HOME","value":"/home/app"},{"name":"HF_HOME","value":"/data/hf"}]`, `[]`, `[]`,
			residual("HOME", "/home/app") + "; " + residual("HF_HOME", "/data/hf")},
		"last value wins": {`[{"name":"HOME","value":"/tmp/home"},{"name":"HOME","value":"/opt/home"}]`, `[]`, `[]`, residual("HOME", "/opt/home")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
				"env":`+c.env+`,"volumeMounts":`+c.mounts+`}],"volumes":`+c.volumes+`}`)
			r := runFixers(t, base, "KS-WL-008")
			assertResidual(t, r, "KS-WL-008", 1, c.reason)
		})
	}
	writable := map[string]struct{ env, mounts, volumes string }{
		"under a mount WL-008 adds": {`[{"name":"HOME","value":"/tmp/home"},{"name":"HF_HOME","value":"/kshield/cache/hf"}]`, `[]`, `[]`},
		"under a writable mount":    {`[{"name":"HF_HOME","value":"/data/hf/"}]`, `[{"name":"data","mountPath":"/data"}]`, `[{"name":"data","emptyDir":{}}]`},
		"value from a secret":       {`[{"name":"HF_HOME","valueFrom":{"secretKeyRef":{"name":"s","key":"k"}}}]`, `[]`, `[]`},
		"value from another var":    {`[{"name":"HF_HOME","value":"$(BASE)/hf"}]`, `[]`, `[]`},
	}
	for name, c := range writable {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
				"env":`+c.env+`,"volumeMounts":`+c.mounts+`}],"volumes":`+c.volumes+`}`)
			r := runFixers(t, base, "KS-WL-008")
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			assertNoFindings(t, r.rescan(t), "KS-WL-008")
		})
	}
}

func TestWL008NameClash(t *testing.T) {
	base := deploymentWith(t, `{"containers":[`+wlVLLM+`],
		"volumes":[{"name":"kshield-cache","configMap":{"name":"c"}},{"name":"kshield-tmp","configMap":{"name":"t"}},{"name":"kshield-tmp-2","secret":{"secretName":"s"}}]}`)
	r := runFixers(t, base, "KS-WL-008")
	got := byName(t, r.patched(t), "Deployment", "app")
	assertJSON(t, at(t, got, wlPod+"/volumes"), `[
		{"name":"kshield-cache","configMap":{"name":"c"}},
		{"name":"kshield-tmp","configMap":{"name":"t"}},
		{"name":"kshield-tmp-2","secret":{"secretName":"s"}},
		{"name":"kshield-tmp-3","emptyDir":{}},
		{"name":"kshield-cache-2","emptyDir":{}}]`)
	assertJSON(t, at(t, got, wlC0+"/volumeMounts"), `[{"name":"kshield-tmp-3","mountPath":"/tmp"},{"name":"kshield-cache-2","mountPath":"/kshield/cache"}]`)
	assertNoFindings(t, r.rescan(t), "KS-WL-008")
}

func TestWL008StackDataPaths(t *testing.T) {
	cases := map[string]struct{ image, mounts, volumes, want string }{
		"qdrant": {"qdrant/qdrant:v1.15.5", `[{"name":"storage","mountPath":"/qdrant/storage"}]`, `[{"name":"storage","persistentVolumeClaim":{"claimName":"q"}}]`,
			`[{"name":"storage","mountPath":"/qdrant/storage"},{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"},{"name":"kshield-qdrant-snapshots","mountPath":"/qdrant/snapshots"}]`},
		"milvus": {"milvusdb/milvus:v2.6.4", `[]`, `[]`,
			`[{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"},{"name":"kshield-milvus-data","mountPath":"/var/lib/milvus"}]`},
		"ollama": {"ollama/ollama:0.12.6", `[]`, `[]`,
			`[{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"},{"name":"kshield-ollama","mountPath":"/root/.ollama"}]`},
		"qdrant parent mount": {"qdrant/qdrant:v1.15.5", `[{"name":"data","mountPath":"/qdrant/"}]`, `[{"name":"data","emptyDir":{}}]`,
			`[{"name":"data","mountPath":"/qdrant/"},{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"}]`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, `{"containers":[{"name":"db","image":"`+c.image+`","volumeMounts":`+c.mounts+`}],"volumes":`+c.volumes+`}`)
			r := runFixers(t, base, "KS-WL-008")
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, wlC0+"/volumeMounts"), c.want)
			assertNoFindings(t, r.rescan(t), "KS-WL-008")
		})
	}
}

func TestWL008TwoContainersShareVolumes(t *testing.T) {
	base := deploymentWith(t, `{"initContainers":[{"name":"init","image":"busybox:1.37.0"}],"containers":[`+wlVLLM+`]}`)
	r := runFixers(t, base, "KS-WL-008")
	got := byName(t, r.patched(t), "Deployment", "app")
	assertJSON(t, at(t, got, wlPod+"/volumes"), `[{"name":"kshield-tmp","emptyDir":{}},{"name":"kshield-cache","emptyDir":{}}]`)
	mounts := `[{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"}]`
	assertJSON(t, at(t, got, wlInit+"/volumeMounts"), mounts)
	assertJSON(t, at(t, got, wlC0+"/volumeMounts"), mounts)
	assertNoFindings(t, r.rescan(t), "KS-WL-008")
}

func TestWL010RayAutoscalerResidual(t *testing.T) {
	group := `{"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}}`
	worker := `[{"groupName":"gpu","template":{"spec":{"containers":[{"name":"ray-worker","image":"rayproject/ray:2.50.0"}]}}}]`
	cases := map[string]struct{ obj, worker string }{
		"RayCluster": {`{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"ai"},
			"spec":{"enableInTreeAutoscaling":true,"headGroupSpec":` + group + `,"workerGroupSpecs":` + worker + `}}`,
			"/spec/workerGroupSpecs/0/template/spec"},
		"RayService": {`{"apiVersion":"ray.io/v1","kind":"RayService","metadata":{"name":"rs","namespace":"ai"},
			"spec":{"rayClusterConfig":{"enableInTreeAutoscaling":true,"headGroupSpec":` + group + `,"workerGroupSpecs":` + worker + `}}}`,
			"/spec/rayClusterConfig/workerGroupSpecs/0/template/spec"},
		"RayJob": {`{"apiVersion":"ray.io/v1","kind":"RayJob","metadata":{"name":"rj","namespace":"ai"},
			"spec":{"entrypoint":"python job.py","rayClusterSpec":{"enableInTreeAutoscaling":true,"headGroupSpec":` + group + `,"workerGroupSpecs":` + worker + `}}}`,
			"/spec/rayClusterSpec/workerGroupSpecs/0/template/spec"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runFixers(t, toYAML(t, c.obj), "KS-WL-010")
			assertResidual(t, r, "KS-WL-010", 1, "the Ray autoscaler needs the API token")
			if g := r.residuals[0].Finding.Group; g != "head" {
				t.Fatalf("residual group %q", g)
			}
			assertJSON(t, r.only(t), `[{"op":"add","path":"`+c.worker+`/automountServiceAccountToken","value":false}]`)
			left := findingsOf(t, r.rescan(t), "KS-WL-010")
			if len(left) != 1 || left[0].Group != "head" {
				t.Fatalf("left: %+v", left)
			}
		})
	}
}

func TestWL010RayWithoutAutoscalerFixed(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"ai"},
		"spec":{"enableInTreeAutoscaling":false,"headGroupSpec":{"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}}}}`)
	r := runFixers(t, base, "KS-WL-010")
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	assertNoFindings(t, r.rescan(t), "KS-WL-010")
}

func TestInitContainerFixed(t *testing.T) {
	ids := []string{"KS-WL-001", "KS-WL-002", "KS-WL-003", "KS-WL-008", "KS-WL-009"}
	base := deploymentWith(t, `{"initContainers":[{"name":"init","image":"busybox:1.37.0"}],"containers":[`+wlVLLM+`]}`)
	r := runFixers(t, base, ids...)
	var initOps, mainOps []string
	for _, op := range r.only(t) {
		switch {
		case strings.HasPrefix(op.Path, wlInit+"/securityContext"):
			op.Path = strings.TrimPrefix(op.Path, wlInit)
			initOps = append(initOps, opJSON(t, op))
		case strings.HasPrefix(op.Path, wlC0+"/securityContext"):
			op.Path = strings.TrimPrefix(op.Path, wlC0)
			mainOps = append(mainOps, opJSON(t, op))
		}
	}
	if len(initOps) != 7 || !slices.Equal(initOps, mainOps) {
		t.Fatalf("init %v\nmain %v", initOps, mainOps)
	}
	got := byName(t, r.patched(t), "Deployment", "app")
	assertJSON(t, at(t, got, wlInit+"/securityContext"), `{"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000,
		"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"seccompProfile":{"type":"RuntimeDefault"}}`)
	assertNoFindings(t, r.rescan(t), ids...)
}

func TestWorkloadFixersTogether(t *testing.T) {
	deploy := deploymentWith(t, `{"hostNetwork":true,"hostPID":true,"hostIPC":true,"shareProcessNamespace":true,"automountServiceAccountToken":true,
		"securityContext":{"runAsUser":0,"seccompProfile":{"type":"Unconfined"}},
		"initContainers":[{"name":"init","image":"busybox:1.37.0","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}],
		"containers":[
			{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","securityContext":{"privileged":true,"readOnlyRootFilesystem":false},
				"resources":{"limits":{"memory":"32Gi"}},"env":[{"name":"A","value":"1"}],
				"volumeMounts":[{"name":"shm","mountPath":"/dev/shm"},{"name":"scratch","mountPath":"/tmp"}]},
			{"name":"side","image":"vllm/vllm-openai:v0.31.0","volumeMounts":[{"name":"mem","mountPath":"/dev/shm"}]}],
		"volumes":[{"name":"shm","hostPath":{"path":"/dev/shm"}},{"name":"scratch","emptyDir":{}},{"name":"mem","emptyDir":{"medium":"Memory"}},
			{"name":"data","persistentVolumeClaim":{"claimName":"d"}}]}`)
	ray := toYAML(t, `{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"ai"},
		"spec":{"headGroupSpec":{"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}},
		"workerGroupSpecs":[{"groupName":"cpu","template":{"spec":{"containers":[{"name":"ray-worker","image":"rayproject/ray:2.50.0"}]}}},
			{"groupName":"gpu","template":{"spec":{"hostIPC":true,"volumes":[{"name":"shm","hostPath":{"path":"/dev/shm"}}],
				"containers":[{"name":"ray-worker","image":"rayproject/ray:2.50.0","volumeMounts":[{"name":"shm","mountPath":"/dev/shm"}]},
					{"name":"sidecar","image":"rayproject/ray:2.50.0","securityContext":{"runAsUser":0}}]}}}]}}`)
	cron := toYAML(t, `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"cj","namespace":"ai"},
		"spec":{"schedule":"0 * * * *","jobTemplate":{"spec":{"template":{"spec":{"restartPolicy":"Never",
			"containers":[{"name":"ollama","image":"ollama/ollama:0.12.6","securityContext":{"capabilities":{"drop":["NET_RAW"]}}}]}}}}}}`)
	base := joinDocs(t, deploy, ray, cron)
	r := runFixers(t, base, wlChecks...)
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	if len(r.ops) != 3 {
		t.Fatalf("ops on %d objects", len(r.ops))
	}
	dups := 0
	for ref, ops := range r.raw {
		dups += len(ops) - len(r.ops[ref])
	}
	if dups == 0 {
		t.Fatal("no duplicate ops: the engine dedupe is not exercised")
	}
	objs := r.build(t, r.raw)
	got := byName(t, objs, "Deployment", "app")
	assertJSON(t, at(t, got, wlPod+"/volumes"), `[
		{"name":"shm","emptyDir":{"medium":"Memory","sizeLimit":"32Gi"}},
		{"name":"scratch","emptyDir":{}},
		{"name":"mem","emptyDir":{"medium":"Memory","sizeLimit":"8Gi"}},
		{"name":"data","persistentVolumeClaim":{"claimName":"d"}},
		{"name":"kshield-cache","emptyDir":{}},
		{"name":"kshield-tmp","emptyDir":{}}]`)
	assertJSON(t, at(t, got, wlC0+"/env"), `[{"name":"A","value":"1"},
		{"name":"HOME","value":"/kshield/cache"},{"name":"HF_HOME","value":"/kshield/cache/huggingface"},{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}]`)
	assertJSON(t, at(t, got, wlPod+"/securityContext"), `{"runAsUser":0,"seccompProfile":{"type":"Unconfined"},"fsGroup":1000}`)
	assertJSON(t, at(t, byName(t, objs, "RayCluster", "rc"), "/spec/workerGroupSpecs/1/template/spec/volumes/0"),
		`{"name":"shm","emptyDir":{"medium":"Memory","sizeLimit":"8Gi"}}`)
	assertNoFindings(t, reload(t, objs), wlChecks...)
}

func TestRootMountResidual(t *testing.T) {
	const wl008Reason = "a volume is mounted under /root and the process keeps HOME=/root; a read-only root filesystem would block writes there; move the mount out of /root first"
	cases := map[string]struct{ image, mount string }{
		"ollama data":   {"ollama/ollama:0.12.6", "/root/.ollama"},
		"ollama models": {"ollama/ollama:0.12.6", "/root/.ollama/models"},
		"vllm hf cache": {"vllm/vllm-openai:v0.31.0", "/root/.cache/huggingface"},
		"root":          {"vllm/vllm-openai:v0.31.0", "/root"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := deploymentWith(t, `{"containers":[{"name":"app","image":"`+c.image+`","volumeMounts":[{"name":"data","mountPath":"`+c.mount+`"}]},`+wlVLLM+`],
				"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"models"}}]}`)
			r := runFixers(t, base, "KS-WL-001", "KS-WL-008")
			assertResidual(t, r, "KS-WL-001", 1, "a volume is mounted under /root; a non-root user cannot reach it; move the mount out of /root and point HOME/HF_HOME/OLLAMA_MODELS at it first")
			assertResidual(t, r, "KS-WL-008", 1, wl008Reason)
			for _, res := range r.residuals {
				if res.Finding.Container != "app" {
					t.Errorf("residual for %s", res.Finding.Container)
				}
			}
			for _, op := range r.only(t) {
				if under(op.Path, wlC0) {
					t.Errorf("op on the root-mount container: %s %s", op.Op, op.Path)
				}
			}
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, wlC0), `{"name":"app","image":"`+c.image+`","volumeMounts":[{"name":"data","mountPath":"`+c.mount+`"}]}`)
			assertJSON(t, at(t, got, wlC1+"/volumeMounts"), `[{"name":"kshield-tmp","mountPath":"/tmp"},{"name":"kshield-cache","mountPath":"/kshield/cache"}]`)
			assertJSON(t, at(t, got, wlPod+"/volumes"), `[{"name":"data","persistentVolumeClaim":{"claimName":"models"}},
				{"name":"kshield-tmp","emptyDir":{}},{"name":"kshield-cache","emptyDir":{}}]`)
			after := r.rescan(t)
			for _, id := range []string{"KS-WL-001", "KS-WL-008"} {
				left := findingsOf(t, after, id)
				if len(left) != 1 || left[0].Container != "app" {
					t.Errorf("%s left: %+v", id, left)
				}
			}
		})
	}
}

func TestWL008EnvFrom(t *testing.T) {
	cm := toYAML(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"hf","namespace":"ai"},"data":{"HOME":"/models"}}`)
	cases := map[string]struct {
		docs []string
		want string
	}{
		"key in input": {[]string{cm, deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
			"envFrom":[{"configMapRef":{"name":"hf"},"prefix":"HF_"}]}]}`)},
			`[{"name":"HOME","value":"/kshield/cache"},{"name":"XDG_CACHE_HOME","value":"/kshield/cache/xdg"}]`},
		"source not in input": {[]string{deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
			"envFrom":[{"secretRef":{"name":"elsewhere"}}]}]}`)}, `null`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runFixers(t, joinDocs(t, c.docs...), "KS-WL-008")
			got := byName(t, r.patched(t), "Deployment", "app")
			assertJSON(t, at(t, got, wlC0+"/env"), c.want)
			assertNoFindings(t, r.rescan(t), "KS-WL-008")
		})
	}
}

func TestServingRuntimeFixes(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"serving.kserve.io/v1alpha1","kind":"ServingRuntime","metadata":{"name":"rt","namespace":"ai"},
		"spec":{"supportedModelFormats":[{"name":"vllm"}],"hostIPC":true,"hostPID":true,"hostNetwork":true,"shareProcessNamespace":true,
		"containers":[`+wlVLLM+`],"volumes":[{"name":"models","persistentVolumeClaim":{"claimName":"m"}}]}}`)
	ids := []string{"KS-WL-001", "KS-WL-004", "KS-WL-007", "KS-WL-010"}
	r := runFixers(t, base, ids...)
	assertResidual(t, r, "KS-WL-007", 1, "ServingRuntime has no shareProcessNamespace field; remove shareProcessNamespace from the manifest by hand")
	assertResidual(t, r, "KS-WL-010", 1, reasonRuntimeSA)
	var reasons []string
	for _, res := range r.residuals {
		if res.Check == "KS-WL-004" {
			reasons = append(reasons, res.Reason)
		}
	}
	assertJSON(t, reasons, `["ServingRuntime has no hostNetwork field; remove hostNetwork from the manifest by hand",
		"ServingRuntime has no hostPID field; remove hostPID from the manifest by hand"]`)
	assertJSON(t, r.only(t), `[
		{"op":"add","path":"/spec/containers/0/securityContext","value":{"runAsNonRoot":true}},
		{"op":"add","path":"/spec/containers/0/securityContext","value":{"runAsUser":1000}},
		{"op":"add","path":"/spec/containers/0/securityContext","value":{"runAsGroup":1000}},
		{"op":"replace","path":"/spec/hostIPC","value":false}]`)
	after := r.rescan(t)
	assertNoFindings(t, after, "KS-WL-001")
	left := map[string]int{}
	for _, id := range ids {
		left[id] = len(findingsOf(t, after, id))
	}
	assertJSON(t, left, `{"KS-WL-001":0,"KS-WL-004":2,"KS-WL-007":1,"KS-WL-010":1}`)
}

func TestWL002DropsSysAdmin(t *testing.T) {
	pod := `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",
		"securityContext":{"capabilities":{"drop":["ALL"],"add":["SYS_ADMIN","NET_BIND_SERVICE"]}}},
		{"name":"side","image":"vllm/vllm-openai:v0.31.0","securityContext":{"capabilities":{"add":["CAP_SYS_ADMIN","NET_ADMIN"]}}}]}`
	t.Run("alone", func(t *testing.T) {
		r := runFixers(t, deploymentWith(t, pod), "KS-WL-002")
		assertJSON(t, r.only(t), `[
			{"op":"add","path":"`+wlC0+`/securityContext/allowPrivilegeEscalation","value":false},
			{"op":"replace","path":"`+wlC0+`/securityContext/capabilities/add","value":["NET_BIND_SERVICE"]},
			{"op":"add","path":"`+wlC1+`/securityContext/allowPrivilegeEscalation","value":false},
			{"op":"remove","path":"`+wlC1+`/securityContext/capabilities/add"}]`)
		assertNoFindings(t, r.rescan(t), "KS-WL-002")
	})
	t.Run("with WL-003", func(t *testing.T) {
		r := runFixers(t, deploymentWith(t, pod), "KS-WL-002", "KS-WL-003")
		got := byName(t, r.build(t, r.raw), "Deployment", "app")
		assertJSON(t, at(t, got, wlC0+"/securityContext"), `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"],"add":["NET_BIND_SERVICE"]}}`)
		assertJSON(t, at(t, got, wlC1+"/securityContext"), `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}`)
		assertNoFindings(t, reload(t, r.build(t, r.raw)), "KS-WL-002", "KS-WL-003")
	})
}

func TestBindNoOpsIsResidual(t *testing.T) {
	r := newRun(t, deploymentWith(t, `{"containers":[`+wlVLLM+`]}`))
	w := r.in.Workloads[0]
	f := check.Finding{Object: w.Owner, Path: wlPod + "/x"}
	ops, res := bind("KS-X", func(model.Workload, check.Finding, *check.Input, string) ([]Op, string) { return nil, "" })(w, f, r.in, "audit")
	if len(ops) > 0 || res == nil {
		t.Fatalf("ops %v, residual %v", ops, res)
	}
	assertJSON(t, res, `{"Check":"KS-X","Finding":{"Object":{"APIVersion":"apps/v1","Kind":"Deployment","Namespace":"ai","Name":"app"},
		"Group":"","Container":"","Path":"`+wlPod+`/x","Message":"","Strength":0},"Reason":"no automatic fix for this finding"}`)
}
