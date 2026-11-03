package check

import (
	"cmp"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	podSpecPath = "/spec/template/spec"
	deployRef   = "Deployment/ai/vllm"
)

const deploymentHead = `apiVersion: apps/v1
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
`

func deployment(podSpec string) string {
	lines := strings.Split(strings.Trim(podSpec, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "      " + l
	}
	return deploymentHead + strings.Join(lines, "\n") + "\n"
}

func runWL(t *testing.T, id, doc string) Result {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := ByID(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	return Evaluate(c, &Input{Objects: objs, Workloads: ws})
}

type wantFinding struct {
	container string
	path      string
}

func sortedFindings(fs []Finding) []wantFinding {
	out := make([]wantFinding, len(fs))
	for i, f := range fs {
		out[i] = wantFinding{f.Container, f.Path}
	}
	slices.SortFunc(out, func(a, b wantFinding) int {
		return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.container, b.container))
	})
	return out
}

func TestWorkloadFindings(t *testing.T) {
	const (
		ctr0  = podSpecPath + "/containers/0"
		init0 = podSpecPath + "/initContainers/0"
	)
	cases := []struct {
		name string
		id   string
		spec string
		want []wantFinding
	}{
		{"wl001 uid 0", "KS-WL-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsUser: 0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/runAsUser"}}},
		{"wl001 nothing set", "KS-WL-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/runAsNonRoot"}}},
		{"wl001 uid 0 with runAsNonRoot true", "KS-WL-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsNonRoot: true
      runAsUser: 0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/runAsUser"}}},
		{"wl001 uid 0 from the pod", "KS-WL-001", `
securityContext:
  runAsUser: 0
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/runAsUser"}}},
		{"wl001 container false over pod true", "KS-WL-001", `
securityContext:
  runAsNonRoot: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsNonRoot: false
`, []wantFinding{{"vllm", ctr0 + "/securityContext/runAsNonRoot"}}},
		{"wl001 init container only", "KS-WL-001", `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsNonRoot: true
`, []wantFinding{{"setup", init0 + "/securityContext/runAsNonRoot"}}},
		{"wl001 pod runAsNonRoot", "KS-WL-001", `
securityContext:
  runAsNonRoot: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, nil},
		{"wl001 uid 1000 without runAsNonRoot", "KS-WL-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsUser: 1000
`, nil},
		{"wl001 uid 1000 with runAsNonRoot false", "KS-WL-001", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsNonRoot: false
      runAsUser: 1000
`, nil},
		{"wl001 container uid over pod uid 0", "KS-WL-001", `
securityContext:
  runAsUser: 0
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      runAsUser: 1000
`, nil},

		{"wl002 privileged and escalation unset", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      privileged: true
`, []wantFinding{
			{"vllm", ctr0 + "/securityContext/allowPrivilegeEscalation"},
			{"vllm", ctr0 + "/securityContext/privileged"},
		}},
		{"wl002 privileged and escalation true", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
`, []wantFinding{
			{"vllm", ctr0 + "/securityContext/allowPrivilegeEscalation"},
			{"vllm", ctr0 + "/securityContext/privileged"},
		}},
		{"wl002 privileged only", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      privileged: true
      allowPrivilegeEscalation: false
`, []wantFinding{{"vllm", ctr0 + "/securityContext/privileged"}}},
		{"wl002 escalation unset", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/allowPrivilegeEscalation"}}},
		{"wl002 escalation true", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      privileged: false
      allowPrivilegeEscalation: true
`, []wantFinding{{"vllm", ctr0 + "/securityContext/allowPrivilegeEscalation"}}},
		{"wl002 init container", "KS-WL-002", `
initContainers:
  - name: setup
    image: busybox:1.36
    securityContext:
      privileged: true
      allowPrivilegeEscalation: false
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      allowPrivilegeEscalation: false
`, []wantFinding{{"setup", init0 + "/securityContext/privileged"}}},
		{"wl002 hardened", "KS-WL-002", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
`, nil},

		{"wl003 nothing set", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"vllm", ctr0 + "/securityContext/capabilities"}}},
		{"wl003 drop other than ALL", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["NET_RAW"]
`, []wantFinding{{"vllm", ctr0 + "/securityContext/capabilities"}}},
		{"wl003 add SYS_ADMIN", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["SYS_ADMIN"]
`, []wantFinding{{"vllm", ctr0 + "/securityContext/capabilities"}}},
		{"wl003 add NET_BIND_SERVICE and another", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE", "SYS_PTRACE"]
`, []wantFinding{{"vllm", ctr0 + "/securityContext/capabilities"}}},
		{"wl003 both problems give one finding", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]
`, []wantFinding{{"vllm", ctr0 + "/securityContext/capabilities"}}},
		{"wl003 init container", "KS-WL-003", `
initContainers:
  - name: setup
    image: busybox:1.36
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["ALL"]
`, []wantFinding{{"setup", init0 + "/securityContext/capabilities"}}},
		{"wl003 drop ALL", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["ALL"]
`, nil},
		{"wl003 drop all lowercase with NET_BIND_SERVICE", "KS-WL-003", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        drop: ["NET_RAW", "all"]
        add: ["NET_BIND_SERVICE"]
`, nil},

		{"wl004 all three fields", "KS-WL-004", `
hostIPC: true
hostPID: true
hostNetwork: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{
			{"", podSpecPath + "/hostIPC"},
			{"", podSpecPath + "/hostNetwork"},
			{"", podSpecPath + "/hostPID"},
		}},
		{"wl004 hostIPC and hostPID", "KS-WL-004", `
hostIPC: true
hostPID: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{
			{"", podSpecPath + "/hostIPC"},
			{"", podSpecPath + "/hostPID"},
		}},
		{"wl004 hostNetwork only", "KS-WL-004", `
hostIPC: false
hostNetwork: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"", podSpecPath + "/hostNetwork"}}},
		{"wl004 none", "KS-WL-004", `
hostIPC: false
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, nil},

		{"wl005 hostPath dev shm", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: data
    emptyDir: {}
  - name: shm
    hostPath:
      path: /dev/shm
`, []wantFinding{{"", podSpecPath + "/volumes/1"}}},
		{"wl005 hostPath dev", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: dev
    hostPath:
      path: /dev
`, []wantFinding{{"", podSpecPath + "/volumes/0"}}},
		{"wl005 hostPath dev with trailing slash", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: dev
    hostPath:
      path: /dev/
`, []wantFinding{{"", podSpecPath + "/volumes/0"}}},
		{"wl005 hostPath below dev shm", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: nccl
    hostPath:
      path: /dev/shm/nccl
`, []wantFinding{{"", podSpecPath + "/volumes/0"}}},
		{"wl005 hostPath cleaned into dev", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: dev
    hostPath:
      path: /dev/shm/../nvidia0/..
`, []wantFinding{{"", podSpecPath + "/volumes/0"}}},
		{"wl005 two hostPath volumes", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: shm
    hostPath:
      path: /dev/shm
  - name: dev
    hostPath:
      path: /dev
`, []wantFinding{
			{"", podSpecPath + "/volumes/0"},
			{"", podSpecPath + "/volumes/1"},
		}},
		{"wl005 lookalike hostPaths", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: a
    hostPath:
      path: /dev/shmem
  - name: b
    hostPath:
      path: /devices
  - name: c
    hostPath:
      path: /dev/nvidia0
  - name: d
    hostPath:
      path: /data/dev/shm
`, nil},
		{"wl005 emptyDir shm", "KS-WL-005", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: shm
    emptyDir:
      medium: Memory
      sizeLimit: 8Gi
`, nil},

		{"wl006 memory emptyDir without sizeLimit", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: data
    emptyDir: {}
  - name: shm
    emptyDir:
      medium: Memory
`, []wantFinding{{"", podSpecPath + "/volumes/1/emptyDir/sizeLimit"}}},
		{"wl006 one finding when mounted in two containers", "KS-WL-006", `
initContainers:
  - name: warmup
    image: busybox:1.36
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: shm
    emptyDir:
      medium: Memory
`, []wantFinding{{"", podSpecPath + "/volumes/0/emptyDir/sizeLimit"}}},
		{"wl006 mount path cleaned", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev//shm/
volumes:
  - name: shm
    emptyDir:
      medium: Memory
`, []wantFinding{{"", podSpecPath + "/volumes/0/emptyDir/sizeLimit"}}},
		{"wl006 sizeLimit set", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: shm
    emptyDir:
      medium: Memory
      sizeLimit: 8Gi
`, nil},
		{"wl006 memory emptyDir mounted elsewhere", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: scratch
        mountPath: /scratch
      - name: other
        mountPath: /dev/shm2
volumes:
  - name: scratch
    emptyDir:
      medium: Memory
  - name: other
    emptyDir:
      medium: Memory
`, nil},
		{"wl006 disk emptyDir at shm", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: shm
    emptyDir: {}
`, nil},
		{"wl006 memory emptyDir with no mount", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
volumes:
  - name: shm
    emptyDir:
      medium: Memory
`, nil},
		{"wl006 hostPath at shm is not this check", "KS-WL-006", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: shm
    hostPath:
      path: /dev/shm
`, nil},

		{"wl007 shared", "KS-WL-007", `
shareProcessNamespace: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, []wantFinding{{"", podSpecPath + "/shareProcessNamespace"}}},
		{"wl007 false", "KS-WL-007", `
shareProcessNamespace: false
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, nil},
		{"wl007 unset", "KS-WL-007", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, tc.id, deployment(tc.spec))
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			got := sortedFindings(r.Findings)
			want := slices.Clone(tc.want)
			slices.SortFunc(want, func(a, b wantFinding) int {
				return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.container, b.container))
			})
			if !slices.Equal(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
			for _, f := range r.Findings {
				if f.Object.String() != deployRef || f.Group != "" || f.Strength != Violation || f.Message == "" {
					t.Errorf("bad finding %+v", f)
				}
			}
		})
	}
}

func TestWorkloadFindingGroup(t *testing.T) {
	doc := `apiVersion: ray.io/v1
kind: RayCluster
metadata:
  name: rc
  namespace: ai
spec:
  headGroupSpec:
    template:
      spec:
        shareProcessNamespace: true
        containers:
          - name: ray-head
            image: rayproject/ray:2.9.0
  workerGroupSpecs:
    - groupName: gpu
      template:
        spec:
          shareProcessNamespace: true
          containers:
            - name: ray-worker
              image: rayproject/ray:2.9.0-gpu
`
	r := runWL(t, "KS-WL-007", doc)
	if len(r.Findings) != 2 {
		t.Fatalf("got %+v", r.Findings)
	}
	byGroup := map[string]Finding{}
	for _, f := range r.Findings {
		byGroup[f.Group] = f
	}
	head, worker := byGroup["head"], byGroup["gpu"]
	if head.Path != "/spec/headGroupSpec/template/spec/shareProcessNamespace" || head.Object.String() != "RayCluster/ai/rc" {
		t.Errorf("head %+v", head)
	}
	if worker.Path != "/spec/workerGroupSpecs/0/template/spec/shareProcessNamespace" || worker.Object.String() != "RayCluster/ai/rc" {
		t.Errorf("worker %+v", worker)
	}
}

func TestCapabilitiesMessageNamesBothProblems(t *testing.T) {
	r := runWL(t, "KS-WL-003", deployment(`
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "NET_BIND_SERVICE", "SYS_PTRACE"]
`))
	if len(r.Findings) != 1 {
		t.Fatalf("got %+v", r.Findings)
	}
	m := r.Findings[0].Message
	for _, want := range []string{"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_BIND_SERVICE"} {
		if !strings.Contains(m, want) {
			t.Errorf("message %q lacks %q", m, want)
		}
	}
}

func TestWorkloadChecksApplicability(t *testing.T) {
	generic := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: ai
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      shareProcessNamespace: true
      containers:
        - name: nginx
          image: nginx:1.27
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: shm
              mountPath: /dev/shm
      volumes:
        - name: shm
          hostPath:
            path: /dev/shm
`
	hardened := deployment(`
securityContext:
  runAsNonRoot: true
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    volumeMounts:
      - name: shm
        mountPath: /dev/shm
volumes:
  - name: shm
    emptyDir:
      medium: Memory
      sizeLimit: 8Gi
`)
	for _, id := range []string{"KS-WL-001", "KS-WL-002", "KS-WL-003", "KS-WL-004", "KS-WL-005", "KS-WL-006", "KS-WL-007"} {
		t.Run(id, func(t *testing.T) {
			c, ok := ByID(id)
			if !ok {
				t.Fatalf("%s is not registered", id)
			}
			if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
				t.Errorf("empty input: %+v", r)
			}
			if r := runWL(t, id, generic); r.Applicable || len(r.Findings) != 0 {
				t.Errorf("generic workload only: %+v", r)
			}
			if r := runWL(t, id, hardened); !r.Applicable || len(r.Findings) != 0 {
				t.Errorf("hardened AI workload: %+v", r)
			}
		})
	}
}

func TestWorkloadChecksRegistered(t *testing.T) {
	want := []struct {
		id    string
		title string
		fix   Fix
	}{
		{"KS-WL-001", "Container may run as root (no runAsNonRoot: true, or UID 0)", FixPatch},
		{"KS-WL-002", "privileged: true or allowPrivilegeEscalation not false", FixPatch},
		{"KS-WL-003", "Capabilities not dropped (drop: [ALL] missing)", FixPatch},
		{"KS-WL-004", "hostIPC, hostPID or hostNetwork true", FixPatch},
		{"KS-WL-005", "/dev/shm from hostPath (or hostPath /dev)", FixPatch},
		{"KS-WL-006", "Memory emptyDir for shm without sizeLimit", FixPatch},
		{"KS-WL-007", "shareProcessNamespace: true on AI workload", FixPatch},
	}
	all := All()
	if len(all) < len(want) {
		t.Fatalf("catalog has %d checks", len(all))
	}
	for i, w := range want {
		c := all[i]
		if c.ID != w.id || c.Title != w.title || c.Fix != w.fix || c.Tier != Both {
			t.Errorf("catalog[%d] = %s %q fix=%s tier=%d, want %s %q fix=%s tier=%d", i, c.ID, c.Title, c.Fix, c.Tier, w.id, w.title, w.fix, Both)
		}
	}
}
