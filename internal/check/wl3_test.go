package check

import "testing"

func TestHostPathFindings(t *testing.T) {
	const spec0 = podSpecPath
	runEngineCases(t, "KS-WL-015", []engineCase{
		{"models directory", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: models
    hostPath: {path: /var/lib/models}
`, []wantFinding{{"", spec0 + "/volumes/0"}}, nil},
		{"two volumes and an emptyDir", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: cache
    emptyDir: {}
  - name: models
    hostPath: {path: /srv/models, type: Directory}
  - name: logs
    hostPath: {path: /var/log}
`, []wantFinding{{"", spec0 + "/volumes/1"}, {"", spec0 + "/volumes/2"}}, nil},
		{"path is cleaned", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: models
    hostPath: {path: /dev/../srv/models}
`, []wantFinding{{"", spec0 + "/volumes/0"}}, nil},
		{"dev lookalikes are not dev", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: a
    hostPath: {path: /devices}
  - name: b
    hostPath: {path: /dev/shmem}
  - name: c
    hostPath: {path: /dev/infiniband}
`, []wantFinding{{"", spec0 + "/volumes/0"}, {"", spec0 + "/volumes/1"}, {"", spec0 + "/volumes/2"}}, nil},
		{"dev and shm are KS-WL-005", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: a
    hostPath: {path: /dev}
  - name: b
    hostPath: {path: /dev/shm}
  - name: c
    hostPath: {path: /dev/shm/cache}
`, nil, nil},
		{"gpu devices are KS-WL-014", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
volumes:
  - name: a
    hostPath: {path: /dev/nvidia0}
  - name: b
    hostPath: {path: /dev/nvidiactl}
`, nil, nil},
		{"no volumes", `
containers:
  - {name: vllm, image: "vllm/vllm-openai:v0.6.0"}
`, nil, nil},
	})
}

func TestHostPathNotApplicable(t *testing.T) {
	c, _ := ByID("KS-WL-015")
	if r := Evaluate(c, &Input{}); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("empty input: %+v", r)
	}
	generic := deployment("containers:\n  - {name: web, image: nginx}\nvolumes:\n  - name: v\n    hostPath: {path: /srv}\n")
	if r := runWL(t, "KS-WL-015", generic); r.Applicable || len(r.Findings) != 0 {
		t.Errorf("generic workload: %+v", r)
	}
}

func TestHostPortFindings(t *testing.T) {
	const ctr0 = podSpecPath + "/containers/0"
	const ctr1 = podSpecPath + "/containers/1"
	runEngineCases(t, "KS-WL-016", []engineCase{
		{"one hostPort", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    ports:
      - {containerPort: 8000, hostPort: 8000}
`, []wantFinding{{"vllm", ctr0 + "/ports/0/hostPort"}}, nil},
		{"two ports, one hostPort", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    ports:
      - {containerPort: 8000}
      - {containerPort: 9000, hostPort: 9000}
`, []wantFinding{{"vllm", ctr0 + "/ports/1/hostPort"}}, nil},
		{"sidecar of an AI workload", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
  - name: proxy
    image: envoyproxy/envoy:v1.31
    ports:
      - {containerPort: 443, hostPort: 443}
`, []wantFinding{{"proxy", ctr1 + "/ports/0/hostPort"}}, nil},
		{"no hostPort", `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    ports:
      - {containerPort: 8000}
`, nil, nil},
		{"init container is not checked", `
initContainers:
  - name: init
    image: busybox
    ports:
      - {containerPort: 80, hostPort: 80}
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
`, nil, nil},
	})
}
