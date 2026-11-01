package check

import (
	"cmp"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

type ai2Want struct {
	object    string
	group     string
	container string
	path      string
	strength  Strength
}

type ai2Case struct {
	name string
	doc  string
	want []ai2Want
}

func runAI2Cases(t *testing.T, id string, cases []ai2Case) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runWL(t, id, tc.doc)
			if !r.Applicable {
				t.Fatal("must be applicable")
			}
			var got []ai2Want
			for _, f := range r.Findings {
				got = append(got, ai2Want{f.Object.String(), f.Group, f.Container, f.Path, f.Strength})
				if f.Message == "" {
					t.Errorf("empty message %+v", f)
				}
			}
			want := slices.Clone(tc.want)
			order := func(a, b ai2Want) int {
				return cmp.Or(cmp.Compare(a.object, b.object), cmp.Compare(a.group, b.group), cmp.Compare(a.path, b.path), cmp.Compare(a.container, b.container), cmp.Compare(a.strength, b.strength))
			}
			slices.SortFunc(got, order)
			slices.SortFunc(want, order)
			if !slices.Equal(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
		})
	}
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.Trim(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func rayHead(fields, env string) string {
	s := fields + `template:
  spec:
    containers:
      - name: ray-head
        image: rayproject/ray:2.9.0
        ports:
          - name: gcs
            containerPort: 6379
          - name: dashboard
            containerPort: 8265
          - name: client
            containerPort: 10001
          - name: serve
            containerPort: 8000
`
	if env != "" {
		s += indent("env:\n"+env, 8)
	}
	return s
}

func rayWorker(group, env string) string {
	s := "- groupName: " + group + `
  template:
    spec:
      containers:
        - name: ray-worker
          image: rayproject/ray:2.9.0-gpu
`
	if env != "" {
		s += indent("env:\n"+env, 10)
	}
	return s
}

func rayDoc(kind, base, head, workers string) string {
	doc := "apiVersion: ray.io/v1\nkind: " + kind + "\nmetadata:\n  name: rc\n  namespace: ai\nspec:\n"
	body := "headGroupSpec:\n" + indent(head, 2)
	if workers != "" {
		body += "workerGroupSpecs:\n" + indent(workers, 2)
	}
	if base != "" {
		body = base + ":\n" + indent(body, 2)
	}
	return doc + indent(body, 2)
}

func rayCluster(head, workers string) string {
	return rayDoc("RayCluster", "", head, workers)
}

const (
	rcRef    = "RayCluster/ai/rc"
	tlsOn    = "- name: RAY_USE_TLS\n  value: \"1\"\n"
	tlsOff   = "- name: RAY_USE_TLS\n  value: \"0\"\n"
	tlsFrom  = "- name: RAY_USE_TLS\n  valueFrom:\n    configMapKeyRef:\n      name: ray\n      key: tls\n"
	headSpec = "/spec/headGroupSpec"
)

func headSvc(name, typ, selector string, ports ...string) string {
	return svcDoc("ai", name, typ, selector, ports...)
}

func TestRayExposed(t *testing.T) {
	cluster := rayCluster(rayHead("", ""), rayWorker("gpu", ""))
	headSel := `ray.io/node-type: head`
	runAI2Cases(t, "KS-AI-005", []ai2Case{
		{name: "nodeport head service", doc: rayCluster(rayHead("serviceType: NodePort\n", ""), ""),
			want: []ai2Want{{rcRef, "head", "", headSpec + "/serviceType", Violation}}},
		{name: "loadbalancer head service", doc: rayCluster(rayHead("serviceType: LoadBalancer\n", ""), ""),
			want: []ai2Want{{rcRef, "head", "", headSpec + "/serviceType", Violation}}},
		{name: "clusterip head service", doc: rayCluster(rayHead("serviceType: ClusterIP\n", ""), "")},
		{name: "enable ingress", doc: rayCluster(rayHead("enableIngress: true\n", ""), ""),
			want: []ai2Want{{rcRef, "head", "", headSpec + "/enableIngress", Violation}}},
		{name: "ingress disabled", doc: rayCluster(rayHead("enableIngress: false\n", ""), "")},
		{name: "both", doc: rayCluster(rayHead("serviceType: NodePort\nenableIngress: true\n", ""), ""),
			want: []ai2Want{
				{rcRef, "head", "", headSpec + "/serviceType", Violation},
				{rcRef, "head", "", headSpec + "/enableIngress", Violation},
			}},
		{name: "rayservice prefix", doc: rayDoc("RayService", "rayClusterConfig", rayHead("serviceType: NodePort\n", ""), ""),
			want: []ai2Want{{"RayService/ai/rc", "head", "", "/spec/rayClusterConfig/headGroupSpec/serviceType", Violation}}},
		{name: "rayjob prefix", doc: rayDoc("RayJob", "rayClusterSpec", rayHead("enableIngress: true\n", ""), ""),
			want: []ai2Want{{"RayJob/ai/rc", "head", "", "/spec/rayClusterSpec/headGroupSpec/enableIngress", Violation}}},
		{name: "user service on dashboard port", doc: cluster + headSvc("dash", "LoadBalancer", headSel, "port: 8265"),
			want: []ai2Want{{"Service/ai/dash", "", "", serviceTypePath, Violation}}},
		{name: "user service on gcs target port", doc: cluster + headSvc("gcs", "NodePort", headSel, "port: 80\ntargetPort: 6379"),
			want: []ai2Want{{"Service/ai/gcs", "", "", serviceTypePath, Violation}}},
		{name: "user service on named client port", doc: cluster + headSvc("client", "NodePort", headSel, "port: 80\ntargetPort: client"),
			want: []ai2Want{{"Service/ai/client", "", "", serviceTypePath, Violation}}},
		{name: "user service on serve port", doc: cluster + headSvc("serve", "LoadBalancer", headSel, "port: 8000")},
		{name: "user service on named serve port", doc: cluster + headSvc("serve", "LoadBalancer", headSel, "port: 80\ntargetPort: serve")},
		{name: "clusterip user service", doc: cluster + headSvc("dash", "ClusterIP", headSel, "port: 8265")},
		{name: "user service by group label", doc: cluster + headSvc("dash", "LoadBalancer", "ray.io/group: headgroup", "port: 8265"),
			want: []ai2Want{{"Service/ai/dash", "", "", serviceTypePath, Violation}}},
		{name: "user service for a worker group", doc: cluster + headSvc("w", "LoadBalancer", "ray.io/group: gpu", "port: 6379")},
		{name: "ingress to head dashboard", doc: cluster + headSvc("dash", "", headSel, "port: 8265") + ingressDoc("networking.k8s.io/v1", "ai", "dash", "", portRuleSpec("dash", "number: 8265")),
			want: []ai2Want{{"Ingress/ai/dash", "", "", ingressRulesPath, Violation}}},
		{name: "ingress with auth still exposes", doc: cluster + headSvc("dash", "", headSel, "port: 8265") + ingressDoc("networking.k8s.io/v1", "ai", "dash", "    nginx.ingress.kubernetes.io/auth-url: https://auth\n", portRuleSpec("dash", "number: 8265")),
			want: []ai2Want{{"Ingress/ai/dash", "", "", ingressRulesPath, Violation}}},
		{name: "ingress to two head services is one finding", doc: cluster + headSvc("a", "", headSel, "port: 8265") + headSvc("b", "", headSel, "port: 6379") +
			ingressDoc("networking.k8s.io/v1", "ai", "dash", "", portRulesSpec([2]string{"a", "number: 8265"}, [2]string{"b", "number: 6379"})),
			want: []ai2Want{{"Ingress/ai/dash", "", "", ingressRulesPath, Violation}}},
		{name: "ingress to head serve port only", doc: cluster + headSvc("serve", "", headSel, "port: 80\ntargetPort: serve") + ingressDoc("networking.k8s.io/v1", "ai", "serve", "", ruleSpec("serve"))},
		{name: "ingress to serve and dashboard services", doc: cluster + headSvc("serve", "", headSel, "port: 8000") + headSvc("dash", "", headSel, "port: 8265") +
			ingressDoc("networking.k8s.io/v1", "ai", "mixed", "", portRulesSpec([2]string{"serve", "number: 8000"}, [2]string{"dash", "number: 8265"})),
			want: []ai2Want{{"Ingress/ai/mixed", "", "", ingressRulesPath, Violation}}},
		{name: "ingress to the serve port of a head service that also has the dashboard port", doc: cluster + headSvc("head", "", headSel, "name: serve\nport: 8000", "name: dashboard\nport: 8265") +
			ingressDoc("networking.k8s.io/v1", "ai", "serve", "", portRuleSpec("head", "number: 8000"))},
		{name: "ingress to the named dashboard port of a head service", doc: cluster + headSvc("head", "", headSel, "name: serve\nport: 8000", "name: dashboard\nport: 8265") +
			ingressDoc("networking.k8s.io/v1", "ai", "dash", "", portRuleSpec("head", "name: dashboard")),
			want: []ai2Want{{"Ingress/ai/dash", "", "", ingressRulesPath, Violation}}},
		{name: "ingress to a port the head service lacks", doc: cluster + headSvc("dash", "", headSel, "port: 8265") + ingressDoc("networking.k8s.io/v1", "ai", "dash", "", ruleSpec("dash"))},
		{name: "rayservice head selected without cluster label", doc: rayDoc("RayService", "rayClusterConfig", rayHead("", ""), "") + headSvc("dash", "LoadBalancer", headSel, "port: 8265"),
			want: []ai2Want{{"Service/ai/dash", "", "", serviceTypePath, Violation}}},
		{name: "vllm on dashboard port is not ray", doc: deployment(vllmContainerSpec) + svcDoc("ai", "v", "LoadBalancer", "app: vllm", "port: 8265")},
	})
}

func TestRayTLS(t *testing.T) {
	const (
		headEnv   = headSpec + "/template/spec/containers/0/env"
		workerEnv = "/spec/workerGroupSpecs/0/template/spec/containers/0/env"
	)
	runAI2Cases(t, "KS-AI-006", []ai2Case{
		{name: "all groups on", doc: rayCluster(rayHead("", tlsOn), rayWorker("gpu", tlsOn))},
		{name: "unset worker", doc: rayCluster(rayHead("", tlsOn), rayWorker("gpu", "")),
			want: []ai2Want{{rcRef, "gpu", "ray-worker", workerEnv, Violation}}},
		{name: "all unset", doc: rayCluster(rayHead("", ""), rayWorker("gpu", "")+rayWorker("cpu", "")),
			want: []ai2Want{
				{rcRef, "head", "ray-head", headEnv, Violation},
				{rcRef, "gpu", "ray-worker", workerEnv, Violation},
				{rcRef, "cpu", "ray-worker", "/spec/workerGroupSpecs/1/template/spec/containers/0/env", Violation},
			}},
		{name: "zero", doc: rayCluster(rayHead("", tlsOff), rayWorker("gpu", tlsOn)),
			want: []ai2Want{{rcRef, "head", "ray-head", headEnv, Violation}}},
		{name: "true is not 1", doc: rayCluster(rayHead("", "- name: RAY_USE_TLS\n  value: \"true\"\n"), rayWorker("gpu", tlsOn)),
			want: []ai2Want{{rcRef, "head", "ray-head", headEnv, Violation}}},
		{name: "last duplicate wins", doc: rayCluster(rayHead("", tlsOn+tlsOff), rayWorker("gpu", tlsOff+tlsOn)),
			want: []ai2Want{{rcRef, "head", "ray-head", headEnv, Violation}}},
		{name: "value from", doc: rayCluster(rayHead("", tlsOn), rayWorker("gpu", tlsFrom)),
			want: []ai2Want{{rcRef, "gpu", "ray-worker", workerEnv, Suspect}}},
		{name: "rayservice", doc: rayDoc("RayService", "rayClusterConfig", rayHead("", ""), ""),
			want: []ai2Want{{"RayService/ai/rc", "head", "ray-head", "/spec/rayClusterConfig/headGroupSpec/template/spec/containers/0/env", Violation}}},
		{name: "only containers 0 counts", doc: rayCluster(`template:
  spec:
    initContainers:
      - name: init
        image: busybox:1.36
    containers:
      - name: ray-head
        image: rayproject/ray:2.9.0
        env:
          - name: RAY_USE_TLS
            value: "1"
      - name: sidecar
        image: busybox:1.36
`, "")},
		{name: "init container is not containers 0", doc: rayCluster(`template:
  spec:
    initContainers:
      - name: init
        image: rayproject/ray:2.9.0
        env:
          - name: RAY_USE_TLS
            value: "1"
    containers:
      - name: ray-head
        image: rayproject/ray:2.9.0
`, ""), want: []ai2Want{{rcRef, "head", "ray-head", headEnv, Violation}}},
		{name: "ray image in a deployment is not a ray group", doc: deployment("containers:\n  - name: ray\n    image: rayproject/ray:2.9.0\n")},
	})
}

const ollamaSpec = `
containers:
  - name: ollama
    image: ollama/ollama:0.12.0
    ports:
      - containerPort: 11434
`

func TestOllamaExposed(t *testing.T) {
	sel := "app: vllm"
	runAI2Cases(t, "KS-AI-007", []ai2Case{
		{name: "loadbalancer", doc: deployment(ollamaSpec) + svcDoc("ai", "o", "LoadBalancer", sel, "port: 11434"),
			want: []ai2Want{{"Service/ai/o", "", "", serviceTypePath, Violation}}},
		{name: "nodeport on any port", doc: deployment(ollamaSpec) + svcDoc("ai", "o", "NodePort", sel, "port: 9999"),
			want: []ai2Want{{"Service/ai/o", "", "", serviceTypePath, Violation}}},
		{name: "clusterip", doc: deployment(ollamaSpec) + svcDoc("ai", "o", "ClusterIP", sel, "port: 11434")},
		{name: "ingress without auth", doc: deployment(ollamaSpec) + svcDoc("ai", "o", "", sel, "port: 11434") + ingressDoc("networking.k8s.io/v1", "ai", "o", "", ruleSpec("o")),
			want: []ai2Want{{"Ingress/ai/o", "", "", ingressRulesPath, Violation}}},
		{name: "ingress with auth", doc: deployment(ollamaSpec) + svcDoc("ai", "o", "", sel, "port: 11434") + ingressDoc("networking.k8s.io/v1", "ai", "o", "    nginx.ingress.kubernetes.io/auth-url: https://auth\n", ruleSpec("o"))},
		{name: "vllm is not ollama", doc: deployment(vllmContainerSpec) + svcDoc("ai", "v", "LoadBalancer", sel, "port: 8000")},
	})
}

const qdrantSpec = `
containers:
  - name: qdrant
    image: qdrant/qdrant:v1.19.2
`

func qdrantEnv(env string) string {
	return qdrantSpec + indent("env:\n"+env, 4)
}

func TestQdrantAuthTLS(t *testing.T) {
	const env = ctr0Path + "/env"
	key := ai2Want{deployRef, "", "qdrant", env, Violation}
	keyFrom := "- name: QDRANT__SERVICE__API_KEY\n  valueFrom:\n    secretKeyRef:\n      name: q\n      key: k\n"
	tls := "- name: QDRANT__SERVICE__ENABLE_TLS\n  value: \"true\"\n"
	cfg := func(data string) string { return configMapDoc("ai", "qcfg", "  production.yaml: \""+data+"\"\n") }
	mountedEnv := func(env string) string {
		s := qdrantSpec + "    volumeMounts:\n      - name: cfg\n        mountPath: /qdrant/config/production.yaml\n        subPath: production.yaml\n"
		if env != "" {
			s += indent("env:\n"+env, 4)
		}
		return s + "volumes:\n  - name: cfg\n    configMap:\n      name: qcfg\n"
	}
	mounted := mountedEnv("")
	runAI2Cases(t, "KS-AI-008", []ai2Case{
		{name: "nothing", doc: deployment(qdrantSpec), want: []ai2Want{key, key}},
		{name: "env secret and tls", doc: deployment(qdrantEnv(keyFrom + tls))},
		{name: "literal key and tls 1", doc: deployment(qdrantEnv("- name: QDRANT__SERVICE__API_KEY\n  value: k\n- name: QDRANT__SERVICE__ENABLE_TLS\n  value: \"1\"\n"))},
		{name: "empty key", doc: deployment(qdrantEnv("- name: QDRANT__SERVICE__API_KEY\n  value: \"\"\n" + tls)), want: []ai2Want{key}},
		{name: "tls from a reference", doc: deployment(qdrantEnv(keyFrom + "- name: QDRANT__SERVICE__ENABLE_TLS\n  valueFrom:\n    configMapKeyRef:\n      name: q\n      key: tls\n")),
			want: []ai2Want{{deployRef, "", "qdrant", env, Suspect}}},
		{name: "tls false", doc: deployment(qdrantEnv(keyFrom + "- name: QDRANT__SERVICE__ENABLE_TLS\n  value: \"false\"\n")), want: []ai2Want{key}},
		{name: "config map", doc: deployment(mounted) + cfg(`service:\n  api_key: k\n  enable_tls: true\n`)},
		{name: "config map without key", doc: deployment(mounted) + cfg(`service:\n  enable_tls: true\n`), want: []ai2Want{key}},
		{name: "config map empty key", doc: deployment(mounted) + cfg(`service:\n  api_key: \"\"\n  enable_tls: true\n`), want: []ai2Want{key}},
		{name: "config map tls false", doc: deployment(mounted) + cfg(`service:\n  api_key: k\n  enable_tls: false\n`), want: []ai2Want{key}},
		{name: "env overrides config", doc: deployment(mountedEnv("- name: QDRANT__SERVICE__API_KEY\n  value: \"\"\n- name: QDRANT__SERVICE__ENABLE_TLS\n  value: \"false\"\n")) + cfg(`service:\n  api_key: k\n  enable_tls: true\n`),
			want: []ai2Want{key, key}},
		{name: "qdrant is the second container", doc: deployment("containers:\n  - name: proxy\n    image: nginx:1.27\n  - name: qdrant\n    image: qdrant/qdrant:v1.19.2\n"),
			want: []ai2Want{{deployRef, "", "qdrant", podSpecPath + "/containers/1/env", Violation}, {deployRef, "", "qdrant", podSpecPath + "/containers/1/env", Violation}}},
		{name: "vllm is not qdrant", doc: deployment(vllmContainerSpec)},
	})
}

func qdrantSecretMounted(env string) string {
	return qdrantSecretAt(env, "    volumeMounts:\n      - name: key\n        mountPath: /qdrant/config/local.yaml\n        subPath: local.yaml\n")
}

func qdrantMount(mountPath string) string {
	return "    volumeMounts:\n      - name: key\n        mountPath: " + mountPath + "\n"
}

func qdrantSecretAt(env, mounts string) string {
	s := qdrantSpec + mounts
	if env != "" {
		s += indent("env:\n"+env, 4)
	}
	return s + "volumes:\n  - name: key\n    secret:\n      secretName: qkey\n"
}

func qdrantSecretDoc(data string) string {
	return "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: qkey\n  namespace: ai\ndata:\n  local.yaml: " + data + "\n"
}

func TestQdrantSecretVolume(t *testing.T) {
	const env = ctr0Path + "/env"
	v := ai2Want{deployRef, "", "qdrant", env, Violation}
	s := ai2Want{deployRef, "", "qdrant", env, Suspect}
	keyAndTLS := base64.StdEncoding.EncodeToString([]byte("service:\n  api_key: k\n  enable_tls: true\n"))
	keyOnly := base64.StdEncoding.EncodeToString([]byte("service:\n  api_key: k\n"))
	tlsOnly := base64.StdEncoding.EncodeToString([]byte("service:\n  enable_tls: true\n"))
	cfgKey := configMapDoc("ai", "qcfg", "  production.yaml: \"service:\\n  api_key: k\\n\"\n")
	withCfg := func(spec string) string {
		return spec + "  - name: cfg\n    configMap:\n      name: qcfg\n"
	}
	runAI2Cases(t, "KS-AI-008", []ai2Case{
		{name: "secret sets key and tls", doc: deployment(qdrantSecretMounted("")) + qdrantSecretDoc(keyAndTLS)},
		{name: "secret sets key only", doc: deployment(qdrantSecretMounted("")) + qdrantSecretDoc(keyOnly), want: []ai2Want{v}},
		{name: "secret sets tls only", doc: deployment(qdrantSecretMounted("")) + qdrantSecretDoc(tlsOnly), want: []ai2Want{v}},
		{name: "secret not in input", doc: deployment(qdrantSecretMounted("")), want: []ai2Want{s, v}},
		{name: "secret in another namespace", doc: deployment(qdrantSecretMounted("")) + strings.Replace(qdrantSecretDoc(keyAndTLS), "namespace: ai", "namespace: other", 1), want: []ai2Want{s, v}},
		{name: "secret not in input, empty env key wins", doc: deployment(qdrantSecretMounted("- name: QDRANT__SERVICE__API_KEY\n  value: \"\"\n")), want: []ai2Want{v, v}},
		{name: "secret not in input, config map sets key", doc: deployment(withCfg(qdrantSecretMounted(""))) + cfgKey, want: []ai2Want{v}},
		{name: "secret not in input, mounted as the config dir", doc: deployment(qdrantSecretAt("", qdrantMount("/qdrant/config"))), want: []ai2Want{s, v}},
		{name: "secret not in input, unclean config path", doc: deployment(qdrantSecretAt("", qdrantMount("/qdrant//config/./local.yaml"))), want: []ai2Want{s, v}},
		{name: "secret not in input, mounted for tls certs", doc: deployment(qdrantSecretAt("", qdrantMount("/qdrant/tls"))), want: []ai2Want{v, v}},
		{name: "secret not in input, sibling of the config dir", doc: deployment(qdrantSecretAt("", qdrantMount("/qdrant/configx/local.yaml"))), want: []ai2Want{v, v}},
		{name: "secret not in input, not mounted", doc: deployment(qdrantSecretAt("", "")), want: []ai2Want{v, v}},
	})
}

func TestQdrantMessagesHideSecretValues(t *testing.T) {
	const value = "s3cr3t-value"
	doc := deployment(qdrantSecretMounted("")) + qdrantSecretDoc(base64.StdEncoding.EncodeToString([]byte("service:\n  api_key: "+value+"\n")))
	for _, d := range []string{doc, deployment(qdrantSecretMounted(""))} {
		r := runWL(t, "KS-AI-008", d)
		if len(r.Findings) == 0 {
			t.Fatal("want findings")
		}
		for _, f := range r.Findings {
			if strings.Contains(f.Message, value) {
				t.Fatalf("message leaks the secret value: %q", f.Message)
			}
		}
	}
	r := runWL(t, "KS-AI-008", deployment(qdrantSecretMounted("")))
	if !slices.ContainsFunc(r.Findings, func(f Finding) bool { return f.Strength == Suspect && strings.Contains(f.Message, "qkey") }) {
		t.Fatalf("want a Suspect that names Secret qkey, got %+v", r.Findings)
	}
}

func TestQdrantSuspectNamesSecretOnce(t *testing.T) {
	mounts := "    volumeMounts:\n      - name: key\n        mountPath: /qdrant/config/local.yaml\n        subPath: local.yaml\n      - name: key2\n        mountPath: /qdrant/config/extra.yaml\n        subPath: extra.yaml\n"
	doc := deployment(qdrantSecretAt("", mounts) + "  - name: key2\n    secret:\n      secretName: qkey\n")
	r := runWL(t, "KS-AI-008", doc)
	var msgs []string
	for _, f := range r.Findings {
		if f.Strength == Suspect {
			msgs = append(msgs, f.Message)
		}
	}
	if len(msgs) != 1 || strings.Count(msgs[0], "qkey") != 1 {
		t.Fatalf("want one Suspect naming qkey once, got %q", msgs)
	}
}

func TestQdrantMessagesDiffer(t *testing.T) {
	r := runWL(t, "KS-AI-008", deployment(qdrantSpec))
	if len(r.Findings) != 2 || r.Findings[0].Message == r.Findings[1].Message {
		t.Fatalf("want two findings with distinct messages, got %+v", r.Findings)
	}
}

const milvusSpec = `
containers:
  - name: milvus
    image: milvusdb/milvus:v3.0.3
`

func TestMilvusAuthorization(t *testing.T) {
	vols := podSpecPath + "/volumes"
	finding := []ai2Want{{deployRef, "", "", vols, Violation}}
	volumes := "volumes:\n  - name: cfg\n    configMap:\n      name: milvus\n"
	mounted := milvusSpec + volumes
	cfg := func(v string) string {
		return configMapDoc("ai", "milvus", "  default.yaml: \"etcd:\\n  endpoints: [e]\\n\"\n  user.yaml: \"common:\\n  security:\\n    authorizationEnabled: "+v+"\\n\"\n")
	}
	env := func(spec, e string) string { return spec + indent("env:\n"+e, 4) }
	runAI2Cases(t, "KS-AI-009", []ai2Case{
		{name: "default", doc: deployment(milvusSpec), want: finding},
		{name: "config enabled", doc: deployment(mounted) + cfg("true")},
		{name: "config disabled", doc: deployment(mounted) + cfg("false"), want: finding},
		{name: "user.yaml false overrides default.yaml true", doc: deployment(mounted) + configMapDoc("ai", "milvus", "  default.yaml: \"common:\\n  security:\\n    authorizationEnabled: true\\n\"\n  user.yaml: \"common:\\n  security:\\n    authorizationEnabled: false\\n\"\n"), want: finding},
		{name: "user.yaml true overrides default.yaml false", doc: deployment(mounted) + configMapDoc("ai", "milvus", "  default.yaml: \"common:\\n  security:\\n    authorizationEnabled: false\\n\"\n  user.yaml: \"common:\\n  security:\\n    authorizationEnabled: true\\n\"\n")},
		{name: "config map not mounted", doc: deployment(milvusSpec) + cfg("true"), want: finding},
		{name: "env enabled", doc: deployment(env(milvusSpec, "- name: COMMON_SECURITY_AUTHORIZATIONENABLED\n  value: \"true\"\n"))},
		{name: "prefixed env enabled", doc: deployment(env(milvusSpec, "- name: MILVUS_CONF_COMMON_SECURITY_AUTHORIZATIONENABLED\n  value: \"true\"\n"))},
		{name: "env disables config", doc: deployment(env(milvusSpec, "- name: COMMON_SECURITY_AUTHORIZATIONENABLED\n  value: \"false\"\n")+volumes) + cfg("true"), want: finding},
		{name: "env from a reference", doc: deployment(env(milvusSpec, "- name: COMMON_SECURITY_AUTHORIZATIONENABLED\n  valueFrom:\n    configMapKeyRef:\n      name: m\n      key: auth\n")),
			want: []ai2Want{{deployRef, "", "", vols, Suspect}}},
		{name: "vllm is not milvus", doc: deployment(vllmContainerSpec)},
	})
}

func TestAIChecks2Registered(t *testing.T) {
	want := []struct {
		id    string
		title string
		fix   Fix
	}{
		{"KS-AI-005", "Ray GCS 6379, client 10001 or dashboard 8265 exposed beyond ClusterIP", FixPatch},
		{"KS-AI-006", "Ray TLS off (RAY_USE_TLS not 1)", FixManual},
		{"KS-AI-007", "Ollama 11434 exposed without an auth proxy", FixManual},
		{"KS-AI-008", "Qdrant without API key or TLS", FixManual},
		{"KS-AI-009", "Milvus authorization disabled", FixManual},
	}
	all := All()
	const first = 18
	if len(all) < first+len(want) {
		t.Fatalf("catalog has %d checks", len(all))
	}
	for i, w := range want {
		c := all[first+i]
		if c.ID != w.id || c.Title != w.title || c.Fix != w.fix || c.Tier != Both {
			t.Errorf("catalog[%d] = %s %q fix=%s tier=%d, want %s %q fix=%s tier=%d", first+i, c.ID, c.Title, c.Fix, c.Tier, w.id, w.title, w.fix, Both)
		}
	}
}
