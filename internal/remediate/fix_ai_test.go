package remediate

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	aiKeyItem = `{"name":"VLLM_API_KEY","valueFrom":{"secretKeyRef":{"name":"app-vllm-api-key","key":"api-key"}}}`
	rayHeadC  = `"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}`
	rayWorker = "/spec/workerGroupSpecs/0/template/spec/containers/0"
)

func runMode(t *testing.T, base, mode string, ids ...string) fixRun {
	t.Helper()
	r := newRun(t, base)
	fixers := Fixers()
	for _, id := range ids {
		fx, ok := fixers[id]
		if !ok {
			t.Fatalf("no fixer for %s", id)
		}
		for _, f := range findingsOf(t, r.in, id) {
			ops, res := fx(fixTarget(t, r.in, f), f, r.in, mode)
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

func fixTarget(t *testing.T, in *check.Input, f check.Finding) model.Workload {
	t.Helper()
	for _, w := range in.Workloads {
		if w.Owner == f.Object && w.Group == f.Group && strings.HasPrefix(f.Path, w.SpecPath+"/") {
			return w
		}
	}
	for _, w := range in.Workloads {
		if w.Owner == f.Object && w.Group == f.Group {
			return w
		}
	}
	for i := range in.Objects {
		if in.Objects[i].Ref == f.Object {
			o := in.Objects[i]
			return model.Workload{Owner: o.Ref, Object: &o}
		}
	}
	t.Fatalf("no object for %s", f.Object)
	return model.Workload{}
}

func vllmDeploy(t *testing.T, fields string) string {
	t.Helper()
	return deploymentWith(t, `{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0",`+fields+`}]}`)
}

func objectOf(t *testing.T, r fixRun, kind, name string) Target {
	t.Helper()
	for _, o := range r.in.Objects {
		if o.Ref.Kind == kind && o.Ref.Name == name {
			return Target{Ref: o.Ref, Original: o.U.Object, Ops: r.ops[o.Ref]}
		}
	}
	t.Fatalf("%s/%s not in input", kind, name)
	return Target{}
}

func TestAIFixes(t *testing.T) {
	cases := []struct {
		name, check, fields, want string
	}{
		{"AI-002 args", "KS-AI-002", `"args":["--model","m","--trust-remote-code","--port","8000"]`, `[
			{"op":"remove","path":"` + wlC0 + `/args/2"}]`},
		{"AI-002 command", "KS-AI-002", `"command":["vllm","serve","m","--trust-remote-code"]`, `[
			{"op":"remove","path":"` + wlC0 + `/command/3"}]`},
		{"AI-002 command and args", "KS-AI-002", `"command":["vllm","serve"],"args":["m","--trust-remote-code"]`, `[
			{"op":"remove","path":"` + wlC0 + `/args/1"}]`},
		{"AI-002 equals form", "KS-AI-002", `"args":["--model","m","--trust-remote-code=true"]`, `[
			{"op":"remove","path":"` + wlC0 + `/args/2"}]`},
		{"AI-002 underscore flag", "KS-AI-002", `"args":["--model","m","--trust_remote_code","--load-format","safetensors"]`, `[
			{"op":"remove","path":"` + wlC0 + `/args/2"}]`},
		{"AI-002 opaque script", "KS-AI-002", `"command":["/start.sh"],"args":["--model","m","--trust-remote-code"]`, `[
			{"op":"remove","path":"` + wlC0 + `/args/2"}]`},
		{"AI-002 shell string", "KS-AI-002", `"command":["sh","-c","vllm serve m --trust-remote-code --load-format safetensors --port 8000"]`, `[
			{"op":"replace","path":"` + wlC0 + `/command/2","value":"vllm serve m --load-format safetensors --port 8000"}]`},
		{"AI-002 shell string in args", "KS-AI-002", `"command":["/bin/bash","-c"],"args":["exec vllm serve m --trust_remote_code=true --load-format=safetensors"]`, `[
			{"op":"replace","path":"` + wlC0 + `/args/0","value":"exec vllm serve m --load-format=safetensors"}]`},
		{"AI-002 shell string sets load format too", "KS-AI-002", `"command":["sh","-c","vllm serve m --trust-remote-code"]`, `[
			{"op":"replace","path":"` + wlC0 + `/command/2","value":"vllm serve m --load-format safetensors"}]`},
		{"AI-003 append args", "KS-AI-003", `"args":["--model","m"]`, `[
			{"op":"add","path":"` + wlC0 + `/args/-","value":"--load-format"},
			{"op":"add","path":"` + wlC0 + `/args/-","value":"safetensors"}]`},
		{"AI-003 append command", "KS-AI-003", `"command":["vllm","serve","m"]`, `[
			{"op":"add","path":"` + wlC0 + `/command/-","value":"--load-format"},
			{"op":"add","path":"` + wlC0 + `/command/-","value":"safetensors"}]`},
		{"AI-003 python module", "KS-AI-003", `"command":["python3","-m","vllm.entrypoints.openai.api_server"],"args":["--model","m"]`, `[
			{"op":"add","path":"` + wlC0 + `/args/-","value":"--load-format"},
			{"op":"add","path":"` + wlC0 + `/args/-","value":"safetensors"}]`},
		{"AI-003 value", "KS-AI-003", `"args":["--model","m","--load-format","pt"]`, `[
			{"op":"replace","path":"` + wlC0 + `/args/3","value":"safetensors"}]`},
		{"AI-003 equals form", "KS-AI-003", `"args":["--model","m","--load-format=pt"]`, `[
			{"op":"replace","path":"` + wlC0 + `/args/2","value":"--load-format=safetensors"}]`},
		{"AI-003 underscore flag", "KS-AI-003", `"args":["--model","m","--load_format","auto"]`, `[
			{"op":"replace","path":"` + wlC0 + `/args/3","value":"safetensors"}]`},
		{"AI-003 every occurrence", "KS-AI-003", `"args":["--load-format","pt","--model","m","--load-format=npcache"]`, `[
			{"op":"replace","path":"` + wlC0 + `/args/1","value":"safetensors"},
			{"op":"replace","path":"` + wlC0 + `/args/4","value":"--load-format=safetensors"}]`},
		{"AI-003 shell string", "KS-AI-003", `"command":["sh","-c","pip install x && exec vllm serve m --load-format=pt"]`, `[
			{"op":"replace","path":"` + wlC0 + `/command/2","value":"pip install x && exec vllm serve m --load-format=safetensors"}]`},
		{"AI-003 shell string append", "KS-AI-003", `"command":["sh","-c","vllm serve m && echo done"]`, `[
			{"op":"replace","path":"` + wlC0 + `/command/2","value":"vllm serve m --load-format safetensors && echo done"}]`},
		{"AI-001 no env", "KS-AI-001", `"args":["--model","m"]`, `[
			{"op":"add","path":"` + wlC0 + `/env","value":[` + aiKeyItem + `]}]`},
		{"AI-001 other env", "KS-AI-001", `"args":["--model","m"],"env":[{"name":"HF_HOME","value":"/c"}]`, `[
			{"op":"add","path":"` + wlC0 + `/env/-","value":` + aiKeyItem + `}]`},
		{"AI-001 empty value", "KS-AI-001", `"args":["--model","m"],"env":[{"name":"VLLM_API_KEY","value":""},{"name":"HF_HOME","value":"/c"}]`, `[
			{"op":"replace","path":"` + wlC0 + `/env/0","value":` + aiKeyItem + `}]`},
		{"AI-001 shell string", "KS-AI-001", `"command":["sh","-c","vllm serve m"]`, `[
			{"op":"add","path":"` + wlC0 + `/env","value":[` + aiKeyItem + `]}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := vllmDeploy(t, c.fields)
			if len(findingsOf(t, loadInput(t, base), c.check)) == 0 {
				t.Fatal("input has no finding")
			}
			r := runMode(t, base, "audit", c.check)
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			assertJSON(t, r.only(t), c.want)
			assertNoFindings(t, r.rescan(t), c.check)
		})
	}
}

func TestAIResiduals(t *testing.T) {
	cases := []struct {
		name, check, fields, reason string
	}{
		{"AI-003 pickle model", "KS-AI-003", `"args":["--model","/models/llama.bin"]`, reasonPickle},
		{"AI-003 pickle model with pt", "KS-AI-003", `"args":["--model","/models/llama.pth","--load-format","pt"]`, reasonPickle},
		{"AI-003 pickle model in shell", "KS-AI-003", `"command":["sh","-c","vllm serve /models/m.ckpt"]`, reasonPickle},
		{"AI-003 other format", "KS-AI-003", `"args":["--model","/models/llama.gguf","--load-format","gguf"]`,
			"--load-format gguf is not a pickle format; kshield does not change it; review how the weights are loaded"},
		{"AI-003 variable", "KS-AI-003", `"args":["--model","m","--load-format","$(FMT)"]`, reasonDynamicLoad},
		{"AI-003 opaque script", "KS-AI-003", `"command":["/start.sh"],"args":["--model","m"]`, reasonOpaqueLoad},
		{"AI-001 envFrom not in input", "KS-AI-001", `"args":["--model","m"],"envFrom":[{"secretRef":{"name":"vllm-env"}}]`,
			"VLLM_API_KEY may come from envFrom Secret vllm-env, not in the input; an added env would override it; set the key by hand"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := vllmDeploy(t, c.fields)
			r := runMode(t, base, "audit", c.check)
			assertResidual(t, r, c.check, 1, c.reason)
			if len(r.ops) > 0 {
				t.Fatalf("ops: %v", r.ops)
			}
		})
	}
}

func TestAI001EnvFromInInput(t *testing.T) {
	cm := toYAML(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"vllm-env","namespace":"ai"},"data":{"HF_HOME":"/c"}}`)
	base := joinDocs(t, vllmDeploy(t, `"args":["--model","m"],"envFrom":[{"configMapRef":{"name":"vllm-env"}}]`), cm)
	r := runMode(t, base, "audit", "KS-AI-001")
	assertJSON(t, r.only(t), `[{"op":"add","path":"`+wlC0+`/env","value":[`+aiKeyItem+`]}]`)
	assertNoFindings(t, r.rescan(t), "KS-AI-001")
}

func TestAI001WithWL008(t *testing.T) {
	r := runMode(t, vllmDeploy(t, `"args":["--model","m"]`), "audit", "KS-AI-001", "KS-WL-008")
	got := byName(t, r.build(t, r.raw), "Deployment", "app")
	env := at(t, got, wlC0+"/env").([]any)
	if len(env) != 4 {
		t.Fatalf("env: %v", env)
	}
	assertNoFindings(t, reload(t, r.build(t, r.raw)), "KS-AI-001", "KS-WL-008")
}

func TestAPIKeySecretName(t *testing.T) {
	if got := APIKeySecretName(nil, load.ObjectRef{Name: "vllm"}); got != "vllm-vllm-api-key" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("a", 245)
	got := APIKeySecretName(nil, load.ObjectRef{Name: long})
	if len(got) != 253 || !strings.HasPrefix(got, long+"-vllm") {
		t.Fatalf("got %d %q", len(got), got)
	}
	got = APIKeySecretName(nil, load.ObjectRef{Name: strings.Repeat("a", 247)})
	if len(got) != 252 || !strings.HasSuffix(got, "a-vllm") {
		t.Fatalf("got %d %q", len(got), got)
	}
}

func TestAITrustAndLoadTogether(t *testing.T) {
	cases := []struct{ name, fields, path, want string }{
		{"shell string", `"command":["sh","-c","vllm serve m --trust-remote-code"]`, wlC0 + "/command",
			`["sh","-c","vllm serve m --load-format safetensors"]`},
		{"list replace", `"args":["--model","m","--trust-remote-code","--load-format","pt"]`, wlC0 + "/args",
			`["--model","m","--load-format","safetensors"]`},
		{"list append", `"args":["--model","m","--trust-remote-code"]`, wlC0 + "/args",
			`["--model","m","--load-format","safetensors"]`},
		{"list equals forms", `"args":["--trust_remote_code=1","--model","m","--load-format=pt"]`, wlC0 + "/args",
			`["--model","m","--load-format=safetensors"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runMode(t, vllmDeploy(t, c.fields), "audit", "KS-AI-002", "KS-AI-003")
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			objs := r.build(t, r.raw)
			assertJSON(t, at(t, byName(t, objs, "Deployment", "app"), c.path), c.want)
			assertNoFindings(t, reload(t, objs), "KS-AI-002", "KS-AI-003")
		})
	}
}

func TestAITrustWithPickleModelInShell(t *testing.T) {
	r := runMode(t, vllmDeploy(t, `"command":["sh","-c","vllm serve /models/m.bin --trust-remote-code"]`), "audit", "KS-AI-002", "KS-AI-003")
	assertResidual(t, r, "KS-AI-003", 1, reasonPickle)
	assertJSON(t, r.only(t), `[{"op":"replace","path":"`+wlC0+`/command/2","value":"vllm serve /models/m.bin"}]`)
	after := r.rescan(t)
	assertNoFindings(t, after, "KS-AI-002")
	if n := len(findingsOf(t, after, "KS-AI-003")); n != 1 {
		t.Fatalf("KS-AI-003 findings after fix: %d", n)
	}
}

func TestAIRayWorkerGroup(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"ai"},
		"spec":{"headGroupSpec":{`+rayHeadC+`},"workerGroupSpecs":[{"groupName":"gpu","template":{"spec":{"containers":[
		{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","command":["sh","-c","vllm serve m --trust-remote-code"]}]}}}]}}`)
	r := runMode(t, base, "audit", "KS-AI-002", "KS-AI-003")
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	tg := objectOf(t, r, "RayCluster", "rc")
	smp, j := render(t, tg)
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/workerGroupSpecs/0/groupName","value":"gpu"},
		{"op":"test","path":"`+rayWorker+`/name","value":"vllm"},
		{"op":"test","path":"`+rayWorker+`/command/2","value":"vllm serve m --trust-remote-code"},
		{"op":"replace","path":"`+rayWorker+`/command/2","value":"vllm serve m --load-format safetensors"}]`)
	assertNoFindings(t, r.rescan(t), "KS-AI-002", "KS-AI-003")
}

func TestAIServingRuntime(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"serving.kserve.io/v1alpha1","kind":"ServingRuntime","metadata":{"name":"rt","namespace":"ai"},
		"spec":{"supportedModelFormats":[{"name":"vllm"}],"containers":[{"name":"kserve-container","image":"vllm/vllm-openai:v0.31.0",
		"args":["--model","m","--trust-remote-code"]}]}}`)
	r := runMode(t, base, "audit", "KS-AI-002", "KS-AI-003")
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	smp, j := render(t, objectOf(t, r, "ServingRuntime", "rt"))
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/containers/0/name","value":"kserve-container"},
		{"op":"test","path":"/spec/containers/0/args/2","value":"--trust-remote-code"},
		{"op":"add","path":"/spec/containers/0/args/-","value":"--load-format"},
		{"op":"add","path":"/spec/containers/0/args/-","value":"safetensors"},
		{"op":"remove","path":"/spec/containers/0/args/2"}]`)
	objs := r.patched(t)
	assertJSON(t, at(t, byName(t, objs, "ServingRuntime", "rt"), "/spec/containers/0/args"), `["--model","m","--load-format","safetensors"]`)
	assertNoFindings(t, reload(t, objs), "KS-AI-002", "KS-AI-003")
}

func rayClusterJSON(t *testing.T, kind, clusterField, head string) string {
	t.Helper()
	spec := `{"headGroupSpec":{` + head + rayHeadC + `}}`
	if clusterField != "" {
		spec = `{"` + clusterField + `":` + spec + `}`
	}
	return toYAML(t, `{"apiVersion":"ray.io/v1","kind":"`+kind+`","metadata":{"name":"rc","namespace":"ai"},"spec":`+spec+`}`)
}

func rayService(t *testing.T, spec string) string {
	t.Helper()
	return toYAML(t, `{"apiVersion":"v1","kind":"Service","metadata":{"name":"dash","namespace":"ai"},"spec":`+spec+`}`)
}

func TestAI005Fixes(t *testing.T) {
	cluster := rayClusterJSON(t, "RayCluster", "", "")
	cases := []struct{ name, base, want string }{
		{"head service and ingress", rayClusterJSON(t, "RayCluster", "", `"serviceType":"NodePort","enableIngress":true,`), `[
			{"op":"replace","path":"/spec/headGroupSpec/enableIngress","value":false},
			{"op":"replace","path":"/spec/headGroupSpec/serviceType","value":"ClusterIP"}]`},
		{"RayService head", rayClusterJSON(t, "RayService", "rayClusterConfig", `"serviceType":"LoadBalancer",`), `[
			{"op":"replace","path":"/spec/rayClusterConfig/headGroupSpec/serviceType","value":"ClusterIP"}]`},
		{"NodePort Service", joinDocs(t, cluster, rayService(t, `{"type":"NodePort","externalTrafficPolicy":"Local",
			"selector":{"ray.io/node-type":"head"},"ports":[{"name":"dash","port":8265,"nodePort":30265},{"name":"gcs","port":6379,"protocol":"TCP"}]}`)), `[
			{"op":"replace","path":"/spec/type","value":"ClusterIP"},
			{"op":"remove","path":"/spec/ports/0/nodePort"},
			{"op":"remove","path":"/spec/externalTrafficPolicy"}]`},
		{"LoadBalancer Service", joinDocs(t, cluster, rayService(t, `{"type":"LoadBalancer","externalTrafficPolicy":"Local","healthCheckNodePort":31000,
			"loadBalancerIP":"10.0.0.9","loadBalancerSourceRanges":["10.0.0.0/8"],"loadBalancerClass":"x/lb","allocateLoadBalancerNodePorts":true,
			"selector":{"ray.io/node-type":"head"},"ports":[{"name":"gcs","port":6379,"protocol":"TCP","nodePort":30379},{"name":"dash","port":8265,"nodePort":30265}]}`)), `[
			{"op":"replace","path":"/spec/type","value":"ClusterIP"},
			{"op":"remove","path":"/spec/ports/0/nodePort"},
			{"op":"remove","path":"/spec/ports/1/nodePort"},
			{"op":"remove","path":"/spec/externalTrafficPolicy"},
			{"op":"remove","path":"/spec/healthCheckNodePort"},
			{"op":"remove","path":"/spec/loadBalancerIP"},
			{"op":"remove","path":"/spec/loadBalancerSourceRanges"},
			{"op":"remove","path":"/spec/loadBalancerClass"},
			{"op":"remove","path":"/spec/allocateLoadBalancerNodePorts"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(findingsOf(t, loadInput(t, c.base), "KS-AI-005")) == 0 {
				t.Fatal("input has no finding")
			}
			r := runMode(t, c.base, "audit", "KS-AI-005")
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			assertJSON(t, r.only(t), c.want)
			assertNoFindings(t, r.rescan(t), "KS-AI-005")
		})
	}
}

func TestAI005ServicePortTests(t *testing.T) {
	base := joinDocs(t, rayClusterJSON(t, "RayCluster", "", ""), rayService(t, `{"type":"NodePort",
		"selector":{"ray.io/node-type":"head"},"ports":[{"name":"dash","port":8265,"nodePort":30265}]}`))
	r := runMode(t, base, "audit", "KS-AI-005")
	_, j := render(t, objectOf(t, r, "Service", "dash"))
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/ports/0/port","value":8265},
		{"op":"replace","path":"/spec/type","value":"ClusterIP"},
		{"op":"remove","path":"/spec/ports/0/nodePort"}]`)
}

func TestAI005IngressResidual(t *testing.T) {
	ing := toYAML(t, `{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"dash","namespace":"ai"},
		"spec":{"rules":[{"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"dash","port":{"number":8265}}}}]}}]}}`)
	base := joinDocs(t, rayClusterJSON(t, "RayCluster", "", ""),
		rayService(t, `{"selector":{"ray.io/node-type":"head"},"ports":[{"name":"dash","port":8265}]}`), ing)
	r := runMode(t, base, "audit", "KS-AI-005")
	assertResidual(t, r, "KS-AI-005", 1, reasonRayIngress)
	if len(r.ops) > 0 {
		t.Fatalf("ops: %v", r.ops)
	}
}

func egressBase(t *testing.T, policies ...string) string {
	t.Helper()
	docs := []string{vllmDeploy(t, `"args":["--model","m"]`)}
	for _, p := range policies {
		docs = append(docs, toYAML(t, p))
	}
	return joinDocs(t, docs...)
}

const (
	broadNetpol = `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"np","namespace":"ai"},
		"spec":{"podSelector":{},"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]},
		{"to":[{"namespaceSelector":{}}],"ports":[{"port":53,"protocol":"UDP"}]},{}]}}`
	broadCilium = `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"cnp","namespace":"ai"},
		"spec":{"endpointSelector":{},"egress":[{"toEntities":["world"]}]}}`
	mixedCilium = `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"cnp","namespace":"ai"},
		"spec":{"endpointSelector":{},"egress":[{"toCIDR":["0.0.0.0/0"]},{"toFQDNs":[{"matchName":"huggingface.co"}]}]}}`
	broadClusterwide = `{"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"ccnp"},
		"specs":[{"endpointSelector":{},"egress":[{"toEntities":["all"]},{"toCIDRSet":[{"cidr":"::/0"}]}]}]}`
)

func TestNET002Enforce(t *testing.T) {
	cases := []struct{ name, policy, kind, objName, want, after, afterPath string }{
		{"NetworkPolicy", broadNetpol, "NetworkPolicy", "np", `[
			{"op":"test","path":"/spec/egress/0","value":{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}},
			{"op":"test","path":"/spec/egress/2","value":{}},
			{"op":"add","path":"/spec/policyTypes","value":["Ingress","Egress"]},
			{"op":"remove","path":"/spec/egress/2"},
			{"op":"remove","path":"/spec/egress/0"}]`,
			`[{"to":[{"namespaceSelector":{}}],"ports":[{"port":53,"protocol":"UDP"}]}]`, "/spec/egress"},
		{"Cilium only rule", broadCilium, "CiliumNetworkPolicy", "cnp", `[
			{"op":"test","path":"/spec/egress/0","value":{"toEntities":["world"]}},
			{"op":"add","path":"/spec/egress/-","value":{}},
			{"op":"remove","path":"/spec/egress/0"}]`,
			`[{}]`, "/spec/egress"},
		{"Cilium mixed rules", mixedCilium, "CiliumNetworkPolicy", "cnp", `[
			{"op":"test","path":"/spec/egress/0","value":{"toCIDR":["0.0.0.0/0"]}},
			{"op":"remove","path":"/spec/egress/0"}]`,
			`[{"toFQDNs":[{"matchName":"huggingface.co"}]}]`, "/spec/egress"},
		{"Cilium clusterwide specs", broadClusterwide, "CiliumClusterwideNetworkPolicy", "ccnp", `[
			{"op":"test","path":"/specs/0","value":{"endpointSelector":{},"egress":[{"toEntities":["all"]},{"toCIDRSet":[{"cidr":"::/0"}]}]}},
			{"op":"test","path":"/specs/0/egress/0","value":{"toEntities":["all"]}},
			{"op":"test","path":"/specs/0/egress/1","value":{"toCIDRSet":[{"cidr":"::/0"}]}},
			{"op":"add","path":"/specs/0/egress/-","value":{}},
			{"op":"remove","path":"/specs/0/egress/1"},
			{"op":"remove","path":"/specs/0/egress/0"}]`,
			`[{}]`, "/specs/0/egress"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := egressBase(t, c.policy)
			if len(findingsOf(t, loadInput(t, base), "KS-NET-002")) == 0 {
				t.Fatal("input has no finding")
			}
			r := runMode(t, base, "enforce", "KS-NET-002")
			if len(r.residuals) > 0 {
				t.Fatalf("residuals: %+v", r.residuals)
			}
			smp, j := render(t, objectOf(t, r, c.kind, c.objName))
			if smp != nil {
				t.Fatalf("smp: %v", smp)
			}
			assertJSON(t, j, c.want)
			objs := r.patched(t)
			assertJSON(t, at(t, byName(t, objs, c.kind, c.objName), c.afterPath), c.after)
			after := reload(t, objs)
			assertNoFindings(t, after, "KS-NET-002", "KS-NET-001")
		})
	}
}

func TestNET002NetworkPolicyKeepsEgressType(t *testing.T) {
	policy := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"np","namespace":"ai"},
		"spec":{"podSelector":{},"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}]}}`
	r := runMode(t, egressBase(t, policy), "enforce", "KS-NET-002")
	objs := r.patched(t)
	np := byName(t, objs, "NetworkPolicy", "np")
	assertJSON(t, at(t, np, "/spec/policyTypes"), `["Ingress","Egress"]`)
	assertNoFindings(t, reload(t, objs), "KS-NET-002", "KS-NET-001")
}

func TestNET002Audit(t *testing.T) {
	r := runMode(t, egressBase(t, broadNetpol), "audit", "KS-NET-002")
	assertResidual(t, r, "KS-NET-002", 2, reasonAuditEgress)
	if len(r.ops) > 0 {
		t.Fatalf("ops: %v", r.ops)
	}
}

func assertNoSecret(t *testing.T, r fixRun, secret string) {
	t.Helper()
	for _, o := range r.in.Objects {
		ops := r.raw[o.Ref]
		if len(ops) == 0 {
			continue
		}
		smp, j := render(t, Target{Ref: o.Ref, Original: o.U.Object, Ops: ops})
		if out := marshal(t, smp) + marshal(t, j); strings.Contains(out, secret) {
			t.Fatalf("patch of %s holds %q:\n%s", o.Ref, secret, out)
		}
	}
}

func TestAIShellLiteralAPIKey(t *testing.T) {
	cases := map[string]string{
		"value word":   `"command":["sh","-c","vllm serve m --api-key sk-123"]`,
		"equals form":  `"command":["sh","-c","vllm serve m --trust-remote-code --api_key=sk-123"]`,
		"second call":  `"command":["sh","-c","vllm serve m --trust-remote-code; vllm serve n --api-key 'sk-123'"]`,
		"in args item": `"command":["bash","-c"],"args":["exec vllm serve m --api-key \"sk-123\" --load-format pt"]`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			r := runMode(t, vllmDeploy(t, fields), "audit", "KS-AI-002", "KS-AI-003")
			if len(r.ops) > 0 {
				t.Fatalf("ops: %v", r.ops)
			}
			for _, res := range r.residuals {
				if res.Reason != reasonShellKey {
					t.Fatalf("residual %s: %q", res.Check, res.Reason)
				}
			}
			if len(r.residuals) == 0 {
				t.Fatal("no residual")
			}
		})
	}
}

func TestAIListLiteralAPIKeyNotInPatch(t *testing.T) {
	fields := `"args":["--model","m","--api-key=sk-123","--trust-remote-code","--api-key","sk-123","--load-format","pt"]`
	r := runMode(t, vllmDeploy(t, fields), "audit", "KS-AI-002", "KS-AI-003")
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	assertNoSecret(t, r, "sk-123")
	assertNoFindings(t, reload(t, r.build(t, r.raw)), "KS-AI-002", "KS-AI-003")
}

func TestAIShellFlagFromVariable(t *testing.T) {
	fields := `"env":[{"name":"EXTRA","value":"--trust-remote-code"}],"command":["sh","-c","vllm serve m $(EXTRA)"]`
	r := runMode(t, vllmDeploy(t, fields), "audit", "KS-AI-002", "KS-AI-003")
	assertResidual(t, r, "KS-AI-002", 1, reasonShellEdit)
	assertJSON(t, r.only(t), `[{"op":"replace","path":"`+wlC0+`/command/2","value":"vllm serve m $(EXTRA) --load-format safetensors"}]`)
	after := r.rescan(t)
	assertNoFindings(t, after, "KS-AI-003")
	if n := len(findingsOf(t, after, "KS-AI-002")); n != 1 {
		t.Fatalf("KS-AI-002 findings after fix: %d", n)
	}
}

func TestAI003ConfigFileResidual(t *testing.T) {
	for name, fields := range map[string]string{
		"list":  `"args":["--model","m","--config","/cfg/vllm.yaml"]`,
		"shell": `"command":["sh","-c","vllm serve m --config=/cfg/vllm.yaml"]`,
	} {
		t.Run(name, func(t *testing.T) {
			r := runMode(t, vllmDeploy(t, fields), "audit", "KS-AI-003")
			assertResidual(t, r, "KS-AI-003", 1, reasonConfigLoad)
		})
	}
	r := runMode(t, vllmDeploy(t, `"args":["--model","m","--config","/cfg/vllm.yaml","--load-format","pt"]`), "audit", "KS-AI-003")
	assertJSON(t, r.only(t), `[{"op":"replace","path":"`+wlC0+`/args/5","value":"safetensors"}]`)
}

func TestNET002EmptyPolicyTypes(t *testing.T) {
	policy := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"np","namespace":"ai"},
		"spec":{"podSelector":{},"policyTypes":[],"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}]}}`
	base := egressBase(t, policy)
	if len(findingsOf(t, loadInput(t, base), "KS-NET-002")) == 0 {
		t.Fatal("input has no finding")
	}
	r := runMode(t, base, "enforce", "KS-NET-002")
	assertJSON(t, r.only(t), `[
		{"op":"remove","path":"/spec/egress/0"},
		{"op":"replace","path":"/spec/policyTypes","value":["Ingress","Egress"]}]`)
	objs := r.patched(t)
	assertJSON(t, at(t, byName(t, objs, "NetworkPolicy", "np"), "/spec/policyTypes"), `["Ingress","Egress"]`)
	assertNoFindings(t, reload(t, objs), "KS-NET-002", "KS-NET-001")
}

func TestAIWithWorkloadFixers(t *testing.T) {
	ids := []string{"KS-AI-001", "KS-AI-002", "KS-AI-003", "KS-WL-001", "KS-WL-002", "KS-WL-003", "KS-WL-008", "KS-WL-009"}
	base := vllmDeploy(t, `"args":["--model","m","--trust-remote-code","--port","8000"],"env":[{"name":"HF_HOME","value":"/tmp/hf"}]`)
	r := runMode(t, base, "audit", ids...)
	if len(r.residuals) > 0 {
		t.Fatalf("residuals: %+v", r.residuals)
	}
	tg := objectOf(t, r, "Deployment", "app")
	tg.Ops = r.raw[tg.Ref]
	smp, j := render(t, tg)
	if smp == nil || len(j) == 0 {
		t.Fatalf("want SMP and JSON 6902 parts, got smp %v, 6902 %v", smp, j)
	}
	objs := r.build(t, r.raw)
	got := byName(t, objs, "Deployment", "app")
	assertJSON(t, at(t, got, wlC0+"/args"), `["--model","m","--port","8000","--load-format","safetensors"]`)
	assertNoFindings(t, reload(t, objs), ids...)
}

func TestAI001CustomResource(t *testing.T) {
	base := toYAML(t, `{"apiVersion":"serving.kserve.io/v1alpha1","kind":"ServingRuntime","metadata":{"name":"rt","namespace":"ai"},
		"spec":{"supportedModelFormats":[{"name":"vllm"}],"containers":[{"name":"kserve-container","image":"vllm/vllm-openai:v0.31.0",
		"args":["--model","m"]}]}}`)
	r := runMode(t, base, "audit", "KS-AI-001")
	smp, j := render(t, objectOf(t, r, "ServingRuntime", "rt"))
	if smp != nil {
		t.Fatalf("smp: %v", smp)
	}
	key := strings.Replace(aiKeyItem, "app-vllm-api-key", "rt-vllm-api-key", 1)
	assertJSON(t, j, `[
		{"op":"test","path":"/spec/containers/0/name","value":"kserve-container"},
		{"op":"add","path":"/spec/containers/0/env","value":[`+key+`]}]`)
	assertNoFindings(t, r.rescan(t), "KS-AI-001")
}
