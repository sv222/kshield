package check

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const vllmContainerSpec = `
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.0
    ports:
      - name: http
        containerPort: 8000
`

func svcDoc(namespace, name, typ, selector string, ports ...string) string {
	doc := "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\nspec:\n"
	if typ != "" {
		doc += "  type: " + typ + "\n"
	}
	if selector != "" {
		doc += "  selector:\n    " + selector + "\n"
	}
	if len(ports) > 0 {
		doc += "  ports:\n"
	}
	for _, p := range ports {
		doc += "    - " + strings.ReplaceAll(p, "\n", "\n      ") + "\n"
	}
	return doc
}

func ingressDoc(apiVersion, namespace, name, annotations, spec string) string {
	doc := "---\napiVersion: " + apiVersion + "\nkind: Ingress\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\n"
	if annotations != "" {
		doc += "  annotations:\n" + annotations
	}
	return doc + spec
}

func ruleSpec(services ...string) string {
	spec := "spec:\n  rules:\n    - http:\n        paths:\n"
	for _, s := range services {
		spec += fmt.Sprintf("          - path: /%[1]s\n            pathType: Prefix\n            backend:\n              service:\n                name: %[1]s\n                port:\n                  number: 80\n", s)
	}
	return spec
}

func portRuleSpec(service, port string) string {
	return portRulesSpec([2]string{service, port})
}

func portRulesSpec(backends ...[2]string) string {
	spec := "spec:\n  rules:\n    - http:\n        paths:\n"
	for _, b := range backends {
		spec += "          - path: /" + b[0] + "\n            pathType: Prefix\n            backend:\n              service:\n                name: " + b[0] + "\n"
		if b[1] != "" {
			spec += "                port:\n                  " + b[1] + "\n"
		}
	}
	return spec
}

func defaultBackendSpec(service string) string {
	return fmt.Sprintf("spec:\n  defaultBackend:\n    service:\n      name: %s\n      port:\n        number: 80\n", service)
}

func exposureInput(t *testing.T, podSpec, extra string) (*Input, model.Workload) {
	t.Helper()
	doc := deployment(podSpec) + extra
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range ws {
		if w.Owner.String() == deployRef {
			return &Input{Objects: objs, Workloads: ws}, w
		}
	}
	t.Fatal("no workload")
	return nil, model.Workload{}
}

type wantExposure struct {
	ref           string
	kind          string
	authenticated bool
	path          string
}

func gotExposures(es []Exposure) []wantExposure {
	out := make([]wantExposure, len(es))
	for i, e := range es {
		out[i] = wantExposure{e.Object.Ref.String(), e.Kind, e.Authenticated, e.Path}
	}
	return out
}

func equalExposures(a, b []wantExposure) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExposuresServices(t *testing.T) {
	const sel = "app: vllm"
	nodePort := wantExposure{"Service/ai/svc", "service-nodeport", false, "/spec/type"}
	loadBalancer := wantExposure{"Service/ai/svc", "service-loadbalancer", false, "/spec/type"}
	cases := []struct {
		name  string
		extra string
		ports []int32
		want  []wantExposure
	}{
		{"nodeport", svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), nil, []wantExposure{nodePort}},
		{"loadbalancer", svcDoc("ai", "svc", "LoadBalancer", sel, "port: 8000"), nil, []wantExposure{loadBalancer}},
		{"clusterip", svcDoc("ai", "svc", "ClusterIP", sel, "port: 8000"), nil, nil},
		{"default type is clusterip", svcDoc("ai", "svc", "", sel, "port: 8000"), nil, nil},
		{"externalname", svcDoc("ai", "svc", "ExternalName", sel, "port: 8000"), nil, nil},
		{"selector does not match", svcDoc("ai", "svc", "NodePort", "app: other", "port: 8000"), nil, nil},
		{"selector with an extra key", svcDoc("ai", "svc", "NodePort", "app: vllm\n    tier: gpu", "port: 8000"), nil, nil},
		{"no selector", svcDoc("ai", "svc", "NodePort", "", "port: 8000"), nil, nil},
		{"other namespace", svcDoc("other", "svc", "NodePort", sel, "port: 8000"), nil, nil},
		{"two services", svcDoc("ai", "svc", "NodePort", sel, "port: 8000") + svcDoc("ai", "lb", "LoadBalancer", sel, "port: 80"), nil, []wantExposure{
			nodePort,
			{"Service/ai/lb", "service-loadbalancer", false, "/spec/type"},
		}},
		{"port filter by port", svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), []int32{8000}, []wantExposure{nodePort}},
		{"port filter by other port", svcDoc("ai", "svc", "NodePort", sel, "port: 8001"), []int32{8000}, nil},
		{"port filter by target port number", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: 8000"), []int32{8000}, []wantExposure{nodePort}},
		{"port filter by named target port", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: http"), []int32{8000}, []wantExposure{nodePort}},
		{"port filter by unknown named target port", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: metrics"), []int32{8000}, nil},
		{"port filter by other target port", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: 9000"), []int32{8000}, nil},
		{"port filter second port", svcDoc("ai", "svc", "NodePort", sel, "port: 80", "port: 8000"), []int32{8000}, []wantExposure{nodePort}},
		{"port filter several wanted ports", svcDoc("ai", "svc", "NodePort", sel, "port: 6379"), []int32{8265, 6379}, []wantExposure{nodePort}},
		{"quoted port without a filter", svcDoc("ai", "svc", "NodePort", sel, `port: "8000"`), nil, []wantExposure{nodePort}},
		{"quoted port in the filter", svcDoc("ai", "svc", "NodePort", sel, `port: "8000"`), []int32{8000}, []wantExposure{nodePort}},
		{"quoted port outside the filter", svcDoc("ai", "svc", "NodePort", sel, `port: "8001"`), []int32{8000}, nil},
		{"quoted target port in the filter", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: \"8000\""), []int32{8000}, []wantExposure{nodePort}},
		{"quoted target port outside the filter", svcDoc("ai", "svc", "NodePort", sel, "port: 80\ntargetPort: \"9000\""), []int32{8000}, nil},
		{"unreadable port counts as a match", svcDoc("ai", "svc", "NodePort", sel, "port: eighty"), []int32{8000}, []wantExposure{nodePort}},
		{"object port counts as a match", svcDoc("ai", "svc", "NodePort", sel, "port: {a: b}"), []int32{8000}, []wantExposure{nodePort}},
		{"unreadable port next to a readable one", svcDoc("ai", "svc", "NodePort", sel, "port: 80", "port: eighty"), []int32{8000}, []wantExposure{nodePort}},
		{"empty port filter matches nothing", svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), []int32{}, nil},
		{"nil ports and no service ports", svcDoc("ai", "svc", "NodePort", sel), nil, []wantExposure{nodePort}},
		{"port filter without service ports", svcDoc("ai", "svc", "NodePort", sel), []int32{8000}, nil},
		{"other api version", strings.Replace(svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), "apiVersion: v1", "apiVersion: example.io/v1", 1), nil, nil},
		{"other kind", strings.Replace(svcDoc("ai", "svc", "NodePort", sel, "port: 8000"), "kind: Service", "kind: ConfigMap", 1), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, w := exposureInput(t, vllmContainerSpec, tc.extra)
			got := gotExposures(Exposures(in, w, tc.ports))
			if !equalExposures(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestExposuresIngress(t *testing.T) {
	const (
		sel     = "app: vllm"
		authURL = "    nginx.ingress.kubernetes.io/auth-url: https://auth.example.com/check\n"
	)
	cluster := svcDoc("ai", "svc", "ClusterIP", sel, "port: 80")
	rules := wantExposure{"Ingress/ai/web", "ingress", false, "/spec/rules"}
	cases := []struct {
		name  string
		extra string
		ports []int32
		want  []wantExposure
	}{
		{"rule to a clusterip service", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), nil, []wantExposure{rules}},
		{"default backend only", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", defaultBackendSpec("svc")), nil,
			[]wantExposure{{"Ingress/ai/web", "ingress", false, "/spec/defaultBackend"}}},
		{"rule and default backend", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")+strings.TrimPrefix(defaultBackendSpec("svc"), "spec:\n")), nil, []wantExposure{rules}},
		{"default backend names the service and a rule names another", cluster + svcDoc("ai", "other", "ClusterIP", "app: other", "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("other")+strings.TrimPrefix(defaultBackendSpec("svc"), "spec:\n")), nil,
			[]wantExposure{{"Ingress/ai/web", "ingress", false, "/spec/defaultBackend"}}},
		{"two rules naming the same service give one exposure", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc", "svc")), nil, []wantExposure{rules}},
		{"auth-url", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", authURL, ruleSpec("svc")), nil,
			[]wantExposure{{"Ingress/ai/web", "ingress", true, "/spec/rules"}}},
		{"auth-type", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "    nginx.ingress.kubernetes.io/auth-type: basic\n", ruleSpec("svc")), nil,
			[]wantExposure{{"Ingress/ai/web", "ingress", true, "/spec/rules"}}},
		{"empty auth-url", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "    nginx.ingress.kubernetes.io/auth-url: \"\"\n", ruleSpec("svc")), nil, []wantExposure{rules}},
		{"other annotation", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "    nginx.ingress.kubernetes.io/rewrite-target: /\n", ruleSpec("svc")), nil, []wantExposure{rules}},
		{"service that does not select the workload", svcDoc("ai", "svc", "ClusterIP", "app: other", "port: 80") +
			ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), nil, nil},
		{"service that does not exist", ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("missing")), nil, nil},
		{"ingress in another namespace", cluster + ingressDoc("networking.k8s.io/v1", "other", "web", "", ruleSpec("svc")), nil, nil},
		{"service in another namespace", svcDoc("other", "svc", "ClusterIP", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "other", "web", "", ruleSpec("svc")), nil, nil},
		{"old api version", cluster + ingressDoc("extensions/v1beta1", "ai", "web", "", ruleSpec("svc")), nil, nil},
		{"resource backend", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "",
			"spec:\n  defaultBackend:\n    resource:\n      apiGroup: example.io\n      kind: Bucket\n      name: svc\n"), nil, nil},
		{"no rules", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", "spec: {}\n"), nil, nil},
		{"rule without http", cluster + ingressDoc("networking.k8s.io/v1", "ai", "web", "", "spec:\n  rules:\n    - host: example.com\n"), nil, nil},
		{"ports filter ingresses through the service", svcDoc("ai", "svc", "ClusterIP", sel, "port: 9999") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), []int32{8000}, nil},
		{"ingress through a service on a matching port", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80\ntargetPort: 8000") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), []int32{8000}, []wantExposure{rules}},
		{"nodeport service and ingress", svcDoc("ai", "svc", "NodePort", sel, "port: 80") + ingressDoc("networking.k8s.io/v1", "ai", "web", "", ruleSpec("svc")), nil, []wantExposure{
			{"Service/ai/svc", "service-nodeport", false, "/spec/type"},
			rules,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, w := exposureInput(t, vllmContainerSpec, tc.extra)
			got := gotExposures(Exposures(in, w, tc.ports))
			if !equalExposures(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestExposuresIngressBackendPort(t *testing.T) {
	const sel = "app: vllm"
	ray := []int32{8265}
	twoPorts := svcDoc("ai", "svc", "ClusterIP", sel, "name: web\nport: 80\ntargetPort: 8000", "name: dashboard\nport: 8265")
	ing := func(port string) string {
		return ingressDoc("networking.k8s.io/v1", "ai", "web", "", portRuleSpec("svc", port))
	}
	rules := []wantExposure{{"Ingress/ai/web", "ingress", false, "/spec/rules"}}
	cases := []struct {
		name  string
		extra string
		ports []int32
		want  []wantExposure
	}{
		{"backend on a non-ray port", twoPorts + ing("number: 80"), ray, nil},
		{"backend on the ray port", twoPorts + ing("number: 8265"), ray, rules},
		{"backend names the ray port", twoPorts + ing("name: dashboard"), ray, rules},
		{"backend names a non-ray port", twoPorts + ing("name: web"), ray, nil},
		{"backend names a port the service lacks", twoPorts + ing("name: grpc"), ray, nil},
		{"backend on a port the service lacks", twoPorts + ing("number: 9999"), ray, nil},
		{"backend port resolves to a ray target port", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80\ntargetPort: 8265") + ing("number: 80"), ray, rules},
		{"backend without a port falls back to any service port", twoPorts + ing(""), ray, rules},
		{"unreadable service port counts as a match", svcDoc("ai", "svc", "ClusterIP", sel, "port: eighty") + ing("number: 80"), ray, rules},
		{"unreadable target port of the backend port counts", svcDoc("ai", "svc", "ClusterIP", sel, "port: 80\ntargetPort: {a: b}") + ing("number: 80"), ray, rules},
		{"no port filter ignores the backend port", twoPorts + ing("number: 80"), nil, rules},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, w := exposureInput(t, vllmContainerSpec, tc.extra)
			got := gotExposures(Exposures(in, w, tc.ports))
			if !equalExposures(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestExposuresObjectIsTheSourceObject(t *testing.T) {
	in, w := exposureInput(t, vllmContainerSpec, svcDoc("ai", "svc", "LoadBalancer", "app: vllm", "port: 8000"))
	es := Exposures(in, w, nil)
	if len(es) != 1 || es[0].Object.U == nil || es[0].Object.U.GetName() != "svc" {
		t.Fatalf("got %+v", es)
	}
}

func TestInputIndexIsBuiltOncePerInput(t *testing.T) {
	in, w := exposureInput(t, vllmContainerSpec, svcDoc("ai", "svc", "NodePort", "app: vllm", "port: 8000"))
	first := in.idx()
	if es := Exposures(in, w, nil); len(es) != 1 {
		t.Fatalf("got %+v", es)
	}
	if in.idx() != first {
		t.Fatal("the index must be built once per Input")
	}
	extra, w2 := exposureInput(t, vllmContainerSpec, svcDoc("ai", "svc", "NodePort", "app: vllm", "port: 8000")+svcDoc("ai", "lb", "LoadBalancer", "app: vllm", "port: 80"))
	if es := Exposures(extra, w2, nil); len(es) != 2 {
		t.Fatalf("a new Input must get its own index: %+v", es)
	}
	if extra.idx() == first {
		t.Fatal("two Inputs share one index")
	}
}

func TestExposuresNothingToScan(t *testing.T) {
	in, w := exposureInput(t, vllmContainerSpec, "")
	if es := Exposures(in, w, nil); len(es) != 0 {
		t.Fatalf("got %+v", es)
	}
	if es := Exposures(&Input{}, w, nil); len(es) != 0 {
		t.Fatalf("got %+v", es)
	}
}

func TestExposuresKServeLabels(t *testing.T) {
	doc := `apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: sklearn
  namespace: ai
spec:
  predictor:
    containers:
      - name: kserve-container
        image: kserve/sklearnserver:v0.15.0
---
apiVersion: v1
kind: Service
metadata:
  name: sklearn-lb
  namespace: ai
spec:
  type: LoadBalancer
  selector:
    serving.kserve.io/inferenceservice: sklearn
    component: predictor
  ports:
    - port: 80
`
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("got %d workloads", len(ws))
	}
	got := gotExposures(Exposures(&Input{Objects: objs, Workloads: ws}, ws[0], nil))
	want := []wantExposure{{"Service/ai/sklearn-lb", "service-loadbalancer", false, "/spec/type"}}
	if !equalExposures(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
