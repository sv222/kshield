package crdschema

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const (
	ciliumCRD   = "../../test/crds/cilium/ciliumnetworkpolicies.yaml"
	tetragonCRD = "../../test/crds/tetragon/cilium.io_tracingpoliciesnamespaced.yaml"
	kyvernoCRD  = "../../test/crds/kyverno/kyverno.io_policies.yaml"
)

const cnpSample = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sample
  namespace: ai
spec:
  endpointSelector: {}
  enableDefaultDeny:
    egress: true
    ingress: false
  egress:
  - toEndpoints:
    - {}
`

func readCRD(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func object(t *testing.T, src string) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := yaml.Unmarshal([]byte(src), &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func validate(t *testing.T, crdPath, src string) []string {
	t.Helper()
	problems, err := Validate(readCRD(t, crdPath), object(t, src))
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func wantOne(t *testing.T, problems []string, parts ...string) {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("want 1 problem, got %d: %q", len(problems), problems)
	}
	for _, p := range parts {
		if !strings.Contains(problems[0], p) {
			t.Errorf("problem %q does not contain %q", problems[0], p)
		}
	}
}

func TestValidateAcceptsUpstreamSample(t *testing.T) {
	if problems := validate(t, ciliumCRD, cnpSample); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}

func TestValidateUnknownField(t *testing.T) {
	src := strings.Replace(cnpSample, "  enableDefaultDeny:\n", "  enableDefaultDenyy: {}\n  enableDefaultDeny:\n", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec/enableDefaultDenyy", "unknown field")
}

func TestValidateEnum(t *testing.T) {
	src := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: sample
  namespace: ai
spec:
  kprobes:
  - call: security_bprm_check
    syscall: false
    selectors:
    - matchActions:
      - action: Sigkil
`
	wantOne(t, validate(t, tetragonCRD, src), "/spec/kprobes/0/selectors/0/matchActions/0/action", "enum")
}

func TestValidateType(t *testing.T) {
	src := strings.Replace(cnpSample, "    egress: true\n", "    egress: \"yes\"\n", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec/enableDefaultDeny/egress", "type")
}

func TestValidateRequired(t *testing.T) {
	src := `
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: sample
  namespace: ai
spec:
  rules:
  - match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      failureAction: Audit
      message: no latest tag
      pattern:
        spec:
          containers:
          - image: "!*:latest"
`
	wantOne(t, validate(t, kyvernoCRD, src), "/spec/rules/0", "required", "name")
}

func TestValidatePreserveUnknown(t *testing.T) {
	src := `
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: sample
  namespace: ai
spec:
  rules:
  - name: no-latest
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      failureAction: Audit
      message: no latest tag
      pattern:
        spec:
          anyUnknownKey: 1
          containers:
          - image: "!*:latest"
`
	if problems := validate(t, kyvernoCRD, src); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}

func TestValidateIntOrString(t *testing.T) {
	src := strings.Replace(cnpSample, "  - toEndpoints:\n    - {}\n", "  - icmps:\n    - fields:\n      - type: EchoRequest\n      - type: 8\n", 1)
	if problems := validate(t, ciliumCRD, src); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}

func TestValidateSorted(t *testing.T) {
	src := strings.Replace(cnpSample, "    egress: true\n    ingress: false\n", "    egress: 1\n    ingress: \"no\"\n    zzz: true\n", 1)
	problems := validate(t, ciliumCRD, src)
	if len(problems) != 3 {
		t.Fatalf("want 3 problems, got %q", problems)
	}
	for i := 1; i < len(problems); i++ {
		if problems[i-1] > problems[i] {
			t.Fatalf("problems not sorted: %q", problems)
		}
	}
}

func TestValidateKindMismatch(t *testing.T) {
	src := strings.Replace(cnpSample, "kind: CiliumNetworkPolicy", "kind: CiliumClusterwideNetworkPolicy", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/kind", "CiliumNetworkPolicy")
}

func TestValidateVersionMismatch(t *testing.T) {
	src := strings.Replace(cnpSample, "cilium.io/v2", "cilium.io/v9", 1)
	if _, err := Validate(readCRD(t, ciliumCRD), object(t, src)); err == nil {
		t.Fatal("want error for unknown version")
	}
}

func TestValidateBadCRD(t *testing.T) {
	if _, err := Validate([]byte("---\n: [\n"), object(t, cnpSample)); err == nil {
		t.Fatal("want error for unparsable CRD")
	}
}

func TestValidateMissingEndpointSelector(t *testing.T) {
	src := strings.Replace(cnpSample, "  endpointSelector: {}\n", "", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec: ", "oneOf", "none of 2")
}

func TestValidateBothSelectors(t *testing.T) {
	src := strings.Replace(cnpSample, "  endpointSelector: {}\n", "  endpointSelector: {}\n  nodeSelector: {}\n", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec: ", "oneOf", "2 of 2")
}

func TestValidateNoRules(t *testing.T) {
	src := strings.Replace(cnpSample, "  egress:\n  - toEndpoints:\n    - {}\n", "", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec: ", "anyOf", "none of 4")
}

func TestValidateFQDNOneOf(t *testing.T) {
	src := strings.Replace(cnpSample, "  - toEndpoints:\n    - {}\n", "  - toFQDNs:\n    - matchName: api.example.com\n      matchPattern: \"*.example.com\"\n", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec/egress/0/toFQDNs/0: ", "oneOf", "2 of 2")
}

func TestValidateMaxItems(t *testing.T) {
	src := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: sample
  namespace: ai
spec:
  kprobes:
  - call: security_bprm_check
    syscall: false
    selectors:
    - matchBinaries:
      - operator: In
        values: [/usr/bin/curl]
      - operator: In
        values: [/usr/bin/wget]
      matchActions:
      - action: Post
`
	wantOne(t, validate(t, tetragonCRD, src), "/spec/kprobes/0/selectors/0/matchBinaries: ", "maxItems")
}

func TestValidateNot(t *testing.T) {
	src := `
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: sample
  namespace: ai
spec:
  rules:
  - name: no-latest
    match:
      any:
      - resources:
          kinds:
          - Pod
    exclude:
      any:
      - resources:
          namespaces:
          - kube-system
      all:
      - resources:
          namespaces:
          - kube-system
    validate:
      failureAction: Audit
      message: no latest tag
      pattern:
        spec:
          containers:
          - image: "!*:latest"
`
	wantOne(t, validate(t, kyvernoCRD, src), "/spec/rules/0/exclude: ", "not")
}

func goTypedCNP(endPort int) map[string]any {
	return map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]string{"name": "sample", "namespace": "ai"},
		"spec": map[string]any{
			"endpointSelector":  map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": "vllm"}},
			"enableDefaultDeny": map[string]bool{"egress": true, "ingress": false},
			"egress": []map[string]any{
				{
					"toPorts": []map[string]any{
						{"ports": []map[string]any{{"port": "53", "endPort": endPort, "protocol": "UDP"}}},
					},
				},
				{
					"icmps": []map[string]any{{"fields": []map[string]any{{"type": 8}}}},
				},
			},
		},
	}
}

func TestValidateGoTypedMap(t *testing.T) {
	problems, err := Validate(readCRD(t, ciliumCRD), goTypedCNP(60000))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
	problems, err = Validate(readCRD(t, ciliumCRD), goTypedCNP(70000))
	if err != nil {
		t.Fatal(err)
	}
	wantOne(t, problems, "/spec/egress/0/toPorts/0/ports/0/endPort: ", "maximum")
}

func TestValidateAdditionalProperties(t *testing.T) {
	src := strings.Replace(cnpSample, "  endpointSelector: {}\n", "  endpointSelector:\n    matchLabels:\n      app.kubernetes.io/name: 5\n", 1)
	wantOne(t, validate(t, ciliumCRD, src), "/spec/endpointSelector/matchLabels/app.kubernetes.io~1name: ", "type: want string, got integer")
	src = strings.Replace(src, "app.kubernetes.io/name: 5", "app.kubernetes.io/name: vllm", 1)
	if problems := validate(t, ciliumCRD, src); len(problems) != 0 {
		t.Fatalf("want no problems, got %q", problems)
	}
}
