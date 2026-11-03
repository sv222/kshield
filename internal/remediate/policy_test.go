package remediate

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/crdschema"
)

const (
	ciliumCRDPath   = "../../test/crds/cilium/ciliumnetworkpolicies.yaml"
	tetragonCRDPath = "../../test/crds/tetragon/cilium.io_tracingpoliciesnamespaced.yaml"
	kyvernoCRDPath  = "../../test/crds/kyverno/kyverno.io_policies.yaml"
	policyNS        = "ai-inference"
)

var (
	guardChecks = []string{"KS-NET-001", "KS-RT-001", "KS-RT-002", "KS-RT-003"}
	testPeers   = map[string][]string{policyNS: {"vector-db", "ai-train"}, "ai-train": {policyNS}}
	policyOpts  = []PolicyOptions{
		{Mode: "audit", AllowFQDN: []string{"huggingface.co"}, AllowCIDR: []string{"203.0.113.0/24", "2001:db8::/32"},
			PeerNamespaces: testPeers, APIServerNamespaces: []string{"ai-train"}},
		{Mode: "enforce", AllowFQDN: []string{"huggingface.co"}, AllowCIDR: []string{"203.0.113.0/24", "2001:db8::/32"},
			PeerNamespaces: testPeers, APIServerNamespaces: []string{"ai-train"}},
	}
)

func vllmIn(t *testing.T, ns string) string {
	t.Helper()
	return toYAML(t, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"vllm","namespace":"`+ns+`"},
		"spec":{"selector":{"matchLabels":{"app":"vllm"}},"template":{"metadata":{"labels":{"app":"vllm"}},
		"spec":{"containers":[{"name":"vllm","image":"vllm/vllm-openai:v0.31.0","args":["--model","m"]}]}}}}`)
}

func webIn(t *testing.T, ns string) string {
	t.Helper()
	return toYAML(t, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web","namespace":"`+ns+`"},
		"spec":{"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":{"app":"web"}},
		"spec":{"containers":[{"name":"web","image":"nginx:1.29.1"}]}}}}`)
}

func mustPolicies(t *testing.T, namespaces []string, opt PolicyOptions) []map[string]any {
	t.Helper()
	objs, err := Policies(namespaces, opt)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func policyDocs(t *testing.T, objs []map[string]any) []string {
	t.Helper()
	var docs []string
	for _, o := range objs {
		docs = append(docs, marshal(t, o))
	}
	return docs
}

func crdFor(t *testing.T, obj map[string]any) []byte {
	t.Helper()
	paths := map[string]string{
		"CiliumNetworkPolicy":     ciliumCRDPath,
		"TracingPolicyNamespaced": tetragonCRDPath,
		"Policy":                  kyvernoCRDPath,
	}
	kind, _ := obj["kind"].(string)
	p, ok := paths[kind]
	if !ok {
		t.Fatalf("unexpected kind %q", kind)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPoliciesValidAgainstCRDs(t *testing.T) {
	for _, opt := range policyOpts {
		objs := mustPolicies(t, []string{policyNS, "ai-train"}, opt)
		if len(objs) != 9 {
			t.Fatalf("%s: %d objects, want 9", opt.Mode, len(objs))
		}
		for _, o := range objs {
			problems, err := crdschema.Validate(crdFor(t, o), o)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				t.Errorf("%s %s %s: %s", opt.Mode, o["kind"], lookupPath(o, "/metadata/name"), p)
			}
		}
	}
}

func TestPoliciesOrder(t *testing.T) {
	objs := mustPolicies(t, []string{"b", "a", "b"}, PolicyOptions{Mode: "audit"})
	var got []string
	for _, o := range objs {
		got = append(got, strings.Join([]string{
			lookupPath(o, "/metadata/namespace").(string), o["kind"].(string), lookupPath(o, "/metadata/name").(string),
		}, "/"))
	}
	want := []string{
		"a/CiliumNetworkPolicy/kshield-egress",
		"a/TracingPolicyNamespaced/kshield-shell-exec",
		"a/TracingPolicyNamespaced/kshield-egress-connect",
		"a/Policy/kshield-admission",
		"b/CiliumNetworkPolicy/kshield-egress",
		"b/TracingPolicyNamespaced/kshield-shell-exec",
		"b/TracingPolicyNamespaced/kshield-egress-connect",
		"b/Policy/kshield-admission",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPoliciesRatedByChecks(t *testing.T) {
	for _, opt := range policyOpts {
		docs := append([]string{vllmIn(t, policyNS), vllmIn(t, "ai-train")}, policyDocs(t, mustPolicies(t, []string{policyNS, "ai-train"}, opt))...)
		in := loadInput(t, joinDocs(t, docs...))
		for _, id := range guardChecks {
			fs := findingsOf(t, in, id)
			switch opt.Mode {
			case "audit":
				if len(fs) == 0 {
					t.Errorf("audit %s: no finding, want Suspect", id)
				}
				for _, f := range fs {
					if f.Strength != check.Suspect {
						t.Errorf("audit %s: Violation %s: %s", id, f.Path, f.Message)
					}
				}
			case "enforce":
				for _, f := range fs {
					t.Errorf("enforce %s: finding %s: %s", id, f.Path, f.Message)
				}
			}
		}
		for _, f := range findingsOf(t, in, "KS-NET-002") {
			t.Errorf("%s KS-NET-002: %s %s: %s", opt.Mode, f.Object, f.Path, f.Message)
		}
	}
}

func TestPoliciesModeValues(t *testing.T) {
	connectOptions := []any{map[string]any{"name": "disable-kprobe-multi", "value": "1"}}
	connectArgs := []any{map[string]any{"index": int64(0), "type": "socket"}, map[string]any{"index": int64(1), "type": "sockaddr"}}
	tcpOnly := map[string]any{"index": int64(0), "operator": "Protocol", "values": []any{"IPPROTO_TCP"}}
	want := map[string]map[string]any{
		"audit": {
			"kshield-egress|/spec/enableDefaultDeny":                                  map[string]any{"egress": false, "ingress": false},
			"kshield-shell-exec|/spec/kprobes/0/selectors/0/matchActions":             []any{map[string]any{"action": "Post"}},
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchActions":         []any{map[string]any{"action": "Post"}},
			"kshield-egress-connect|/spec/kprobes/0/call":                             "security_socket_connect",
			"kshield-egress-connect|/spec/options":                                    connectOptions,
			"kshield-egress-connect|/spec/kprobes/0/args":                             connectArgs,
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/0":          tcpOnly,
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/1/index":    int64(1),
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/1/operator": "NotSAddr",
			"kshield-shell-exec|/spec/options":                                        nil,
			"kshield-admission|/spec/rules/0/validate/failureAction":                  "Audit",
			"kshield-admission|/spec/rules/1/validate/failureAction":                  "Audit",
		},
		"enforce": {
			"kshield-egress|/spec/enableDefaultDeny":                                  map[string]any{"egress": true, "ingress": false},
			"kshield-shell-exec|/spec/kprobes/0/selectors/0/matchActions":             []any{map[string]any{"action": "Sigkill"}},
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchActions":         []any{map[string]any{"action": "Override", "argError": int64(-1)}},
			"kshield-egress-connect|/spec/kprobes/0/call":                             "security_socket_connect",
			"kshield-egress-connect|/spec/options":                                    connectOptions,
			"kshield-egress-connect|/spec/kprobes/0/args":                             connectArgs,
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/0":          tcpOnly,
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/1/index":    int64(1),
			"kshield-egress-connect|/spec/kprobes/0/selectors/0/matchArgs/1/operator": "NotSAddr",
			"kshield-shell-exec|/spec/options":                                        nil,
			"kshield-admission|/spec/rules/0/validate/failureAction":                  "Enforce",
			"kshield-admission|/spec/rules/1/validate/failureAction":                  "Enforce",
		},
	}
	for mode, fields := range want {
		objs := mustPolicies(t, []string{policyNS}, PolicyOptions{Mode: mode})
		for key, v := range fields {
			name, ptr, _ := strings.Cut(key, "|")
			n := 0
			for _, o := range objs {
				if lookupPath(o, "/metadata/name") != name {
					continue
				}
				n++
				if got := lookupPath(o, ptr); !reflect.DeepEqual(got, v) {
					t.Errorf("%s %s %s: %#v, want %#v", mode, name, ptr, got, v)
				}
			}
			if n != 1 {
				t.Errorf("%s: %d objects named %s, want 1", mode, n, name)
			}
		}
	}
}

func TestPoliciesPeerRules(t *testing.T) {
	objs := mustPolicies(t, []string{policyNS, "ai-train"}, policyOpts[1])
	nsRule := func(ns string) map[string]any {
		return map[string]any{"matchLabels": map[string]any{"k8s:io.kubernetes.pod.namespace": ns}}
	}
	cases := []struct {
		cnp  map[string]any
		want []any
	}{
		{objs[0], []any{
			map[string]any{"toEndpoints": []any{nsRule("ai-train"), nsRule("vector-db")}},
		}},
		{objs[4], []any{
			map[string]any{"toEndpoints": []any{nsRule(policyNS)}},
		}},
	}
	for _, c := range cases {
		ns := lookupPath(c.cnp, "/metadata/namespace")
		egress, _ := lookupPath(c.cnp, "/spec/egress").([]any)
		if len(egress) != 4+len(c.want) {
			t.Fatalf("%s: %d egress rules, want %d: %v", ns, len(egress), 4+len(c.want), egress)
		}
		if got := egress[2 : 2+len(c.want)]; !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: peer rules %v, want %v", ns, got, c.want)
		}
	}
}

func TestAPIServerPolicyHeadOnly(t *testing.T) {
	for _, opt := range policyOpts {
		objs := mustPolicies(t, []string{policyNS, "ai-train"}, opt)
		var found []map[string]any
		for _, o := range objs {
			if lookupPath(o, "/metadata/name") == apiServerPolicyName {
				found = append(found, o)
			}
			egress, _ := lookupPath(o, "/spec/egress").([]any)
			if lookupPath(o, "/metadata/name") == egressPolicyName {
				for _, r := range egress {
					if _, ok := r.(map[string]any)["toEntities"]; ok {
						t.Errorf("%s: %s/%s has a toEntities rule: %v", opt.Mode, lookupPath(o, "/metadata/namespace"), egressPolicyName, r)
					}
				}
			}
		}
		if len(found) != 1 {
			t.Fatalf("%s: %d %s objects, want 1", opt.Mode, len(found), apiServerPolicyName)
		}
		o := found[0]
		if lookupPath(o, "/metadata/namespace") != "ai-train" || o["kind"] != "CiliumNetworkPolicy" || o["apiVersion"] != "cilium.io/v2" {
			t.Errorf("%s: policy %v", opt.Mode, o)
		}
		wantSel := map[string]any{"matchLabels": map[string]any{"ray.io/node-type": "head"}}
		if got := lookupPath(o, "/spec/endpointSelector"); !reflect.DeepEqual(got, wantSel) {
			t.Errorf("%s: endpointSelector %v, want %v", opt.Mode, got, wantSel)
		}
		wantEgress := []any{map[string]any{"toEntities": []any{"kube-apiserver"}}}
		if got := lookupPath(o, "/spec/egress"); !reflect.DeepEqual(got, wantEgress) {
			t.Errorf("%s: egress %v, want %v", opt.Mode, got, wantEgress)
		}
		wantDeny := map[string]any{"egress": opt.Mode == "enforce", "ingress": false}
		if got := lookupPath(o, "/spec/enableDefaultDeny"); !reflect.DeepEqual(got, wantDeny) {
			t.Errorf("%s: enableDefaultDeny %v, want %v", opt.Mode, got, wantDeny)
		}
	}
	none := mustPolicies(t, []string{policyNS}, PolicyOptions{Mode: "enforce"})
	for _, o := range none {
		if lookupPath(o, "/metadata/name") == apiServerPolicyName {
			t.Errorf("%s without APIServerNamespaces", apiServerPolicyName)
		}
	}
}

func TestPolicyPeers(t *testing.T) {
	qdrant := toYAML(t, `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"qdrant","namespace":"vector-db"},
		"spec":{"selector":{"matchLabels":{"app":"qdrant"}},"template":{"metadata":{"labels":{"app":"qdrant"}},
		"spec":{"containers":[{"name":"qdrant","image":"qdrant/qdrant:v1.15.4"}]}}}}`)
	ray := func(ns, autoscaling string) string {
		return toYAML(t, `{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"`+ns+`"},
			"spec":{"enableInTreeAutoscaling":`+autoscaling+`,"headGroupSpec":{"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}}}}`)
	}
	in := loadInput(t, joinDocs(t, vllmIn(t, policyNS), qdrant, webIn(t, "web"), ray("ai-train", "true"), ray("ray-static", "false")))
	peers, apiServer := PolicyPeers(in)
	wantPeers := map[string][]string{
		policyNS:     {"ai-train", "ray-static", "vector-db"},
		"ai-train":   {policyNS, "ray-static", "vector-db"},
		"ray-static": {policyNS, "ai-train", "vector-db"},
		"vector-db":  {policyNS, "ai-train", "ray-static"},
	}
	if !reflect.DeepEqual(peers, wantPeers) {
		t.Errorf("peers %v, want %v", peers, wantPeers)
	}
	if want := []string{"ai-train"}; !slices.Equal(apiServer, want) {
		t.Errorf("API server namespaces %v, want %v", apiServer, want)
	}
	single, none := PolicyPeers(loadInput(t, vllmIn(t, policyNS)))
	if !reflect.DeepEqual(single, map[string][]string{policyNS: {}}) || len(none) != 0 {
		t.Errorf("one AI namespace: peers %v, API server %v", single, none)
	}
}

func TestPoliciesAllowLists(t *testing.T) {
	objs := mustPolicies(t, []string{policyNS}, PolicyOptions{
		Mode:      "enforce",
		AllowFQDN: []string{"huggingface.co", "cdn-lfs.huggingface.co", "huggingface.co"},
		AllowCIDR: []string{"203.0.113.7/24", "2001:db8::/32"},
	})
	cnp, connect := objs[0], objs[2]
	egress, _ := lookupPath(cnp, "/spec/egress").([]any)
	if len(egress) != 4 {
		t.Fatalf("egress rules: %d, want 4 (DNS, namespace, FQDN, CIDR): %v", len(egress), egress)
	}
	fqdn := lookupPath(cnp, "/spec/egress/2/toFQDNs")
	wantFQDN := []any{map[string]any{"matchName": "cdn-lfs.huggingface.co"}, map[string]any{"matchName": "huggingface.co"}}
	if !reflect.DeepEqual(fqdn, wantFQDN) {
		t.Errorf("toFQDNs: %v, want %v", fqdn, wantFQDN)
	}
	if got, want := lookupPath(cnp, "/spec/egress/3/toCIDR"), []any{"2001:db8::/32", "203.0.113.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("toCIDR: %v, want %v", got, want)
	}
	values, _ := lookupPath(connect, "/spec/kprobes/0/selectors/0/matchArgs/1/values").([]any)
	for _, c := range []string{"127.0.0.0/8", "fe80::/10", "0.0.0.0/32", "::/128", "203.0.113.0/24", "2001:db8::/32"} {
		if !slices.Contains(values, any(c)) {
			t.Errorf("NotDAddr values %v lack %s", values, c)
		}
	}
	none := mustPolicies(t, []string{policyNS}, PolicyOptions{Mode: "audit"})
	if egress, _ := lookupPath(none[0], "/spec/egress").([]any); len(egress) != 2 {
		t.Errorf("egress rules without allow flags: %d, want 2", len(egress))
	}
}

func TestEgressConnectAllowsIPv4MappedIPv6(t *testing.T) {
	for _, mode := range []string{"audit", "enforce"} {
		objs := mustPolicies(t, []string{policyNS}, PolicyOptions{Mode: mode, AllowCIDR: []string{"203.0.113.7/24", "2001:db8::/32"}})
		values, _ := lookupPath(objs[2], "/spec/kprobes/0/selectors/0/matchArgs/1/values").([]any)
		for _, c := range []string{"::ffff:127.0.0.0/104", "::ffff:10.0.0.0/104", "::ffff:172.16.0.0/108", "::ffff:192.168.0.0/112", "::ffff:0.0.0.0/128", "::ffff:203.0.113.0/120"} {
			if !slices.Contains(values, any(c)) {
				t.Errorf("%s: NotSAddr values %v lack %s", mode, values, c)
			}
		}
		for _, v := range values {
			if s, _ := v.(string); strings.HasPrefix(s, "::ffff:169.254.") || strings.HasPrefix(s, "::ffff:2001") {
				t.Errorf("%s: NotSAddr values have %s", mode, s)
			}
		}
		if len(values) != 9+2+6 {
			t.Errorf("%s: NotSAddr values: %d, want 17: %v", mode, len(values), values)
		}
	}
}

func TestAllowCIDRRejectsWorld(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "10.1.2.3/0"} {
		if _, err := Policies([]string{policyNS}, PolicyOptions{Mode: "audit", AllowCIDR: []string{cidr}}); err == nil {
			t.Errorf("--allow-cidr %s: no error", cidr)
		}
	}
}

func TestPolicyOptionsErrors(t *testing.T) {
	cases := map[string]struct {
		ns  []string
		opt PolicyOptions
	}{
		"bad mode":       {[]string{policyNS}, PolicyOptions{Mode: "block"}},
		"bad cidr":       {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowCIDR: []string{"10.0.0.0/33"}}},
		"bad fqdn":       {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"bad name"}}},
		"empty fqdn":     {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{""}}},
		"empty ns":       {[]string{""}, PolicyOptions{Mode: "audit"}},
		"bad ns":         {[]string{"AI_Inference"}, PolicyOptions{Mode: "audit"}},
		"wildcard fqdn":  {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"*.example.com"}}},
		"long fqdn":      {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{strings.Repeat("a", 256)}}},
		"trailing space": {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowCIDR: []string{"10.0.0.0/8 "}}},
		"svc fqdn":       {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"qdrant.vector-db.svc"}}},
		"cluster fqdn":   {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"qdrant.vector-db.svc.cluster.local"}}},
		"cluster dot":    {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"api.cluster.local."}}},
		"svc upper":      {[]string{policyNS}, PolicyOptions{Mode: "audit", AllowFQDN: []string{"QDRANT.SVC"}}},
		"bad peer":       {[]string{policyNS}, PolicyOptions{Mode: "audit", PeerNamespaces: map[string][]string{policyNS: {"Bad_NS"}}}},
		"bad apiserver":  {[]string{policyNS}, PolicyOptions{Mode: "audit", APIServerNamespaces: []string{""}}},
	}
	for name, c := range cases {
		if _, err := Policies(c.ns, c.opt); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestPoliciesDeterministic(t *testing.T) {
	opt := policyOpts[1]
	a := joinDocs(t, policyDocs(t, mustPolicies(t, []string{"ai-train", policyNS}, opt))...)
	b := joinDocs(t, policyDocs(t, mustPolicies(t, []string{"ai-train", policyNS}, opt))...)
	if a != b {
		t.Fatalf("two calls differ:\n%s\n---\n%s", a, b)
	}
	opt2 := PolicyOptions{
		Mode:                opt.Mode,
		AllowFQDN:           slices.Clone(opt.AllowFQDN),
		AllowCIDR:           []string{"2001:db8::/32", "203.0.113.0/24", "2001:db8::/32"},
		PeerNamespaces:      map[string][]string{policyNS: {"ai-train", "vector-db", "ai-train", policyNS}, "ai-train": {policyNS}, "other": {"x"}},
		APIServerNamespaces: []string{"ai-train", "ai-train", "other"},
	}
	c := joinDocs(t, policyDocs(t, mustPolicies(t, []string{policyNS, "ai-train", policyNS}, opt2))...)
	if a != c {
		t.Fatalf("input order changes the output:\n%s\n---\n%s", a, c)
	}
	empty := mustPolicies(t, nil, opt)
	if len(empty) != 0 {
		t.Fatalf("no namespaces: %d objects", len(empty))
	}
}

func TestNoPolicyForNamespaceWithoutFindings(t *testing.T) {
	guarded := policyDocs(t, mustPolicies(t, []string{"ai-guarded"}, PolicyOptions{Mode: "enforce"}))
	docs := append([]string{vllmIn(t, policyNS), vllmIn(t, "ai-guarded"), webIn(t, "web")}, guarded...)
	in := loadInput(t, joinDocs(t, docs...))
	got := PolicyNamespaces(in)
	if want := []string{policyNS}; !slices.Equal(got, want) {
		t.Fatalf("namespaces %v, want %v", got, want)
	}
	for _, o := range mustPolicies(t, got, PolicyOptions{Mode: "audit"}) {
		if ns := lookupPath(o, "/metadata/namespace"); ns != policyNS {
			t.Errorf("%s %s in namespace %v", o["kind"], lookupPath(o, "/metadata/name"), ns)
		}
	}
	audit := policyDocs(t, mustPolicies(t, []string{policyNS}, PolicyOptions{Mode: "audit"}))
	in = loadInput(t, joinDocs(t, append([]string{vllmIn(t, policyNS)}, audit...)...))
	if got := PolicyNamespaces(in); !slices.Equal(got, []string{policyNS}) {
		t.Fatalf("audit-guarded namespace: %v, want [%s] (WARN findings need enforce policies)", got, policyNS)
	}
}

func TestPickleDenyPattern(t *testing.T) {
	re := regexp.MustCompile(pickleDenyPattern())
	deny := []string{
		"vllm serve m --trust-remote-code",
		"--trust_remote_code",
		"vllm serve m --load-format pt",
		"vllm serve m --load-format=npcache --port 8000",
		"sh -c vllm serve m\t--load-format \"pt\" && echo ok",
		"python3 -m vllm.entrypoints.openai.api_server --trust-remote-code --model m",
		"vllm serve m --load-format PT",
		"vllm serve m --load-format=NpCache",
		"sh -c vllm serve m --load-format 'pt'",
		"sh -c vllm serve m --load-format='npcache' --port 8000",
	}
	allow := []string{
		"vllm serve m --no-trust-remote-code",
		"vllm serve m --load-format safetensors",
		"vllm serve m --load-format=pth-like",
		"vllm serve m --load-format ptx",
		"vllm serve m --load-format 'safetensors'",
		"vllm serve m --load-format PTX",
		"vllm serve m --trust-remote-code-x",
		"",
	}
	for _, s := range deny {
		if !re.MatchString(s) {
			t.Errorf("not denied: %q", s)
		}
	}
	for _, s := range allow {
		if re.MatchString(s) {
			t.Errorf("denied: %q", s)
		}
	}
	for _, f := range check.PickleFormats {
		if !re.MatchString("--load-format "+f) || !re.MatchString("--load-format="+strings.ToUpper(f)) {
			t.Errorf("pickle format %s not denied", f)
		}
	}
	if strings.ContainsAny(pickleDenyPattern(), "{}'\\") {
		t.Errorf("pattern %q holds a brace, quote or backslash; it breaks the Kyverno JMESPath string", pickleDenyPattern())
	}
}

func TestBundleAPIServerPolicyOnlyWithAutoscaling(t *testing.T) {
	ray := func(autoscaling string) string {
		return toYAML(t, `{"apiVersion":"ray.io/v1","kind":"RayCluster","metadata":{"name":"rc","namespace":"`+policyNS+`"},
			"spec":{"enableInTreeAutoscaling":`+autoscaling+`,
			"headGroupSpec":{"template":{"spec":{"containers":[{"name":"ray-head","image":"rayproject/ray:2.50.0"}]}}},
			"workerGroupSpecs":[{"groupName":"gpu","replicas":1,"template":{"spec":{"containers":[{"name":"ray-worker","image":"rayproject/ray:2.50.0"}]}}}]}}`)
	}
	for _, mode := range []string{"audit", "enforce"} {
		for autoscaling, want := range map[string]bool{"true": true, "false": false} {
			b, err := Run(Options{ScanJSON: scanJSON(t, policyNS, writeInput(t, ray(autoscaling))), Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			names := policyNames(t, b)
			if got := slices.Contains(names, "CiliumNetworkPolicy/"+policyNS+"/"+apiServerPolicyName); got != want {
				t.Errorf("%s autoscaling %s: %s in the bundle is %v, want %v (%v)", mode, autoscaling, apiServerPolicyName, got, want, names)
			}
			if !slices.Contains(names, "CiliumNetworkPolicy/"+policyNS+"/"+egressPolicyName) {
				t.Errorf("%s autoscaling %s: %s missing: %v", mode, autoscaling, egressPolicyName, names)
			}
			if strings.Contains(string(b.Files[FilePolicies]), "toEntities") != want {
				t.Errorf("%s autoscaling %s: toEntities in the policies is %v, want %v", mode, autoscaling, !want, want)
			}
		}
	}
}
