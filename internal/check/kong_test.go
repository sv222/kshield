package check

import (
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
)

func kongDoc(kind, namespace, name, body string) string {
	doc := "---\napiVersion: configuration.konghq.com/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n"
	if namespace != "" {
		doc += "  namespace: " + namespace + "\n"
	}
	return doc + body
}

func parseKongDoc(t *testing.T, doc string) kongPlugin {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(doc)})
	if err != nil {
		t.Fatal(err)
	}
	return parseKongPlugin(objs[0])
}

func TestParseKongPlugin(t *testing.T) {
	cases := []struct {
		name string
		kind string
		body string
		auth bool
	}{
		{"key-auth", kindKongPlugin, "plugin: key-auth\n", true},
		{"cluster jwt", kindKongClusterPlugin, "plugin: jwt\n", true},
		{"rate limiting", kindKongPlugin, "plugin: rate-limiting\n", false},
		{"disabled", kindKongPlugin, "plugin: key-auth\ndisabled: true\n", false},
		{"anonymous consumer", kindKongPlugin, "plugin: key-auth\nconfig:\n  anonymous: consumer-anon\n", false},
		{"empty anonymous", kindKongPlugin, "plugin: key-auth\nconfig:\n  anonymous: \"\"\n", true},
		{"no plugin", kindKongPlugin, "config: {}\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := parseKongDoc(t, kongDoc(c.kind, "ai", "p", c.body))
			if p.auth != c.auth {
				t.Errorf("auth = %v, want %v", p.auth, c.auth)
			}
			if p.cluster != (c.kind == kindKongClusterPlugin) {
				t.Errorf("cluster = %v", p.cluster)
			}
		})
	}
}

func TestParseKongPluginKnowsEveryAuthPlugin(t *testing.T) {
	for _, plugin := range kongAuthPlugins {
		if p := parseKongDoc(t, kongDoc(kindKongPlugin, "ai", "p", "plugin: "+plugin+"\n")); !p.auth {
			t.Errorf("%s is not an auth plugin", plugin)
		}
	}
}

func kongInput(t *testing.T, extra string) *Input {
	t.Helper()
	in, _ := exposureInput(t, vllmContainerSpec, extra)
	return in
}

func TestKongAuthBinding(t *testing.T) {
	plugins := kongDoc(kindKongPlugin, "ai", "key-auth", "plugin: key-auth\n") +
		kongDoc(kindKongPlugin, "ai", "rate", "plugin: rate-limiting\n") +
		kongDoc(kindKongPlugin, "other", "foreign", "plugin: key-auth\n") +
		kongDoc(kindKongClusterPlugin, "", "jwt-all", "plugin: jwt\n")
	cases := []struct {
		name        string
		annotations map[string]string
		refs        []string
		want        string
	}{
		{"none", nil, nil, ""},
		{"annotation", map[string]string{"konghq.com/plugins": "key-auth"}, nil, "KongPlugin ai/key-auth"},
		{"legacy annotation", map[string]string{"plugins.konghq.com": "key-auth"}, nil, "KongPlugin ai/key-auth"},
		{"list with an auth plugin", map[string]string{"konghq.com/plugins": "rate, key-auth"}, nil, "KongPlugin ai/key-auth"},
		{"rate limit only", map[string]string{"konghq.com/plugins": "rate"}, nil, ""},
		{"unknown plugin", map[string]string{"konghq.com/plugins": "missing"}, nil, ""},
		{"plugin of another namespace", map[string]string{"konghq.com/plugins": "foreign"}, nil, ""},
		{"cluster plugin", map[string]string{"konghq.com/plugins": "jwt-all"}, nil, "KongClusterPlugin jwt-all"},
		{"extension ref", nil, []string{"key-auth"}, "KongPlugin ai/key-auth"},
		{"unrelated annotation", map[string]string{"konghq.com/strip-path": "true"}, nil, ""},
	}
	in := kongInput(t, plugins)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := kongAuth(in, "ai", c.annotations, c.refs)
			if ok != (c.want != "") {
				t.Fatalf("kongAuth = %v (%+v), want %q", ok, a, c.want)
			}
			if ok && (a.Source != AuthKong || !strings.Contains(a.Text(), c.want)) {
				t.Errorf("evidence %+v lacks %q", a, c.want)
			}
		})
	}
}
