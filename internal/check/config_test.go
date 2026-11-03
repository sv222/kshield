package check

import (
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const qdrantMountSpec = `
containers:
  - name: qdrant
    image: qdrant/qdrant:v1.19.2
volumes:
  - name: cfg
    configMap:
      name: qcfg
  - name: data
    emptyDir: {}
`

func configMapDoc(namespace, name, data string) string {
	return "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\ndata:\n" + data
}

func mountedConfigOf(t *testing.T, podSpec, extra string) []map[string]any {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(deployment(podSpec) + extra)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range ws {
		if w.Owner.String() == deployRef {
			return MountedConfig(&Input{Objects: objs, Workloads: ws}, w)
		}
	}
	t.Fatal("no workload")
	return nil
}

func TestMountedConfig(t *testing.T) {
	data := "  config.yaml: \"service:\\n  api_key: x\\n\"\n  notes: \"not: [yaml\"\n"
	got := mountedConfigOf(t, qdrantMountSpec, configMapDoc("ai", "qcfg", data)+configMapDoc("other", "qcfg", "  other.yaml: \"service:\\n  api_key: y\\n\"\n"))
	if len(got) != 1 {
		t.Fatalf("got %d maps %+v, want 1", len(got), got)
	}
	if v := dig(got[0], "service", "api_key"); v != "x" {
		t.Fatalf("service.api_key = %v", v)
	}
}

func TestMountedConfigCases(t *testing.T) {
	cases := []struct {
		name  string
		spec  string
		extra string
		want  int
	}{
		{"no volumes", vllmContainerSpec, configMapDoc("ai", "qcfg", "  a.yaml: \"k: v\\n\"\n"), 0},
		{"missing config map", qdrantMountSpec, "", 0},
		{"other name", qdrantMountSpec, configMapDoc("ai", "other", "  a.yaml: \"k: v\\n\"\n"), 0},
		{"scalar value is skipped", qdrantMountSpec, configMapDoc("ai", "qcfg", "  a: \"plain\"\n"), 0},
		{"list value is skipped", qdrantMountSpec, configMapDoc("ai", "qcfg", "  a: \"- x\\n- y\\n\"\n"), 0},
		{"two keys", qdrantMountSpec, configMapDoc("ai", "qcfg", "  a.yaml: \"k: v\\n\"\n  b.yaml: \"j: w\\n\"\n"), 2},
		{"no data", qdrantMountSpec, "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: qcfg\n  namespace: ai\n", 0},
		{"not a core config map", qdrantMountSpec, "---\napiVersion: example.com/v1\nkind: ConfigMap\nmetadata:\n  name: qcfg\n  namespace: ai\ndata:\n  a.yaml: \"k: v\\n\"\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountedConfigOf(t, tc.spec, tc.extra); len(got) != tc.want {
				t.Fatalf("got %d maps %+v, want %d", len(got), got, tc.want)
			}
		})
	}
}

const qdrantSecretSpec = `
containers:
  - name: qdrant
    image: qdrant/qdrant:v1.19.2
volumes:
  - name: cfg
    configMap:
      name: qcfg
  - name: key
    secret:
      secretName: qkey
`

func secretDoc(namespace, name, body string) string {
	return "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\n" + body
}

func mountedSecretConfigOf(t *testing.T, podSpec, extra string) ([]map[string]any, []MissingSecret) {
	t.Helper()
	objs, err := load.Read([]string{"-"}, load.Options{Stdin: strings.NewReader(deployment(podSpec) + extra)})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := model.Extract(objs)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range ws {
		if w.Owner.String() == deployRef {
			return MountedSecretConfig(&Input{Objects: objs, Workloads: ws}, w)
		}
	}
	t.Fatal("no workload")
	return nil, nil
}

func TestMountedSecretConfig(t *testing.T) {
	keyYAML := "c2VydmljZToKICBhcGlfa2V5OiB4Cg=="
	cases := []struct {
		name    string
		spec    string
		extra   string
		want    int
		missing []MissingSecret
	}{
		{"decodes data", qdrantSecretSpec, secretDoc("ai", "qkey", "data:\n  local.yaml: "+keyYAML+"\n"), 1, nil},
		{"string data", qdrantSecretSpec, secretDoc("ai", "qkey", "stringData:\n  local.yaml: \"service:\\n  api_key: x\\n\"\n"), 1, nil},
		{"string data wins over data", qdrantSecretSpec, secretDoc("ai", "qkey", "data:\n  local.yaml: c2VydmljZToKICBhcGlfa2V5OiB5Cg==\nstringData:\n  local.yaml: \"service:\\n  api_key: x\\n\"\n"), 1, nil},
		{"bad base64 is skipped", qdrantSecretSpec, secretDoc("ai", "qkey", "data:\n  local.yaml: \"%%%\"\n"), 0, nil},
		{"scalar value is skipped", qdrantSecretSpec, secretDoc("ai", "qkey", "data:\n  api-key: azEyMw==\n"), 0, nil},
		{"no data", qdrantSecretSpec, secretDoc("ai", "qkey", ""), 0, nil},
		{"missing secret", qdrantSecretSpec, "", 0, []MissingSecret{{Volume: "key", Secret: "qkey"}}},
		{"other namespace", qdrantSecretSpec, secretDoc("other", "qkey", "data:\n  local.yaml: "+keyYAML+"\n"), 0, []MissingSecret{{Volume: "key", Secret: "qkey"}}},
		{"config map is not a secret", qdrantSecretSpec, configMapDoc("ai", "qkey", "  local.yaml: \"service:\\n  api_key: x\\n\"\n"), 0, []MissingSecret{{Volume: "key", Secret: "qkey"}}},
		{"no secret volume", qdrantMountSpec, secretDoc("ai", "qkey", "data:\n  local.yaml: "+keyYAML+"\n"), 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, missing := mountedSecretConfigOf(t, tc.spec, tc.extra)
			if len(got) != tc.want || !slices.Equal(missing, tc.missing) {
				t.Fatalf("got %d maps %+v missing %v, want %d missing %v", len(got), got, missing, tc.want, tc.missing)
			}
			if tc.want == 1 {
				if v := dig(got[0], "service", "api_key"); v != "x" {
					t.Fatalf("service.api_key = %v", v)
				}
			}
		})
	}
}

func TestMountedConfigKeyOrder(t *testing.T) {
	got := mountedConfigOf(t, qdrantMountSpec, configMapDoc("ai", "qcfg", "  b.yaml: \"k: 2\\n\"\n  a.yaml: \"k: 1\\n\"\n"))
	if len(got) != 2 || got[0]["k"] != float64(1) || got[1]["k"] != float64(2) {
		t.Fatalf("got %+v, want data keys in sorted order", got)
	}
}
