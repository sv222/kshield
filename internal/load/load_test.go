package load

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func refStrings(objs []Object) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = o.Ref.String()
	}
	return out
}

func docs(objs []Object) []int {
	out := make([]int, len(objs))
	for i, o := range objs {
		out[i] = o.Source.Doc
	}
	return out
}

func files(objs []Object) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = o.Source.File
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readStdin(t *testing.T, content string) ([]Object, error) {
	t.Helper()
	return Read([]string{"-"}, Options{Stdin: strings.NewReader(content)})
}

func TestHelmOutput(t *testing.T) {
	objs, err := Read([]string{"testdata/helm.yaml"}, Options{DefaultNamespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Object{
		{
			Ref:    ObjectRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "default", Name: "demo-config"},
			Source: Source{File: "testdata/helm.yaml", Doc: 0, Line: 2},
		},
		{
			Ref:    ObjectRef{APIVersion: "v1", Kind: "Service", Namespace: "default", Name: "demo"},
			Source: Source{File: "testdata/helm.yaml", Doc: 2, Line: 16},
		},
		{
			Ref:    ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "demo"},
			Source: Source{File: "testdata/helm.yaml", Doc: 4, Line: 30},
		},
	}
	if len(objs) != len(want) {
		t.Fatalf("got %d objects %v, want %d", len(objs), refStrings(objs), len(want))
	}
	for i := range want {
		if objs[i].Ref != want[i].Ref {
			t.Errorf("object %d ref = %+v, want %+v", i, objs[i].Ref, want[i].Ref)
		}
		if objs[i].Source != want[i].Source {
			t.Errorf("object %d source = %+v, want %+v", i, objs[i].Source, want[i].Source)
		}
		if got := objs[i].U.GetNamespace(); got != "default" {
			t.Errorf("object %d U namespace = %q, want default", i, got)
		}
	}
	cfg, found, err := unstructured.NestedString(objs[0].U.Object, "data", "config")
	if err != nil || !found {
		t.Fatalf("data.config: found=%v err=%v", found, err)
	}
	if wantCfg := "first: 1\n  ---\nlast: 2\n"; cfg != wantCfg {
		t.Errorf("data.config = %q, want %q", cfg, wantCfg)
	}
	replicas, found, err := unstructured.NestedInt64(objs[2].U.Object, "spec", "replicas")
	if err != nil || !found || replicas != 2 {
		t.Errorf("spec.replicas = %d found=%v err=%v, want int64 2", replicas, found, err)
	}
}

const twoDocs = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: |\n    one\n    two\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: b\n"

func TestCRLF(t *testing.T) {
	dir := t.TempDir()
	lfPath := filepath.Join(dir, "lf.yaml")
	crlfPath := filepath.Join(dir, "crlf.yaml")
	crlf := strings.ReplaceAll(twoDocs, "\n", "\r\n")
	if strings.Count(crlf, "\r\n") != strings.Count(twoDocs, "\n") {
		t.Fatal("crlf twin was not built with \\r\\n")
	}
	writeFile(t, lfPath, twoDocs)
	writeFile(t, crlfPath, crlf)
	raw, err := os.ReadFile(crlfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\r\n") {
		t.Fatal("crlf file on disk has no \\r\\n")
	}
	lf, err := Read([]string{lfPath}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read([]string{crlfPath}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(lf) != 2 {
		t.Fatalf("got %d crlf objects, %d lf objects, want 2 and 2", len(got), len(lf))
	}
	for i := range lf {
		if got[i].Ref != lf[i].Ref {
			t.Errorf("object %d ref = %+v, want %+v", i, got[i].Ref, lf[i].Ref)
		}
		if got[i].Source.Doc != lf[i].Source.Doc {
			t.Errorf("object %d doc = %d, want %d", i, got[i].Source.Doc, lf[i].Source.Doc)
		}
		if !reflect.DeepEqual(got[i].U.Object, lf[i].U.Object) {
			t.Errorf("object %d content differs: %v vs %v", i, got[i].U.Object, lf[i].U.Object)
		}
	}
}

func TestJSONList(t *testing.T) {
	objs, err := Read([]string{"testdata/list.json"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Deployment/ai-inference/vllm", "Service/ai-inference/vllm"}
	if got := refStrings(objs); !slices.Equal(got, want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for i, o := range objs {
		if o.Source != (Source{File: "testdata/list.json", Doc: 0, Line: 1}) {
			t.Errorf("object %d source = %+v, want testdata/list.json doc 0 line 1", i, o.Source)
		}
	}
	if objs[0].Ref.APIVersion != "apps/v1" || objs[1].Ref.APIVersion != "v1" {
		t.Errorf("apiVersions = %q, %q", objs[0].Ref.APIVersion, objs[1].Ref.APIVersion)
	}
	replicas, found, err := unstructured.NestedInt64(objs[0].U.Object, "spec", "replicas")
	if err != nil || !found || replicas != 1 {
		t.Errorf("spec.replicas = %d found=%v err=%v, want int64 1", replicas, found, err)
	}
}

func TestListWithSuffixKind(t *testing.T) {
	in := "apiVersion: v1\nkind: PodList\nitems:\n- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: a\n- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: b\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"
	objs, err := readStdin(t, in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refStrings(objs), []string{"Pod/a", "Pod/b", "Service/s"}; !slices.Equal(got, want) {
		t.Errorf("refs = %v, want %v", got, want)
	}
	if got, want := docs(objs), []int{0, 0, 1}; !slices.Equal(got, want) {
		t.Errorf("docs = %v, want %v", got, want)
	}
}

func TestListEdgeCases(t *testing.T) {
	objs, err := readStdin(t, "apiVersion: v1\nkind: List\nitems: []\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 {
		t.Errorf("empty List gave %v", refStrings(objs))
	}
	_, err = readStdin(t, "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: a\n- apiVersion: v1\n  metadata:\n    name: b\n")
	if err == nil || !strings.Contains(err.Error(), "-#0: items[1]: missing kind") {
		t.Errorf("err = %v, want one containing %q", err, "-#0: items[1]: missing kind")
	}
	_, err = readStdin(t, "apiVersion: v1\nkind: List\nitems:\n- just a string\n")
	if err == nil || !strings.Contains(err.Error(), "-#0: items[0]: not an object") {
		t.Errorf("err = %v, want one containing %q", err, "-#0: items[0]: not an object")
	}
}

func TestEmptyDocumentsAreCounted(t *testing.T) {
	in := "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: first\n---\n---\n# only a comment\n---\nnull\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: late\n"
	objs, err := readStdin(t, in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refStrings(objs), []string{"ConfigMap/first", "ConfigMap/late"}; !slices.Equal(got, want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	if got, want := docs(objs), []int{0, 4}; !slices.Equal(got, want) {
		t.Errorf("docs = %v, want %v", got, want)
	}
}

func TestLeadingEmptyDocumentsAreCounted(t *testing.T) {
	objs, err := readStdin(t, "---\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: late\n")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := docs(objs), []int{1}; !slices.Equal(got, want) {
		t.Errorf("docs = %v, want %v", got, want)
	}
}

func TestDirectoryOrder(t *testing.T) {
	objs, err := Read([]string{"testdata/tree"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"testdata/tree/a.yml", "testdata/tree/b/x.yaml"}
	if got := files(objs); !slices.Equal(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
	if got, want := refStrings(objs), []string{"Deployment/tree/first", "Service/tree/second"}; !slices.Equal(got, want) {
		t.Errorf("refs = %v, want %v", got, want)
	}
}

func TestDirectorySortsByForwardSlashPath(t *testing.T) {
	dir := t.TempDir()
	manifest := func(name string) string {
		return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n"
	}
	writeFile(t, filepath.Join(dir, "b", "x.yaml"), manifest("in-dir"))
	writeFile(t, filepath.Join(dir, "b.yml"), manifest("beside-dir"))
	writeFile(t, filepath.Join(dir, "c.json"), `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"json"}}`)
	writeFile(t, filepath.Join(dir, "d.yaml.bak"), manifest("backup"))
	objs, err := Read([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refStrings(objs), []string{"ConfigMap/beside-dir", "ConfigMap/in-dir", "ConfigMap/json"}; !slices.Equal(got, want) {
		t.Errorf("refs = %v, want %v", got, want)
	}
	for _, f := range files(objs) {
		if strings.Contains(f, "\\") {
			t.Errorf("file %q has a backslash", f)
		}
	}
}

func TestPathsReadInGivenOrder(t *testing.T) {
	objs, err := Read([]string{"testdata/tree/b/x.yaml", "testdata/scoped.yaml", "testdata/tree/a.yml"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"testdata/tree/b/x.yaml", "testdata/scoped.yaml", "testdata/scoped.yaml", "testdata/scoped.yaml", "testdata/scoped.yaml", "testdata/tree/a.yml"}
	if got := files(objs); !slices.Equal(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
}

func TestStdin(t *testing.T) {
	objs, err := readStdin(t, "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: piped\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d objects, want 1", len(objs))
	}
	if objs[0].Source != (Source{File: "-", Doc: 0, Line: 1}) {
		t.Errorf("source = %+v, want {- 0 1}", objs[0].Source)
	}
	if objs[0].Ref.String() != "Deployment/piped" {
		t.Errorf("ref = %s", objs[0].Ref)
	}
}

func TestStdinWithoutReader(t *testing.T) {
	if _, err := Read([]string{"-"}, Options{}); err == nil {
		t.Error("want an error when Stdin is nil")
	}
}

func TestDefaultNamespaceScope(t *testing.T) {
	objs, err := Read([]string{"testdata/scoped.yaml"}, Options{DefaultNamespace: "ai-inference"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Namespace/ai-inference", "ClusterPolicy/require-limits", "TracingPolicy/watch-exec", "Deployment/ai-inference/x"}
	if got := refStrings(objs); !slices.Equal(got, want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for i := 0; i < 3; i++ {
		if ns := objs[i].U.GetNamespace(); ns != "" {
			t.Errorf("object %d U namespace = %q, want empty", i, ns)
		}
		if objs[i].Ref.Namespace != "" {
			t.Errorf("object %d ref namespace = %q, want empty", i, objs[i].Ref.Namespace)
		}
	}
	if ns := objs[3].U.GetNamespace(); ns != "ai-inference" {
		t.Errorf("deployment U namespace = %q, want ai-inference", ns)
	}
}

func TestNoDefaultNamespace(t *testing.T) {
	objs, err := Read([]string{"testdata/scoped.yaml"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := objs[3].Ref.String(); got != "Deployment/x" {
		t.Errorf("ref = %s, want Deployment/x", got)
	}
	if ns := objs[3].U.GetNamespace(); ns != "" {
		t.Errorf("U namespace = %q, want empty", ns)
	}
}

func TestExplicitNamespaceWins(t *testing.T) {
	objs, err := Read([]string{"testdata/tree"}, Options{DefaultNamespace: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refStrings(objs), []string{"Deployment/tree/first", "Service/tree/second"}; !slices.Equal(got, want) {
		t.Errorf("refs = %v, want %v", got, want)
	}
}

func TestMissingKind(t *testing.T) {
	_, err := Read([]string{"testdata/nokind.yaml"}, Options{})
	if err == nil || !strings.Contains(err.Error(), "testdata/nokind.yaml#1: missing kind") {
		t.Errorf("err = %v, want one containing %q", err, "testdata/nokind.yaml#1: missing kind")
	}
}

func TestMissingFields(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"apiVersion", "kind: Pod\nmetadata:\n  name: a\n", "-#0: missing apiVersion"},
		{"kind", "apiVersion: v1\nmetadata:\n  name: a\n", "-#0: missing kind"},
		{"name", "apiVersion: v1\nkind: Pod\nmetadata:\n  labels:\n    a: b\n", "-#0: missing metadata.name"},
		{"metadata", "apiVersion: v1\nkind: Pod\n", "-#0: missing metadata.name"},
		{"second document", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: Pod\n", "-#1: missing metadata.name"},
		{"empty object", "{}\n", "-#0: missing apiVersion"},
		{"kind not a string", "apiVersion: v1\nkind: 5\nmetadata:\n  name: a\n", "-#0: invalid kind"},
		{"namespace not a string", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n  namespace: 7\n", "-#0: invalid metadata.namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readStdin(t, tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestNotAnObject(t *testing.T) {
	for _, in := range []string{"- a\n- b\n", "just text\n", "42\n"} {
		_, err := readStdin(t, in)
		if err == nil || !strings.Contains(err.Error(), "-#0: document is not an object") {
			t.Errorf("input %q: err = %v, want one containing %q", in, err, "-#0: document is not an object")
		}
	}
}

func TestBadYAML(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{"bad.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: [\n"},
		{"bad.json", "{\"apiVersion\": \"v1\", \"kind\": "},
		{"tabs.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n\tname: a\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.ToSlash(filepath.Join(dir, tc.name))
			writeFile(t, path, tc.content)
			_, err := Read([]string{path}, Options{})
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), path+"#0: ") {
				t.Errorf("err = %v, want one containing %q", err, path+"#0: ")
			}
		})
	}
}

func TestBadSecondDocument(t *testing.T) {
	_, err := readStdin(t, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\nmetadata: [\n")
	if err == nil || !strings.Contains(err.Error(), "-#1: ") {
		t.Errorf("err = %v, want one containing %q", err, "-#1: ")
	}
}

func TestMissingPath(t *testing.T) {
	_, err := Read([]string{"testdata/does-not-exist.yaml"}, Options{})
	if err == nil || !strings.Contains(err.Error(), "does-not-exist.yaml") {
		t.Errorf("err = %v, want one naming the file", err)
	}
}

func TestNoPaths(t *testing.T) {
	objs, err := Read(nil, Options{})
	if err != nil || len(objs) != 0 {
		t.Errorf("got %v, %v, want no objects and no error", objs, err)
	}
}

func TestObjectRefString(t *testing.T) {
	cases := []struct {
		ref  ObjectRef
		want string
	}{
		{ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ai", Name: "x"}, "Deployment/ai/x"},
		{ObjectRef{APIVersion: "v1", Kind: "Namespace", Name: "ai"}, "Namespace/ai"},
	}
	for _, tc := range cases {
		if got := tc.ref.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func TestIsClusterScoped(t *testing.T) {
	scoped := []string{
		"Namespace", "Node", "PersistentVolume", "StorageClass", "ClusterRole", "ClusterRoleBinding",
		"CustomResourceDefinition", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
		"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "PriorityClass", "IngressClass",
		"RuntimeClass", "CSIDriver", "APIService", "ClusterPolicy", "ClusterCleanupPolicy", "TracingPolicy",
		"CiliumClusterwideNetworkPolicy", "ClusterServingRuntime", "ClusterStorageContainer", "ClusterIssuer",
	}
	for _, kind := range scoped {
		if !IsClusterScoped(kind) {
			t.Errorf("IsClusterScoped(%q) = false, want true", kind)
		}
	}
	for _, kind := range []string{"Deployment", "Pod", "Service", "Role", "RoleBinding", "ServingRuntime", "InferenceService", "NetworkPolicy", "Policy", "namespace", ""} {
		if IsClusterScoped(kind) {
			t.Errorf("IsClusterScoped(%q) = true, want false", kind)
		}
	}
}

func lines(objs []Object) []int {
	out := make([]int, len(objs))
	for i, o := range objs {
		out[i] = o.Source.Line
	}
	return out
}

const threeHelmDocs = "# Source: chart/templates/a.yaml\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n# Source: chart/templates/b.yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: b\n--- # end of b\n# Source: chart/templates/c.yaml\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: c\n"

func TestSourceLine(t *testing.T) {
	cm := func(name string) string {
		return `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"` + name + `"}}`
	}
	cases := []struct {
		name  string
		in    string
		refs  []string
		lines []int
	}{
		{"three documents with source comments", threeHelmDocs, []string{"ConfigMap/a", "Service/b", "Deployment/c"}, []int{1, 7, 13}},
		{"three documents with crlf", strings.ReplaceAll(threeHelmDocs, "\n", "\r\n"), []string{"ConfigMap/a", "Service/b", "Deployment/c"}, []int{1, 7, 13}},
		{"leading separators", "---\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: late\n", []string{"ConfigMap/late"}, []int{3}},
		{"empty documents", "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: first\n---\n---\n# only a comment\n---\nnull\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: late\n", []string{"ConfigMap/first", "ConfigMap/late"}, []int{2, 12}},
		{"blank lines after separator", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n\n\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n", []string{"ConfigMap/a", "ConfigMap/b"}, []int{1, 6}},
		{"json list after blank lines", "\n\n" + `{"apiVersion":"v1","kind":"List","items":[` + cm("x") + ",\n" + cm("y") + "]}\n", []string{"ConfigMap/x", "ConfigMap/y"}, []int{3, 3}},
		{"json stream", cm("x") + "\n\n  " + cm("y") + "\n" + cm("z"), []string{"ConfigMap/x", "ConfigMap/y", "ConfigMap/z"}, []int{1, 3, 4}},
		{"json then yaml", cm("j") + "\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: w\n", []string{"ConfigMap/j", "ConfigMap/w"}, []int{1, 3}},
		{"json then yaml without separator", cm("j") + " \t\n\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: w\n", []string{"ConfigMap/j", "ConfigMap/w"}, []int{1, 2}},
		{"yaml flow mapping", "{apiVersion: v1, kind: ConfigMap, metadata: {name: f}}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: w\n", []string{"ConfigMap/f", "ConfigMap/w"}, []int{1, 3}},
		{"json then two separators", cm("j") + "\n---\n---\n" + yamlCM("w") + "---\n" + yamlCM("v"), []string{"ConfigMap/j", "ConfigMap/w", "ConfigMap/v"}, []int{1, 4, 9}},
		{"json then three separators in yaml", cm("j") + "\n---\n" + yamlCM("w") + "---\n---\n---\n" + yamlCM("v"), []string{"ConfigMap/j", "ConfigMap/w", "ConfigMap/v"}, []int{1, 3, 10}},
		{"three separators in yaml", yamlCM("w") + "---\n---\n---\n" + yamlCM("v"), []string{"ConfigMap/w", "ConfigMap/v"}, []int{1, 8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := readStdin(t, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := refStrings(objs); !slices.Equal(got, tc.refs) {
				t.Fatalf("refs = %v, want %v", got, tc.refs)
			}
			if got := lines(objs); !slices.Equal(got, tc.lines) {
				t.Errorf("lines = %v, want %v", got, tc.lines)
			}
		})
	}
}

func yamlCM(name string) string {
	return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n"
}

func decodedDocs(t *testing.T, data []byte) int {
	t.Helper()
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(keepEmptyDocuments(data)), peekSize)
	for n := 0; ; n++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return n
			}
			t.Fatalf("decode doc %d: %v", n, err)
		}
	}
}

func TestDocLinesMatchDecoder(t *testing.T) {
	j := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"j"}}`
	inputs := []string{
		threeHelmDocs,
		strings.ReplaceAll(threeHelmDocs, "\n", "\r\n"),
		"---\n",
		"---\n---\n---\n",
		"---\n" + yamlCM("a") + "---\n---\n# c\n---\nnull\n---\n" + yamlCM("b") + "---\n",
		yamlCM("a") + "---\n---\n---\n" + yamlCM("b"),
		yamlCM("a") + "---\n---\n---\n---\n",
		j,
		j + "\n" + j + "\n\n" + j,
		j + "\n---\n" + yamlCM("w"),
		j + "\n---\n---\n" + yamlCM("w") + "---\n" + yamlCM("v"),
		j + "\n---\n" + yamlCM("w") + "---\n---\n---\n" + yamlCM("v"),
		j + "\n---\n---\n---\n---\n" + yamlCM("w") + "---\n---\n",
		j + " \t\n\n" + yamlCM("w"),
		"{apiVersion: v1, kind: ConfigMap, metadata: {name: f}}\n---\n---\n" + yamlCM("w"),
		strings.Repeat(" ", peekSize+10) + j,
	}
	for _, path := range []string{"testdata/helm.yaml", "testdata/list.json", "testdata/scoped.yaml", "../../test/corpus/baseline/toxic/input.yaml"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, string(b))
	}
	for i, in := range inputs {
		data := []byte(in)
		starts := docLines(data)
		if got, want := len(starts), decodedDocs(t, data); got != want {
			t.Errorf("input %d: %d line starts, decoder gives %d documents (starts %v)", i, got, want, starts)
		}
		for d, s := range starts {
			if s <= 0 {
				t.Errorf("input %d: doc %d has line %d", i, d, s)
			}
		}
	}
}

func TestSourceLineInFile(t *testing.T) {
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "chart.yaml"))
	writeFile(t, path, threeHelmDocs)
	objs, err := Read([]string{path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{{File: path, Doc: 0, Line: 1}, {File: path, Doc: 1, Line: 7}, {File: path, Doc: 2, Line: 13}}
	if len(objs) != len(want) {
		t.Fatalf("got %d objects, want %d", len(objs), len(want))
	}
	for i := range want {
		if objs[i].Source != want[i] {
			t.Errorf("object %d source = %+v, want %+v", i, objs[i].Source, want[i])
		}
	}
}

func TestDigests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b", "c.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")
	writeFile(t, filepath.Join(dir, "a.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n")
	writeFile(t, filepath.Join(dir, "notes.txt"), "not a manifest")
	var got []Digest
	if _, err := Read([]string{dir}, Options{Digests: &got}); err != nil {
		t.Fatal(err)
	}
	root := filepath.ToSlash(dir)
	want := []Digest{
		{Path: root + "/a.yaml", SHA256: "01556c1b213a2dffd4cfbb0904b27c35c3cbe925939b2780274279eac0379589"},
		{Path: root + "/b/c.yaml", SHA256: "ca9d3ca5176c7e9a230dc0868762cd4eb0a0d4278eecdba35c1552e0d646b752"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("digests = %+v, want %+v", got, want)
	}
}

func TestDigestsKeepInputOrder(t *testing.T) {
	var got []Digest
	stdin := strings.NewReader("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")
	if _, err := Read([]string{"testdata/tree/b/x.yaml", "-", "testdata/tree/a.yml"}, Options{Stdin: stdin, Digests: &got}); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, len(got))
	for i, d := range got {
		paths[i] = d.Path
	}
	if want := []string{"testdata/tree/b/x.yaml", "-", "testdata/tree/a.yml"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if got[1].SHA256 != "ca9d3ca5176c7e9a230dc0868762cd4eb0a0d4278eecdba35c1552e0d646b752" {
		t.Errorf("stdin digest = %s", got[1].SHA256)
	}
}

func TestStdinDigest(t *testing.T) {
	var got []Digest
	_, err := Read([]string{"-"}, Options{Stdin: strings.NewReader("abc"), Digests: &got})
	if err == nil || !strings.Contains(err.Error(), "document is not an object") {
		t.Errorf("err = %v, want a not-an-object error", err)
	}
	want := []Digest{{Path: "-", SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}
	if !slices.Equal(got, want) {
		t.Errorf("digests = %+v, want %+v", got, want)
	}
}

func TestStdinDigestCoversAllBytes(t *testing.T) {
	in := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: big\ndata:\n  k: " + strings.Repeat("x", 3*peekSize) + "\n"
	var got []Digest
	if _, err := Read([]string{"-"}, Options{Stdin: strings.NewReader(in), Digests: &got}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(in))
	if len(got) != 1 || got[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("digests = %+v, want sha256 of all %d bytes", got, len(in))
	}
}

func TestFileNamedDashIsNotStdin(t *testing.T) {
	dir := t.TempDir()
	content := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: dash\n"
	writeFile(t, filepath.Join(dir, "-"), content)
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	sum := sha256.Sum256([]byte(content))
	for _, arg := range []string{"./-", "./a/../-"} {
		var got []Digest
		objs, err := Read([]string{arg}, Options{Stdin: strings.NewReader("not read"), Digests: &got})
		if err != nil {
			t.Fatal(err)
		}
		want := []Digest{{Path: "./-", SHA256: hex.EncodeToString(sum[:])}}
		if !slices.Equal(got, want) {
			t.Errorf("%s: digests = %+v, want %+v", arg, got, want)
		}
		if len(objs) != 1 || objs[0].Source.File != "./-" {
			t.Errorf("%s: objects = %+v", arg, objs)
		}
	}
}
