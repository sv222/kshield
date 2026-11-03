//go:build kind

package kind

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/cli"
)

func buildBundle(t *testing.T, dir string) []*unstructured.Unstructured {
	t.Helper()
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), dir)
	if err != nil {
		t.Fatalf("kustomize build %s: %v", dir, err)
	}
	var out []*unstructured.Unstructured
	for _, r := range m.Resources() {
		y, err := r.AsYAML()
		if err != nil {
			t.Fatal(err)
		}
		js, err := yaml.YAMLToJSON(y)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err := u.UnmarshalJSON(js); err != nil {
			t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

func TestKindRemediateFromCluster(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)
	kc := kubeconfig(t)
	work := t.TempDir()
	scanPath := filepath.Join(work, "scan.json")
	wantExit(t, runScan(t, kc, "-n", ns, "--format", "json", "--deterministic", "--out", scanPath), 1)

	bundle := filepath.Join(work, "bundle")
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"remediate", "--from", scanPath, "--kubeconfig", kc, "--out", bundle}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("remediate exit %d\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}

	built := buildBundle(t, bundle)
	var ids []string
	for _, u := range built {
		ids = append(ids, u.GetKind()+"/"+u.GetNamespace()+"/"+u.GetName())
		for _, f := range [][]string{{"status"}, {"metadata", "managedFields"}, {"metadata", "resourceVersion"}, {"metadata", "uid"}, {"metadata", "creationTimestamp"}, {"metadata", "generation"}, {"metadata", "annotations", "kubectl.kubernetes.io/last-applied-configuration"}, {"metadata", "annotations", "deployment.kubernetes.io/revision"}} {
			if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, f...); found {
				t.Errorf("%s still has %s", u.GetName(), strings.Join(f, "."))
			}
		}
	}
	slices.Sort(ids)
	want := []string{"Deployment/" + ns + "/qdrant", "Deployment/" + ns + "/vllm", "RayCluster/" + ns + "/rc"}
	if !slices.Equal(ids, want) {
		t.Fatalf("built objects %v, want %v", ids, want)
	}

	dyn, cs := clients(t)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(cs.Discovery()))
	dryRun := func(u *unstructured.Unstructured) error {
		mapping := restMapping(t, mapper, "bundle", u.GroupVersionKind())
		_, err := dyn.Resource(mapping.Resource).Namespace(u.GetNamespace()).Apply(t.Context(), u.GetName(), u, metav1.ApplyOptions{FieldManager: fieldManager, Force: true, DryRun: []string{metav1.DryRunAll}})
		return err
	}
	before, err := cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range built {
		if err := dryRun(u); err != nil {
			t.Errorf("server-side dry-run apply of %s %s: %v", u.GetKind(), u.GetName(), err)
		}
	}
	after, err := cs.AppsV1().Deployments(ns).Get(t.Context(), "vllm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.ResourceVersion != after.ResourceVersion {
		t.Errorf("the dry run changed the live Deployment: resourceVersion %s -> %s", before.ResourceVersion, after.ResourceVersion)
	}

	t.Run("control: a broken object fails the dry run", func(t *testing.T) {
		bad := built[slices.IndexFunc(built, func(u *unstructured.Unstructured) bool { return u.GetKind() == "Deployment" })].DeepCopy()
		if err := unstructured.SetNestedField(bad.Object, int64(1), "spec", "kshieldNotAField"); err != nil {
			t.Fatal(err)
		}
		if err := dryRun(bad); err == nil {
			t.Error("the dry run accepted an object with an unknown field: it proves nothing")
		}
	})
}
