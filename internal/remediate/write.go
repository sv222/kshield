package remediate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/version"
)

const (
	toolName          = "kshield"
	kustomizeVersion  = "kustomize.config.k8s.io/v1beta1"
	kindKustomization = "Kustomization"
	kindConfigMap     = "ConfigMap"

	lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"
	revisionAnnotation    = "deployment.kubernetes.io/revision"
)

var strippedAnnotations = []string{lastAppliedAnnotation, revisionAnnotation}

var stripFields = [][]string{
	{"status"},
	{"metadata", "managedFields"},
	{"metadata", "resourceVersion"},
	{"metadata", "uid"},
	{"metadata", "creationTimestamp"},
	{"metadata", "generation"},
}

type objectJSON struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type itemJSON struct {
	Check     string     `json:"check"`
	Display   string     `json:"display"`
	Verdict   string     `json:"verdict"`
	Object    objectJSON `json:"object"`
	Group     string     `json:"group,omitempty"`
	Container string     `json:"container,omitempty"`
	Path      string     `json:"path"`
	Action    string     `json:"action"`
	File      string     `json:"file"`
	Reason    string     `json:"reason"`
}

type profileJSON struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type remediationJSON struct {
	SchemaVersion string      `json:"schemaVersion"`
	Tool          report.Tool `json:"tool"`
	Profile       profileJSON `json:"profile"`
	Mode          string      `json:"mode"`
	ScanSHA256    string      `json:"scanSha256"`
	Items         []itemJSON  `json:"items"`
}

type kustomizeTarget struct {
	Group     string `json:"group,omitempty"`
	Version   string `json:"version"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type kustomizePatch struct {
	Path   string           `json:"path"`
	Target *kustomizeTarget `json:"target,omitempty"`
}

type kustomization struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Resources  []string         `json:"resources"`
	Patches    []kustomizePatch `json:"patches,omitempty"`
}

func (b *builder) bundle() (*Bundle, error) {
	files := map[string][]byte{}
	base, err := b.base()
	if err != nil {
		return nil, err
	}
	files[FileBase] = base
	var smps []any
	k := kustomization{APIVersion: kustomizeVersion, Kind: kindKustomization, Resources: []string{FileBase}}
	for _, t := range b.targets {
		if t.smp != nil {
			smps = append(smps, t.smp)
		}
		if len(t.json) == 0 {
			continue
		}
		name := patchFileName(t.ref)
		if files[name], err = yaml.Marshal(t.json); err != nil {
			return nil, err
		}
		group, ver := splitAPIVersion(t.ref.APIVersion)
		k.Patches = append(k.Patches, kustomizePatch{Path: name, Target: &kustomizeTarget{
			Group: group, Version: ver, Kind: t.ref.Kind, Name: t.ref.Name, Namespace: t.ref.Namespace,
		}})
	}
	if files[FileWorkloadPatch], err = yamlDocs(smps); err != nil {
		return nil, err
	}
	if len(smps) > 0 {
		k.Patches = append(k.Patches, kustomizePatch{Path: FileWorkloadPatch})
	}
	if files[FileKustomization], err = yaml.Marshal(k); err != nil {
		return nil, err
	}
	policies := make([]any, len(b.policies))
	for i, p := range b.policies {
		policies[i] = p
	}
	if files[FilePolicies], err = yamlDocs(policies); err != nil {
		return nil, err
	}
	if files[FileRemediation], err = b.remediationJSON(); err != nil {
		return nil, err
	}
	files[FileManual] = b.manual()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		for _, v := range b.literals {
			if bytes.Contains(files[name], []byte(v)) {
				return nil, fmt.Errorf("%s would hold a secret value of the input; move the value to a Secret first", name)
			}
		}
	}
	return &Bundle{Files: files}, nil
}

func yamlDocs(docs []any) ([]byte, error) {
	var buf bytes.Buffer
	for i, d := range docs {
		y, err := yaml.Marshal(d)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			buf.WriteString("---\n")
		}
		buf.Write(y)
	}
	return buf.Bytes(), nil
}

func (b *builder) remediationJSON() ([]byte, error) {
	doc := remediationJSON{
		SchemaVersion: RemediationSchema,
		Tool:          report.Tool{Name: toolName, Version: version.Version},
		Profile:       profileJSON{ID: b.report.Profile.ID, SHA256: b.report.Profile.SHA256},
		Mode:          b.mode,
		ScanSHA256:    b.scanSum,
		Items:         []itemJSON{},
	}
	for _, it := range b.items {
		f := it.finding
		doc.Items = append(doc.Items, itemJSON{
			Check:     it.checkID,
			Display:   it.display,
			Verdict:   f.Verdict,
			Object:    objectJSON{f.Object.APIVersion, f.Object.Kind, f.Object.Namespace, f.Object.Name},
			Group:     f.Group,
			Container: f.Container,
			Path:      f.Path,
			Action:    it.action,
			File:      it.file,
			Reason:    it.reason,
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isSecret(ref load.ObjectRef) bool {
	return ref.Kind == "Secret" && ref.APIVersion == "v1"
}

func owned(o *load.Object) bool {
	return o != nil && o.U != nil && len(o.U.GetOwnerReferences()) > 0
}

func (b *builder) clusterBase() ([]byte, error) {
	var docs []any
	for _, t := range b.targets {
		if t.smp == nil && len(t.json) == 0 {
			continue
		}
		if isSecret(t.ref) || t.ref.Kind == kindConfigMap {
			return nil, fmt.Errorf("%s is a patch target, and base/ never holds a Secret or ConfigMap", t.ref)
		}
		m := t.obj.U.DeepCopy().Object
		for _, f := range stripFields {
			unstructured.RemoveNestedField(m, f...)
		}
		for _, a := range strippedAnnotations {
			unstructured.RemoveNestedField(m, "metadata", "annotations", a)
		}
		if a, ok, _ := unstructured.NestedMap(m, "metadata", "annotations"); ok && len(a) == 0 {
			unstructured.RemoveNestedField(m, "metadata", "annotations")
		}
		docs = append(docs, m)
	}
	return yamlDocs(docs)
}

func (b *builder) base() ([]byte, error) {
	if b.cluster {
		return b.clusterBase()
	}
	var docs []any
	for i := range b.fix.Objects {
		o := &b.fix.Objects[i]
		switch {
		case o.U == nil:
			continue
		case isSecret(o.Ref):
			b.excluded = append(b.excluded, o.Ref)
			continue
		case owned(o):
			b.generated = append(b.generated, o.Ref)
			continue
		}
		m := o.U.DeepCopy().Object
		for _, f := range stripFields {
			unstructured.RemoveNestedField(m, f...)
		}
		docs = append(docs, m)
	}
	return yamlDocs(docs)
}

func Write(dir string, b *Bundle) error {
	entries, err := os.ReadDir(dir)
	exists := err == nil
	switch {
	case exists && len(entries) > 0:
		return fmt.Errorf("--out %s is not empty", filepath.ToSlash(dir))
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	parent := filepath.Dir(filepath.Clean(dir))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".kshield-remediation-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, name := range slices.Sorted(maps.Keys(b.Files)) {
		p := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b.Files[name], 0o644); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if exists {
		if err := os.Remove(dir); err != nil {
			return err
		}
	}
	return os.Rename(tmp, dir)
}
