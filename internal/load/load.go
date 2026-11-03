package load

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	stdinPath    = "-"
	peekSize     = 4096
	docSeparator = "---"
)

type ObjectRef struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
}

func (r ObjectRef) String() string {
	if r.Namespace == "" {
		return r.Kind + "/" + r.Name
	}
	return r.Kind + "/" + r.Namespace + "/" + r.Name
}

type Source struct {
	File string
	Doc  int
	Line int
}

type Digest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Object struct {
	Ref    ObjectRef
	Source Source
	U      *unstructured.Unstructured
}

type Options struct {
	DefaultNamespace string
	Stdin            io.Reader
	Digests          *[]Digest
}

func Read(paths []string, opt Options) ([]Object, error) {
	var out []Object
	for _, p := range paths {
		objs, err := readPath(p, opt)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	return out, nil
}

func readPath(p string, opt Options) ([]Object, error) {
	if p == stdinPath {
		if opt.Stdin == nil {
			return nil, fmt.Errorf("%s: no stdin reader", stdinPath)
		}
		data, err := io.ReadAll(opt.Stdin)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", stdinPath, err)
		}
		record(opt, stdinPath, data)
		return parse(data, stdinPath, opt)
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		name := filepath.ToSlash(filepath.Clean(p))
		if name == stdinPath {
			name = "./" + stdinPath
		}
		return readFile(name, opt)
	}
	names, err := manifestFiles(p)
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, name := range names {
		objs, err := readFile(name, opt)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	return out, nil
}

func manifestFiles(root string) ([]string, error) {
	var names []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml", ".json":
			names = append(names, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

func readFile(name string, opt Options) ([]Object, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	record(opt, name, data)
	return parse(data, name, opt)
}

func record(opt Options, path string, data []byte) {
	if opt.Digests == nil {
		return
	}
	sum := sha256.Sum256(data)
	*opt.Digests = append(*opt.Digests, Digest{Path: path, SHA256: hex.EncodeToString(sum[:])})
}

func parse(data []byte, file string, opt Options) ([]Object, error) {
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(keepEmptyDocuments(data)), peekSize)
	starts := docLines(data)
	var out []Object
	for doc := 0; ; doc++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("%s#%d: %w", file, doc, err)
		}
		m, err := toMap(raw)
		if err != nil {
			return nil, fmt.Errorf("%s#%d: %w", file, doc, err)
		}
		if m == nil {
			continue
		}
		objs, err := expand(m, Source{File: file, Doc: doc, Line: lineOf(starts, doc)}, opt)
		if err != nil {
			return nil, fmt.Errorf("%s#%d: %w", file, doc, err)
		}
		out = append(out, objs...)
	}
}

func keepEmptyDocuments(data []byte) []byte {
	if yaml.IsJSONBuffer(data) {
		return data
	}
	var out bytes.Buffer
	out.Grow(len(data))
	prevSeparator := false
	for rest := data; len(rest) > 0; {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line = rest[:i+1]
		}
		rest = rest[len(line):]
		isSeparator := bytes.HasPrefix(line, []byte(docSeparator))
		if isSeparator && prevSeparator {
			out.WriteByte('\n')
		}
		out.Write(line)
		prevSeparator = isSeparator
	}
	return out.Bytes()
}

func lineOf(starts []int, doc int) int {
	if doc < len(starts) {
		return starts[doc]
	}
	return 0
}

func docLines(data []byte) []int {
	if !yaml.IsJSONBuffer(data[:min(len(data), peekSize)]) {
		return yamlDocLines(data, 0, !yaml.IsJSONBuffer(data))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var starts []int
	end := 0
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) || len(starts) > 1 {
				return starts
			}
			return append(starts, yamlDocLines(data, skipToNewline(data, end), false)...)
		}
		start := len(data) - len(bytes.TrimLeft(data[end:], " \t\r\n"))
		starts = append(starts, lineAt(data, start))
		end = int(dec.InputOffset())
	}
}

func skipToNewline(data []byte, from int) int {
	for from < len(data) {
		r, size := utf8.DecodeRune(data[from:])
		if !unicode.IsSpace(r) {
			return from
		}
		from += size
		if r == '\n' {
			return from
		}
	}
	return from
}

func yamlDocLines(data []byte, from int, keepEmpty bool) []int {
	var starts []int
	line := lineAt(data, from)
	open, prevSeparator := false, false
	begin := func(at int) {
		if !open {
			starts = append(starts, at)
			open = true
		}
	}
	for rest := data[from:]; len(rest) > 0; line++ {
		l := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			l = rest[:i+1]
		}
		rest = rest[len(l):]
		isSeparator := bytes.HasPrefix(l, []byte(docSeparator))
		if isSeparator && prevSeparator && keepEmpty {
			begin(line)
		}
		switch {
		case isSeparator && open:
			open = false
		case isSeparator:
			begin(line + 1)
		default:
			begin(line)
		}
		prevSeparator = isSeparator
	}
	return starts
}

func lineAt(data []byte, offset int) int {
	return bytes.Count(data[:offset], []byte("\n")) + 1
}

func toMap(raw json.RawMessage) (map[string]interface{}, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '{' {
		return nil, errors.New("document is not an object")
	}
	var m map[string]interface{}
	if err := utiljson.Unmarshal(trimmed, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func expand(m map[string]interface{}, src Source, opt Options) ([]Object, error) {
	kind, _ := m["kind"].(string)
	if items, ok := m["items"].([]interface{}); ok && strings.HasSuffix(kind, "List") {
		var out []Object
		for i, item := range items {
			im, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("items[%d]: not an object", i)
			}
			objs, err := expand(im, src, opt)
			if err != nil {
				return nil, fmt.Errorf("items[%d]: %w", i, err)
			}
			out = append(out, objs...)
		}
		return out, nil
	}
	obj, err := build(m, src, opt)
	if err != nil {
		return nil, err
	}
	return []Object{obj}, nil
}

func build(m map[string]interface{}, src Source, opt Options) (Object, error) {
	apiVersion, err := requiredString(m, "apiVersion")
	if err != nil {
		return Object{}, err
	}
	kind, err := requiredString(m, "kind")
	if err != nil {
		return Object{}, err
	}
	name, err := requiredString(m, "metadata", "name")
	if err != nil {
		return Object{}, err
	}
	namespace, _, err := unstructured.NestedString(m, "metadata", "namespace")
	if err != nil {
		return Object{}, errors.New("invalid metadata.namespace")
	}
	u := &unstructured.Unstructured{Object: m}
	if namespace == "" && opt.DefaultNamespace != "" && !IsClusterScoped(kind) {
		namespace = opt.DefaultNamespace
		u.SetNamespace(namespace)
	}
	return Object{
		Ref:    ObjectRef{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name},
		Source: src,
		U:      u,
	}, nil
}

func requiredString(m map[string]interface{}, path ...string) (string, error) {
	field := strings.Join(path, ".")
	v, found, err := unstructured.NestedString(m, path...)
	if err != nil {
		return "", fmt.Errorf("invalid %s", field)
	}
	if !found || v == "" {
		return "", fmt.Errorf("missing %s", field)
	}
	return v, nil
}
