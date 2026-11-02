package crdschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/yaml"
)

var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

func Validate(crdYAML []byte, obj map[string]any) ([]string, error) {
	crd, err := parseCRD(crdYAML)
	if err != nil {
		return nil, err
	}
	spec, _ := crd["spec"].(map[string]any)
	apiVersion, _ := obj["apiVersion"].(string)
	group, version, ok := strings.Cut(apiVersion, "/")
	if !ok {
		group, version = "", apiVersion
	}
	crdGroup, _ := spec["group"].(string)
	if group != crdGroup {
		return nil, fmt.Errorf("crdschema: apiVersion %q does not match CRD group %q", apiVersion, crdGroup)
	}
	schema := versionSchema(spec, version)
	if schema == nil {
		return nil, fmt.Errorf("crdschema: CRD %s has no schema for version %q", crdGroup, version)
	}
	val, err := normalize(obj)
	if err != nil {
		return nil, err
	}
	v := &validator{strict: true}
	names, _ := spec["names"].(map[string]any)
	if want, _ := names["kind"].(string); want != "" {
		if got, _ := obj["kind"].(string); got != want {
			v.add("/kind", "kind: want %s, got %q", want, got)
		}
	}
	v.walk("", schema, val, true)
	sort.Strings(v.problems)
	return v.problems, nil
}

func parseCRD(b []byte) (map[string]any, error) {
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(b), 4096)
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil, errors.New("crdschema: no CustomResourceDefinition document")
		}
		if err != nil {
			return nil, fmt.Errorf("crdschema: parse CRD: %w", err)
		}
		if kind, _ := doc["kind"].(string); kind == "CustomResourceDefinition" {
			return doc, nil
		}
	}
}

func versionSchema(spec map[string]any, version string) map[string]any {
	versions, _ := spec["versions"].([]any)
	for _, item := range versions {
		ver, _ := item.(map[string]any)
		if name, _ := ver["name"].(string); name != version {
			continue
		}
		schema, _ := ver["schema"].(map[string]any)
		openAPI, _ := schema["openAPIV3Schema"].(map[string]any)
		return openAPI
	}
	return nil
}

func normalize(obj map[string]any) (any, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("crdschema: encode object: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("crdschema: decode object: %w", err)
	}
	return out, nil
}

type validator struct {
	strict   bool
	problems []string
}

func (v *validator) add(ptr, format string, args ...any) {
	v.problems = append(v.problems, ptr+": "+fmt.Sprintf(format, args...))
}

func branchProblems(ptr string, b any, val any) []string {
	s, _ := b.(map[string]any)
	sub := &validator{}
	sub.walk(ptr, s, val, false)
	return sub.problems
}

func (v *validator) walk(ptr string, s map[string]any, val any, root bool) {
	intOrString := s["x-kubernetes-int-or-string"] == true
	typ, _ := s["type"].(string)
	if val == nil {
		if (typ != "" || intOrString) && s["nullable"] != true {
			v.add(ptr, "type: want %s, got null", wantType(typ, intOrString))
		}
		return
	}
	switch {
	case intOrString:
		if _, isString := val.(string); !isString && !isInteger(val) {
			v.add(ptr, "type: want %s, got %s", wantType(typ, intOrString), typeOf(val))
			return
		}
	case typ != "":
		if !matchesType(typ, val) {
			v.add(ptr, "type: want %s, got %s", typ, typeOf(val))
			return
		}
	}
	if enum, ok := s["enum"].([]any); ok && !inEnum(enum, val) {
		v.add(ptr, "enum: %s is not one of [%s]", encode(val), strings.Join(encodeAll(enum), ", "))
	}
	v.bounds(ptr, s, val)
	v.combinators(ptr, s, val)
	switch x := val.(type) {
	case map[string]any:
		v.object(ptr, s, x, root)
	case []any:
		items, _ := s["items"].(map[string]any)
		if items == nil {
			return
		}
		for i, e := range x {
			v.walk(ptr+"/"+strconv.Itoa(i), items, e, false)
		}
	}
}

func (v *validator) bounds(ptr string, s map[string]any, val any) {
	switch x := val.(type) {
	case []any:
		if n, ok := number(s["minItems"]); ok && float64(len(x)) < n {
			v.add(ptr, "minItems: %d items, want at least %s", len(x), encode(s["minItems"]))
		}
		if n, ok := number(s["maxItems"]); ok && float64(len(x)) > n {
			v.add(ptr, "maxItems: %d items, want at most %s", len(x), encode(s["maxItems"]))
		}
	case string:
		l := utf8.RuneCountInString(x)
		if n, ok := number(s["minLength"]); ok && float64(l) < n {
			v.add(ptr, "minLength: length %d, want at least %s", l, encode(s["minLength"]))
		}
		if n, ok := number(s["maxLength"]); ok && float64(l) > n {
			v.add(ptr, "maxLength: length %d, want at most %s", l, encode(s["maxLength"]))
		}
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return
		}
		if n, ok := number(s["minimum"]); ok {
			if f < n || (s["exclusiveMinimum"] == true && f == n) {
				v.add(ptr, "minimum: %s is below %s", x, encode(s["minimum"]))
			}
		}
		if n, ok := number(s["maximum"]); ok {
			if f > n || (s["exclusiveMaximum"] == true && f == n) {
				v.add(ptr, "maximum: %s is above %s", x, encode(s["maximum"]))
			}
		}
	}
}

func (v *validator) combinators(ptr string, s map[string]any, val any) {
	allOf, _ := s["allOf"].([]any)
	for _, b := range allOf {
		v.problems = append(v.problems, branchProblems(ptr, b, val)...)
	}
	if anyOf, ok := s["anyOf"].([]any); ok && len(anyOf) > 0 {
		var failed []string
		for _, b := range anyOf {
			ps := branchProblems(ptr, b, val)
			if len(ps) == 0 {
				failed = nil
				break
			}
			failed = append(failed, ps...)
		}
		if failed != nil {
			v.add(ptr, "anyOf: matches none of %d schemas (%s)", len(anyOf), strings.Join(failed, "; "))
		}
	}
	if oneOf, ok := s["oneOf"].([]any); ok && len(oneOf) > 0 {
		var failed []string
		matched := 0
		for _, b := range oneOf {
			ps := branchProblems(ptr, b, val)
			if len(ps) == 0 {
				matched++
			}
			failed = append(failed, ps...)
		}
		switch matched {
		case 1:
		case 0:
			v.add(ptr, "oneOf: matches none of %d schemas, want exactly 1 (%s)", len(oneOf), strings.Join(failed, "; "))
		default:
			v.add(ptr, "oneOf: matches %d of %d schemas, want exactly 1", matched, len(oneOf))
		}
	}
	if not, ok := s["not"]; ok && len(branchProblems(ptr, not, val)) == 0 {
		v.add(ptr, "not: matches a forbidden schema")
	}
}

func (v *validator) object(ptr string, s map[string]any, m map[string]any, root bool) {
	required, _ := s["required"].([]any)
	for _, r := range required {
		name, _ := r.(string)
		if _, ok := m[name]; !ok {
			v.add(ptr+"/"+pointerEscaper.Replace(name), "required: field is missing")
		}
	}
	props, _ := s["properties"].(map[string]any)
	preserve := s["x-kubernetes-preserve-unknown-fields"] == true
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if root && (k == "apiVersion" || k == "kind" || k == "metadata") {
			continue
		}
		child := ptr + "/" + pointerEscaper.Replace(k)
		if ps, ok := props[k].(map[string]any); ok {
			v.walk(child, ps, m[k], false)
			continue
		}
		switch a := s["additionalProperties"].(type) {
		case map[string]any:
			v.walk(child, a, m[k], false)
			continue
		case bool:
			if a {
				continue
			}
		}
		if v.strict && !preserve {
			v.add(child, "unknown field")
		}
	}
}

func number(val any) (float64, bool) {
	switch x := val.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func wantType(typ string, intOrString bool) string {
	if intOrString {
		return "integer or string"
	}
	return typ
}

func matchesType(typ string, val any) bool {
	switch typ {
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "string":
		_, ok := val.(string)
		return ok
	case "integer":
		return isInteger(val)
	case "number":
		_, ok := val.(json.Number)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	}
	return true
}

func isInteger(val any) bool {
	n, ok := val.(json.Number)
	if !ok {
		return false
	}
	if _, err := n.Int64(); err == nil {
		return true
	}
	f, err := n.Float64()
	return err == nil && f == float64(int64(f))
}

func typeOf(val any) string {
	switch val.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		if isInteger(val) {
			return "integer"
		}
		return "number"
	}
	return fmt.Sprintf("%T", val)
}

func inEnum(enum []any, val any) bool {
	want := encode(val)
	for _, e := range enum {
		if encode(e) == want {
			return true
		}
	}
	return false
}

func encode(val any) string {
	b, err := json.Marshal(val)
	if err != nil {
		return fmt.Sprint(val)
	}
	return string(b)
}

func encodeAll(vals []any) []string {
	out := make([]string, len(vals))
	for i, val := range vals {
		out[i] = encode(val)
	}
	return out
}
