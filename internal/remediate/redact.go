package remediate

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
	"github.com/sv222/kshield/internal/report"
)

const (
	secretEnvCheck   = "KS-WL-011"
	envSuffix        = "-kshield-env"
	movedAPIKeyEnv   = "KSHIELD_VLLM_API_KEY"
	minLiteralLength = 8
	tokenBefore      = " \t\n'\"="
	tokenAfter       = " \t\n'\";&|)"
)

type movedValue struct {
	owner  load.ObjectRef
	secret string
	key    string
	source string
}

func (b *builder) redactInput() error {
	objs := make([]load.Object, len(b.in.Objects))
	for i, o := range b.in.Objects {
		objs[i] = o
		if o.U != nil {
			objs[i].U = o.U.DeepCopy()
		}
	}
	for i := range objs {
		o := &objs[i]
		if o.U == nil || isSecret(o.Ref) || owned(o) {
			continue
		}
		if err := b.redact(o, o.U.Object); err != nil {
			return err
		}
	}
	workloads, err := model.Extract(objs)
	if err != nil {
		return err
	}
	b.fix = &check.Input{Objects: objs, Workloads: workloads}
	b.objects = map[load.ObjectRef]*load.Object{}
	for i := range objs {
		if _, ok := b.objects[objs[i].Ref]; !ok {
			b.objects[objs[i].Ref] = &objs[i]
		}
	}
	return nil
}

func (b *builder) redact(o *load.Object, m map[string]any) error {
	for _, it := range b.items {
		f := it.finding
		if it.checkID != secretEnvCheck || f.Object != o.Ref {
			continue
		}
		dir, last := path.Split(f.Path)
		var moved []movedValue
		var err error
		if last == "value" && path.Base(path.Dir(path.Clean(dir))) == "env" {
			moved, err = b.moveEnv(o, m, f, strings.TrimSuffix(dir, "/"))
		} else {
			moved, err = b.moveAPIKey(o, m, f, path.Dir(f.Path))
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", o.Ref, f.Path, err)
		}
		var keys []string
		for _, mv := range moved {
			keys = append(keys, fmt.Sprintf("Secret %s key %s", mv.secret, mv.key))
		}
		it.reason = "the literal value is not in this bundle: base/manifests.yaml reads it from " + strings.Join(keys, ", ") + "; create the Secret first (MANUAL.md, Before you apply) and rotate the value"
		b.moved = append(b.moved, moved...)
	}
	return nil
}

func secretKey(f report.Finding, name string) string {
	parts := []string{f.Container, name}
	if f.Group != "" {
		parts = slices.Insert(parts, 0, f.Group)
	}
	return strings.Join(parts, ".")
}

func envSecretName(in *check.Input, owner load.ObjectRef) string {
	return ownerSecretName(in, owner, envSuffix)
}

func secretKeyRef(name, key string) map[string]any {
	return map[string]any{"secretKeyRef": map[string]any{"name": name, "key": key}}
}

func (b *builder) addLiteral(v string) {
	if len(v) >= minLiteralLength && !slices.Contains(b.literals, v) {
		b.literals = append(b.literals, v)
	}
}

func (b *builder) moveEnv(o *load.Object, m map[string]any, f report.Finding, itemPath string) ([]movedValue, error) {
	env, ok := lookupPath(m, itemPath).(map[string]any)
	if !ok {
		return nil, errors.New("the env item is not in the object")
	}
	name, _ := env["name"].(string)
	value, _ := env["value"].(string)
	b.addLiteral(value)
	mv := movedValue{owner: o.Ref, secret: envSecretName(b.in, o.Ref), key: secretKey(f, name), source: fmt.Sprintf("value of env %s in container %s", name, f.Container)}
	delete(env, "value")
	env["valueFrom"] = secretKeyRef(mv.secret, mv.key)
	return []movedValue{mv}, nil
}

func (b *builder) moveAPIKey(o *load.Object, m map[string]any, f report.Finding, containerPath string) ([]movedValue, error) {
	var c *model.Container
	w := findWorkload(b.in, f, o)
	for i := range w.Containers {
		if w.Containers[i].Path == containerPath {
			c = &w.Containers[i]
		}
	}
	cm, ok := lookupPath(m, containerPath).(map[string]any)
	if c == nil || !ok {
		return nil, errors.New("the container is not in the object")
	}
	values := apiKeyLiterals(*c)
	if len(values) == 0 {
		return nil, errors.New("the literal --api-key value could not be found; move it to a Secret by hand")
	}
	for _, v := range values {
		b.addLiteral(v)
	}
	ref := "$(" + movedAPIKeyEnv + ")"
	for _, field := range []string{fieldCommand, fieldArgs} {
		list, _ := cm[field].([]any)
		for i, x := range list {
			s, _ := x.(string)
			for _, v := range values {
				s = replaceToken(s, v, ref)
			}
			list[i] = s
			for _, v := range values {
				if strings.Contains(s, v) {
					return nil, errors.New("the literal --api-key value could not be replaced; move it to a Secret by hand")
				}
			}
		}
	}
	mv := movedValue{owner: o.Ref, secret: envSecretName(b.in, o.Ref), key: secretKey(f, movedAPIKeyEnv), source: "--api-key value of container " + f.Container}
	env, _ := cm["env"].([]any)
	if !slices.ContainsFunc(env, func(e any) bool {
		em, _ := e.(map[string]any)
		return em["name"] == movedAPIKeyEnv
	}) {
		cm["env"] = append(env, map[string]any{"name": movedAPIKeyEnv, "valueFrom": secretKeyRef(mv.secret, mv.key)})
	}
	return []movedValue{mv}, nil
}

func apiKeyLiterals(c model.Container) []string {
	var out []string
	for _, cmd := range c.Commands {
		words := cmd.Words
		for i := 0; i < len(words); i++ {
			name, value, inline := strings.Cut(words[i], "=")
			if !strings.HasPrefix(name, "--") || check.NormalizeFlag(name) != flagAPIKey {
				continue
			}
			if !inline {
				if i+1 >= len(words) || strings.HasPrefix(words[i+1], "--") {
					continue
				}
				i++
				value = words[i]
			}
			if value != "" && !strings.Contains(value, "$") && !slices.Contains(out, value) {
				out = append(out, value)
			}
		}
	}
	return out
}

func replaceToken(s, value, repl string) string {
	var out strings.Builder
	for {
		i := strings.Index(s, value)
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		j := i + len(value)
		before := i == 0 || strings.ContainsRune(tokenBefore, rune(s[i-1]))
		after := j == len(s) || strings.ContainsRune(tokenAfter, rune(s[j]))
		out.WriteString(s[:i])
		if before && after {
			out.WriteString(repl)
		} else {
			out.WriteString(value)
		}
		s = s[j:]
	}
}
