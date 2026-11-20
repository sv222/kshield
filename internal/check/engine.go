package check

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/model"
)

const (
	flagDebug     = "--debug"
	flagAllowHTTP = "--allow-http"

	ollamaDebugEnv   = "OLLAMA_DEBUG"
	ollamaOriginsEnv = "OLLAMA_ORIGINS"

	uncertainSuffix = " (the container runs several commands and the scanner cannot tell which one starts the engine)"
	customSuffix    = " (the engine is a guess: the workload is opted in with " + model.OptInKey + " and the image is not a known engine)"
)

var genericEngines = []model.Stack{
	model.Ollama, model.Triton, model.TGI, model.TEI, model.LocalAI,
	model.SGLang, model.LlamaCpp, model.LMDeploy, model.TRTLLM, model.Custom,
}

func isGenericEngine(s model.Stack) bool {
	return slices.Contains(genericEngines, s)
}

func isEngineContainer(c model.Container) bool {
	return !c.Init && (c.Stack == model.VLLM || isGenericEngine(c.Stack))
}

func engineName(s model.Stack) string {
	if s == model.Custom {
		return "inference engine"
	}
	return string(s)
}

func engineFinding(w model.Workload, c model.Container, certain bool, path, msg string) Finding {
	f := violation(w, c.Spec.Name, path, msg)
	switch {
	case c.Stack == model.Custom:
		f.Strength = Suspect
		f.Message += customSuffix
	case !certain:
		f.Strength = Suspect
		f.Message += uncertainSuffix
	}
	return f
}

func engineContainers(in *Input, visit func(w model.Workload, c model.Container) []Finding) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if !isEngineContainer(c) {
			return nil
		}
		return visit(w, c)
	})
}

func boolFlagOn(words []string, flag string) bool {
	for _, word := range words {
		name, value, inline := strings.Cut(word, "=")
		if NormalizeFlag(name) == flag && (!inline || boolOrTrue(value)) {
			return true
		}
	}
	return false
}

func lastEnvIndex(env []corev1.EnvVar, name string) int {
	for i := len(env) - 1; i >= 0; i-- {
		if env[i].Name == name {
			return i
		}
	}
	return -1
}

func envPath(c model.Container, i int) string {
	return c.Path + "/" + fieldEnv + "/" + strconv.Itoa(i)
}

func originsWildcard(v string) bool {
	return slices.ContainsFunc(strings.Split(v, ","), func(o string) bool { return strings.TrimSpace(o) == "*" })
}

func aiDebugFlags(in *Input) Result {
	return engineContainers(in, func(w model.Workload, c model.Container) []Finding {
		words, certain := c.EngineWords()
		var out []Finding
		for _, flag := range []string{flagDebug, flagAllowHTTP} {
			if boolFlagOn(words, flag) {
				msg := fmt.Sprintf("%s runs with %s: it enables a debug or insecure endpoint", engineName(c.Stack), flag)
				out = append(out, engineFinding(w, c, certain, c.Path+"/"+flagField(c, flag), msg))
			}
		}
		if i := lastEnvIndex(c.Spec.Env, ollamaDebugEnv); i >= 0 {
			if e := c.Spec.Env[i]; e.ValueFrom == nil && envTruthy(e.Value) {
				out = append(out, engineFinding(w, c, true, envPath(c, i), fmt.Sprintf("env %s is %q: Ollama writes debug logs", ollamaDebugEnv, e.Value)))
			}
		}
		if i := lastEnvIndex(c.Spec.Env, ollamaOriginsEnv); i >= 0 {
			if e := c.Spec.Env[i]; e.ValueFrom == nil && originsWildcard(e.Value) {
				out = append(out, engineFinding(w, c, true, envPath(c, i), fmt.Sprintf("env %s is %q: any web page in a visitor's browser can call the engine", ollamaOriginsEnv, e.Value)))
			}
		}
		return out
	})
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1":
		return true
	}
	return false
}

const GatewayAuthKey = "kshield.io/gateway-auth"

const gatewayAuthValue = "true"

const declaredSuffix = "; gateway authentication is declared by " + GatewayAuthKey + ": \"" + gatewayAuthValue + "\", the scanner cannot verify it"

var authFlags = []string{"--api-key", "--api-keys"}

var engineAuthEnv = map[model.Stack][]string{
	model.TEI:      {"API_KEY"},
	model.LlamaCpp: {"LLAMA_API_KEY"},
	model.LocalAI:  {"LOCALAI_API_KEY", "API_KEY"},
}

var customEngineAuthEnv = []string{"API_KEY", "VLLM_API_KEY", "LLAMA_API_KEY", "LOCALAI_API_KEY"}

func authEnvNames(s model.Stack) []string {
	if s == model.Custom {
		return customEngineAuthEnv
	}
	return engineAuthEnv[s]
}

func gatewayAuth(w model.Workload) bool {
	maps := []map[string]string{w.Labels, w.Annotations}
	if w.Object != nil && w.Object.U != nil {
		maps = append(maps, w.Object.U.GetLabels(), w.Object.U.GetAnnotations())
	}
	return slices.ContainsFunc(maps, func(m map[string]string) bool { return m[GatewayAuthKey] == gatewayAuthValue })
}

func declaredFinding(w model.Workload, c model.Container, path, what string) Finding {
	f := violation(w, c.Spec.Name, path, what+declaredSuffix)
	f.Strength = Declared
	return f
}

func valueFlagSet(words []string, flag string) bool {
	for i, word := range words {
		name, value, inline := strings.Cut(word, "=")
		if NormalizeFlag(name) != flag {
			continue
		}
		if inline && value != "" {
			return true
		}
		if !inline && i+1 < len(words) && !strings.HasPrefix(words[i+1], shortFlagPrefix) {
			return true
		}
	}
	return false
}

func engineKeyState(in *Input, w model.Workload, c model.Container, words []string) (keyState, []string) {
	for _, flag := range authFlags {
		if valueFlagSet(words, flag) {
			return keySet, nil
		}
	}
	var missing []string
	for _, name := range authEnvNames(c.Stack) {
		if e, explicit := lastEnv(c.Spec.Env, name); explicit {
			if e.ValueFrom != nil || e.Value != "" {
				return keySet, nil
			}
			continue
		}
		found, refs := EnvFromKey(in, w.Owner.Namespace, c, name)
		if found {
			return keySet, nil
		}
		for _, r := range refs {
			if !slices.Contains(missing, r) {
				missing = append(missing, r)
			}
		}
	}
	if len(missing) > 0 {
		return keyUnknown, missing
	}
	return keyMissing, nil
}

func authEvidenceText(s model.Stack) string {
	if names := authEnvNames(s); len(names) > 0 {
		return "no " + flagAPIKey + " flag and none of the env vars " + strings.Join(names, ", ") + " is set"
	}
	return "no " + flagAPIKey + " flag and no auth env var"
}

func aiEngineAuth(in *Input) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if c.Init || !isGenericEngine(c.Stack) {
			return nil
		}
		words, certain := c.EngineWords()
		state, missing := engineKeyState(in, w, c, words)
		path := c.Path + "/" + fieldArgs
		name := engineName(c.Stack)
		var f Finding
		switch state {
		case keySet:
			return nil
		case keyUnknown:
			msg := fmt.Sprintf("%s API key may come from envFrom %s, not in the input: the scanner cannot see if the key is set", name, strings.Join(missing, ", "))
			if gatewayAuth(w) {
				return []Finding{declaredFinding(w, c, path, msg)}
			}
			f = engineFinding(w, c, certain, path, msg)
			f.Strength = Suspect
			return []Finding{f}
		}
		msg := fmt.Sprintf("%s container %s has no authentication evidence: %s", name, c.Spec.Name, authEvidenceText(c.Stack))
		if gatewayAuth(w) {
			return []Finding{declaredFinding(w, c, path, msg)}
		}
		return []Finding{engineFinding(w, c, certain, path, msg)}
	})
}

var unsafeModelExts = []string{".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".h5", ".keras"}

var objectStoragePrefixes = []string{"s3://", "gs://"}

type modelValue struct {
	kind, raw, value, path string
}

func argValue(word string) string {
	if strings.HasPrefix(word, shortFlagPrefix) {
		_, value, _ := strings.Cut(word, "=")
		return value
	}
	return word
}

func wordField(c model.Container, word string) string {
	holds := func(items []string) bool {
		return slices.ContainsFunc(items, func(s string) bool { return strings.Contains(s, word) })
	}
	if !holds(c.Spec.Args) && holds(c.Spec.Command) {
		return fieldCommand
	}
	return fieldArgs
}

func modelValues(c model.Container, words []string) []modelValue {
	var out []modelValue
	for _, word := range words {
		if v := argValue(word); v != "" {
			out = append(out, modelValue{kind: "arg", raw: word, value: v, path: c.Path + "/" + wordField(c, word)})
		}
	}
	for i, e := range c.Spec.Env {
		if e.ValueFrom == nil && e.Value != "" {
			out = append(out, modelValue{kind: "env " + e.Name, raw: e.Value, value: e.Value, path: envPath(c, i)})
		}
	}
	return out
}

func unsafeModelExt(v string) string {
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	v = strings.ToLower(v)
	for _, ext := range unsafeModelExts {
		if strings.HasSuffix(v, ext) {
			return ext
		}
	}
	return ""
}

func isObjectStorage(v string) bool {
	v = strings.ToLower(v)
	return slices.ContainsFunc(objectStoragePrefixes, func(p string) bool { return strings.HasPrefix(v, p) })
}

func aiModelSource(in *Input) Result {
	return engineContainers(in, func(w model.Workload, c model.Container) []Finding {
		words, certain := c.EngineWords()
		name := engineName(c.Stack)
		pickleScope := c.Stack != model.VLLM
		var out []Finding
		if pickleScope && boolFlagOn(words, flagTrust) {
			msg := fmt.Sprintf("%s runs with %s: it executes code from the model repository", name, flagTrust)
			out = append(out, engineFinding(w, c, certain, c.Path+"/"+flagField(c, flagTrust), msg))
		}
		for _, v := range modelValues(c, words) {
			if ext := unsafeModelExt(v.value); pickleScope && ext != "" {
				msg := fmt.Sprintf("%s %q references a %s model file: this format can run code when it is loaded (use .safetensors)", v.kind, v.raw, ext)
				out = append(out, engineFinding(w, c, certain, v.path, msg))
				continue
			}
			if isObjectStorage(v.value) {
				msg := fmt.Sprintf("%s %q loads the model from object storage that the scanner cannot verify (pin the source: a digest-verified registry or signed artifacts)", v.kind, v.raw)
				f := engineFinding(w, c, certain, v.path, msg)
				f.Strength = Suspect
				out = append(out, f)
			}
		}
		return out
	})
}

func engineAuthReason(in *Input, w model.Workload, c model.Container) (reason string, unsure, final bool) {
	words, certain := c.EngineWords()
	state, missing := engineKeyState(in, w, c, words)
	name := engineName(c.Stack)
	switch state {
	case keySet:
		return "", false, false
	case keyUnknown:
		return fmt.Sprintf("%s container %s may take its API key from envFrom %s, not in the input", name, c.Spec.Name, strings.Join(missing, ", ")), true, false
	}
	reason = fmt.Sprintf("%s container %s has no authentication evidence: %s", name, c.Spec.Name, authEvidenceText(c.Stack))
	if certain && c.Stack != model.Custom {
		return reason, false, true
	}
	return reason, true, false
}
