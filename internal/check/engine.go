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
