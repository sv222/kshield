package check

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/model"
)

const (
	vllmProgram      = "vllm"
	vllmServe        = "serve"
	pythonModuleFlag = "-m"
	vllmModulePrefix = "vllm.entrypoints"
	dynamicMarker    = "$"
	flagPrefix       = "--"
	shortFlagPrefix  = "-"

	flagModel      = "--model"
	flagLoadFormat = "--load-format"
	flagAPIKey     = "--api-key"
	flagConfig     = "--config"
	flagTrust      = "--trust-remote-code"
	flagNoTrust    = "--no-trust-remote-code"

	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/envs.py@v0.31.0
	vllmAPIKeyEnv = "VLLM_API_KEY"

	fieldArgs    = "args"
	fieldCommand = "command"
)

var flagToken = regexp.MustCompile(`(?:^|[\s'"])(--[^\s='".]*)`)

type VLLMArgs struct {
	Found             bool
	Model             string
	LoadFormat        string
	LoadFormatSet     bool
	LoadFormatDynamic bool
	TrustRemoteCode   bool
	APIKey            bool
	APIKeyLiteral     bool
	ConfigFile        bool
	Opaque            bool
}

func ParseVLLM(c model.Container) VLLMArgs {
	args, positional, found, opaque := vllmInvocation(c)
	if !found {
		return VLLMArgs{}
	}
	a := VLLMArgs{Found: true, Opaque: opaque}
	parseVLLMFlags(&a, args, positional)
	if hasAPIKeyEnv(c.Spec.Env) {
		a.APIKey = true
	}
	return a
}

func vllmInvocation(c model.Container) (args []string, positional, found, opaque bool) {
	for _, cmd := range c.Commands {
		if rest, pos, ok := matchVLLMCommand(cmd.Words); ok {
			return rest, pos, true, false
		}
	}
	if c.Stack != model.VLLM {
		return nil, false, false, false
	}
	if words, ok := entrypointArgs(c); ok {
		if len(words) > 0 && words[0] == vllmServe {
			words = words[1:]
		}
		return words, true, true, false
	}
	if opaqueCommand(c) {
		return c.Commands[0].Words[1:], false, true, true
	}
	return nil, false, true, false
}

func opaqueCommand(c model.Container) bool {
	if len(c.Spec.Command) == 0 || len(c.Commands) != 1 || len(c.Commands[0].Words) == 0 {
		return false
	}
	words := c.Commands[0].Words
	if model.IsShellScript(slices.Concat(c.Spec.Command, c.Spec.Args)) || path.Base(words[0]) == vllmProgram {
		return false
	}
	for i := 0; i+1 < len(words); i++ {
		if words[i] == pythonModuleFlag && strings.HasPrefix(words[i+1], vllmProgram) {
			return false
		}
	}
	return true
}

func matchVLLMCommand(words []string) (args []string, positional, ok bool) {
	if len(words) >= 2 && path.Base(words[0]) == vllmProgram && words[1] == vllmServe {
		return words[2:], true, true
	}
	for i := 0; i+1 < len(words); i++ {
		if words[i] == pythonModuleFlag && strings.HasPrefix(words[i+1], vllmModulePrefix) {
			return words[i+2:], false, true
		}
	}
	return nil, false, false
}

func entrypointArgs(c model.Container) ([]string, bool) {
	if len(c.Spec.Command) != 0 || len(c.Commands) != 1 || len(c.Commands[0].Words) != len(c.Spec.Args) {
		return nil, false
	}
	return c.Commands[0].Words, true
}

func parseVLLMFlags(a *VLLMArgs, args []string, positional bool) {
	if positional && len(args) > 0 && !strings.HasPrefix(args[0], shortFlagPrefix) {
		a.Model = args[0]
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		if !strings.HasPrefix(name, flagPrefix) {
			continue
		}
		name = NormalizeFlag(name)
		switch name {
		case flagTrust:
			a.TrustRemoteCode = !inline || boolOrTrue(value)
		case flagNoTrust:
			a.TrustRemoteCode = false
		case flagModel, flagLoadFormat, flagAPIKey, flagConfig:
			if !inline {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], flagPrefix) {
					continue
				}
				i++
				value = args[i]
			}
			applyValueFlag(a, name, value)
		}
	}
}

// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/utils/argparse_utils.py@v0.31.0
func NormalizeFlag(arg string) string {
	if !strings.HasPrefix(arg, flagPrefix) {
		return arg
	}
	rest := arg[len(flagPrefix):]
	head, tail := rest, ""
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		head, tail = rest[:i], rest[i:]
	}
	return flagPrefix + strings.ReplaceAll(head, "_", "-") + tail
}

func flagField(c model.Container, flag string) string {
	switch {
	case holdsFlag(c.Spec.Args, flag):
		return fieldArgs
	case holdsFlag(c.Spec.Command, flag):
		return fieldCommand
	}
	return fieldArgs
}

func holdsFlag(items []string, flag string) bool {
	for _, s := range items {
		for _, m := range flagToken.FindAllStringSubmatch(s, -1) {
			if NormalizeFlag(m[1]) == flag {
				return true
			}
		}
	}
	return false
}

func applyValueFlag(a *VLLMArgs, name, value string) {
	dynamic := strings.Contains(value, dynamicMarker)
	switch name {
	case flagModel:
		a.Model = value
	case flagLoadFormat:
		a.LoadFormat, a.LoadFormatSet, a.LoadFormatDynamic = value, true, dynamic
	case flagAPIKey:
		a.APIKey = value != ""
		a.APIKeyLiteral = value != "" && !dynamic
	case flagConfig:
		a.ConfigFile = a.ConfigFile || value != ""
	}
}

func boolOrTrue(value string) bool {
	b, err := strconv.ParseBool(value)
	return err != nil || b
}

func hasAPIKeyEnv(env []corev1.EnvVar) bool {
	set := false
	for _, e := range env {
		if e.Name == vllmAPIKeyEnv {
			set = e.ValueFrom != nil || e.Value != ""
		}
	}
	return set
}
