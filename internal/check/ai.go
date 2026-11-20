package check

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/model"
)

var (
	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/__init__.py@v0.31.0
	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/default_loader.py@v0.31.0
	PickleFormats = []string{"pt", "npcache"}
	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/__init__.py@v0.31.0
	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/default_loader.py@v0.31.0
	safeFormats = []string{"safetensors", "fastsafetensors", "instanttensor", "mistral"}
	// source: https://github.com/vllm-project/vllm/blob/v0.31.0/vllm/model_executor/model_loader/default_loader.py@v0.31.0
	AutoFormats = []string{"auto", "hf"}

	pickleModelSuffixes = []string{".bin", ".pt", ".pth", ".pkl", ".ckpt"}
)

const opaqueCommandSuffix = " (the container command is a script that is not vllm serve, python -m vllm or a shell -c: the scanner cannot see every flag it passes)"

func vllmContainers(in *Input, visit func(w model.Workload, c model.Container, a VLLMArgs) []Finding) Result {
	return forContainers(in, func(w model.Workload, c model.Container) []Finding {
		if c.Init {
			return nil
		}
		a := ParseVLLM(c)
		if !a.Found {
			return nil
		}
		fs := visit(w, c, a)
		if a.Opaque {
			for i := range fs {
				fs[i] = suspect(fs[i])
				fs[i].Message += opaqueCommandSuffix
			}
		}
		return fs
	})
}

type keyState int

const (
	keyMissing keyState = iota
	keySet
	keyUnknown
)

func vllmKeyState(in *Input, w model.Workload, c model.Container, a VLLMArgs) (keyState, []string) {
	if a.APIKey {
		return keySet, nil
	}
	if _, explicit := lastEnv(c.Spec.Env, vllmAPIKeyEnv); explicit {
		return keyMissing, nil
	}
	found, missing := EnvFromKey(in, w.Owner.Namespace, c, vllmAPIKeyEnv)
	switch {
	case found:
		return keySet, nil
	case len(missing) > 0:
		return keyUnknown, missing
	}
	return keyMissing, nil
}

func aiAPIKey(in *Input) Result {
	return vllmContainers(in, func(w model.Workload, c model.Container, a VLLMArgs) []Finding {
		path := c.Path + "/" + fieldArgs
		switch state, missing := vllmKeyState(in, w, c, a); state {
		case keySet:
			return nil
		case keyUnknown:
			msg := fmt.Sprintf("vLLM API key may come from envFrom %s, not in the input: the scanner cannot see if %s is set", strings.Join(missing, ", "), vllmAPIKeyEnv)
			if a, ok := workloadAuth(in, w); ok {
				return []Finding{declaredFinding(w, c, path, msg, a)}
			}
			return []Finding{suspect(violation(w, c.Spec.Name, path, msg))}
		}
		msg := "vLLM serves without authentication: neither " + flagAPIKey + " nor the " + vllmAPIKeyEnv + " env var is set"
		if a, ok := workloadAuth(in, w); ok {
			return []Finding{declaredFinding(w, c, path, msg, a)}
		}
		return []Finding{violation(w, c.Spec.Name, path, msg)}
	})
}

func aiTrustRemoteCode(in *Input) Result {
	return vllmContainers(in, func(w model.Workload, c model.Container, a VLLMArgs) []Finding {
		if !a.TrustRemoteCode {
			return nil
		}
		return []Finding{violation(w, c.Spec.Name, c.Path+"/"+flagField(c, flagTrust), "vLLM runs with "+flagTrust+": it executes code from the model repository")}
	})
}

func aiPickleLoad(in *Input) Result {
	return vllmContainers(in, func(w model.Workload, c model.Container, a VLLMArgs) []Finding {
		strength, msg, ok := loadVerdict(a)
		if !ok {
			return nil
		}
		field := fieldArgs
		if a.LoadFormatSet {
			field = flagField(c, flagLoadFormat)
		}
		f := violation(w, c.Spec.Name, c.Path+"/"+field, msg)
		f.Strength = strength
		return []Finding{f}
	})
}

func loadVerdict(a VLLMArgs) (Strength, string, bool) {
	format := strings.ToLower(a.LoadFormat)
	switch {
	case a.LoadFormatDynamic:
		return Suspect, flagLoadFormat + " comes from a variable: the scanner cannot see the format", true
	case !a.LoadFormatSet:
		return autoVerdict(a, "no "+flagLoadFormat)
	case slices.Contains(safeFormats, format):
		return Violation, "", false
	case slices.Contains(PickleFormats, format):
		return Violation, fmt.Sprintf("%s %s loads pickle-based PyTorch weights", flagLoadFormat, a.LoadFormat), true
	case slices.Contains(AutoFormats, format):
		return autoVerdict(a, flagLoadFormat+" "+a.LoadFormat)
	}
	return Suspect, fmt.Sprintf("%s %s is not %s: review how the weights are loaded", flagLoadFormat, a.LoadFormat, safeFormats[0]), true
}

func autoVerdict(a VLLMArgs, setting string) (Strength, string, bool) {
	if HasPickleSuffix(a.Model) {
		return Violation, fmt.Sprintf("%s and model %q is a pickle file", setting, a.Model), true
	}
	msg := setting + ": vLLM falls back to .bin and .pt files when the model has no safetensors weights (set " + flagLoadFormat + " " + safeFormats[0] + ")"
	if a.ConfigFile && !a.LoadFormatSet {
		msg += "; " + flagConfig + " may set the format"
	}
	return Suspect, msg, true
}

func HasPickleSuffix(modelName string) bool {
	ext := strings.ToLower(path.Ext(strings.TrimRight(modelName, "/")))
	return slices.Contains(pickleModelSuffixes, ext)
}

func aiExposed(in *Input) Result {
	ws := AIWorkloads(in)
	if len(ws) == 0 {
		return Result{}
	}
	res := Result{Applicable: true}
	seen := map[string]int{}
	for _, w := range ws {
		reason, strength, ok := unauthenticatedServer(in, w)
		if !ok {
			continue
		}
		auth, declared := workloadAuth(in, w)
		if declared {
			strength = Declared
		}
		res.Findings = appendExposures(res.Findings, seen, Exposures(in, w, nil), true, strength, func(e Exposure) string {
			msg := exposureMessage(e, w, reason)
			if declared {
				msg += auth.Suffix()
			}
			return msg
		})
	}
	return res
}

func unauthenticatedServer(in *Input, w model.Workload) (string, Strength, bool) {
	v := serverAuth(in, w)
	return v.reason, v.strength, v.open
}

func serverAuth(in *Input, w model.Workload) serverVerdict {
	server := false
	reason, unsure := "", false
	var keyed AuthEvidence
	for _, c := range w.Containers {
		if c.Init {
			continue
		}
		if isGenericEngine(c.Stack) && c.Stack != model.Ollama {
			server = true
			r, s, final := engineAuthReason(in, w, c)
			switch {
			case final:
				return serverVerdict{reason: r, strength: Violation, open: true}
			case s && !unsure:
				reason, unsure = r, true
			case r == "" && !keyed.Present():
				keyed = keyEvidence(c, flagAPIKey+" or an auth env var")
			}
			continue
		}
		a := ParseVLLM(c)
		if !a.Found {
			continue
		}
		server = true
		state, missing := vllmKeyState(in, w, c, a)
		switch {
		case state == keyMissing && !a.Opaque:
			return serverVerdict{reason: "vLLM container " + c.Spec.Name + " has no " + flagAPIKey + " and no " + vllmAPIKeyEnv, strength: Violation, open: true}
		case state == keyMissing:
			reason, unsure = "vLLM container "+c.Spec.Name+" has no "+flagAPIKey+" and no "+vllmAPIKeyEnv+" that the scanner can see"+opaqueCommandSuffix, true
		case state == keyUnknown && !unsure:
			reason, unsure = "vLLM container "+c.Spec.Name+" may take "+vllmAPIKeyEnv+" from envFrom "+strings.Join(missing, ", ")+", not in the input", true
		case state == keySet && !keyed.Present():
			keyed = keyEvidence(c, flagAPIKey+" or "+vllmAPIKeyEnv)
		}
	}
	switch {
	case unsure:
		return serverVerdict{reason: reason, strength: Suspect, open: true}
	case !server && w.HasStack(model.KServe):
		return serverVerdict{reason: "the KServe predictor has no authentication in the manifests", strength: Violation, open: true}
	}
	return serverVerdict{strength: Violation, keyed: keyed}
}

func exposureMessage(e Exposure, w model.Workload, reason string) string {
	switch e.Kind {
	case ExposureServiceNodePort:
		return fmt.Sprintf("Service type NodePort exposes %s outside the cluster: %s", w.Owner, reason)
	case ExposureServiceLoadBalancer:
		return fmt.Sprintf("Service type LoadBalancer exposes %s outside the cluster: %s", w.Owner, reason)
	}
	return fmt.Sprintf("Ingress routes outside traffic to %s without an auth annotation (%s): %s", w.Owner, strings.Join(ingressAuthHints, ", ")+" or "+GatewayAuthKey, reason)
}
