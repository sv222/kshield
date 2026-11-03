package remediate

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
)

const (
	APIKeySecretKey = "api-key"

	vllmProgram       = "vllm"
	flagTrust         = "--trust-remote-code"
	flagLoadFormat    = "--load-format"
	flagAPIKey        = "--api-key"
	safeLoadFormat    = "safetensors"
	vllmAPIKeyEnv     = "VLLM_API_KEY"
	apiKeySuffix      = "-vllm-api-key"
	maxNameLength     = 253
	fieldArgs         = "args"
	fieldCommand      = "command"
	modeEnforce       = "enforce"
	netBroadCheckID   = "KS-NET-002"
	kindService       = "Service"
	kindIngress       = "Ingress"
	kindNetworkPolicy = "NetworkPolicy"
	networkingGroup   = "networking.k8s.io"
	ciliumGroup       = "cilium.io"
	rayServiceType    = "/serviceType"
	rayEnableIngress  = "/enableIngress"
	policyTypesPath   = "/spec/policyTypes"
	egressDenyKey     = "egressDeny"

	reasonPickle      = "the model file is pickle; convert it to safetensors first, or vLLM will not load"
	reasonRayIngress  = "remove the Ingress path to the Ray port by hand"
	reasonAuditEgress = "audit mode never changes existing egress policies"
	reasonDynamicLoad = "--load-format comes from a variable; set it to safetensors by hand"
	reasonOpaqueLoad  = "the container command is a script that is not vllm serve; add --load-format safetensors where it starts vLLM by hand"
	reasonShellEdit   = "the vllm call in the shell script could not be edited; edit it by hand"
	reasonArgv        = "the vllm arguments could not be mapped to command and args; edit them by hand"
	reasonArgvEdit    = "the vllm arguments still fail the check after the edit; edit them by hand"
	reasonShellKey    = "the shell script holds a literal --api-key; move it to a Secret first"
	reasonConfigLoad  = "the load format may come from the --config file; set --load-format safetensors there by hand"
)

var (
	serviceExternalFields = []string{
		"externalTrafficPolicy",
		"healthCheckNodePort",
		"loadBalancerIP",
		"loadBalancerSourceRanges",
		"loadBalancerClass",
		"allocateLoadBalancerNodePorts",
	}
	// source: https://github.com/kubernetes/api/blob/v0.37.1/networking/v1/types.go@v0.37.1
	defaultPolicyTypes = []any{"Ingress", "Egress"}
)

type argItem struct {
	field string
	index int
	value string
}

func APIKeySecretName(in *check.Input, owner load.ObjectRef) string {
	return ownerSecretName(in, owner, apiKeySuffix)
}

func ownerSecretName(in *check.Input, owner load.ObjectRef, suffix string) string {
	name := owner.Name
	if ownerNameClash(in, owner) {
		name += "-" + strings.ToLower(owner.Kind)
	}
	name += suffix
	if len(name) > maxNameLength {
		name = strings.TrimRight(name[:maxNameLength], "-.")
	}
	return name
}

func ownerNameClash(in *check.Input, owner load.ObjectRef) bool {
	if in == nil {
		return false
	}
	return slices.ContainsFunc(in.Workloads, func(w model.Workload) bool {
		r := w.Owner
		return r.Namespace == owner.Namespace && r.Name == owner.Name && r.Kind != owner.Kind && !owned(w.Object)
	})
}

func fixAPIKey(w model.Workload, c model.Container, in *check.Input) ([]Op, string) {
	i := lastEnvIndex(c.Spec.Env, vllmAPIKeyEnv)
	if i < 0 && len(c.Spec.EnvFrom) > 0 {
		if in == nil {
			return nil, keyRefReason(nil)
		}
		if found, missing := check.EnvFromKey(in, w.Owner.Namespace, c, vllmAPIKeyEnv); !found && len(missing) > 0 {
			return nil, keyRefReason(missing)
		}
	}
	item := map[string]any{
		"name": vllmAPIKeyEnv,
		"valueFrom": map[string]any{"secretKeyRef": map[string]any{
			"name": APIKeySecretName(in, w.Owner),
			"key":  APIKeySecretKey,
		}},
	}
	p := c.Path + "/env/-"
	if i >= 0 {
		p = c.Path + "/env/" + strconv.Itoa(i)
	}
	return []Op{Set(w.Object.U.Object, p, item)}, ""
}

func lastEnvIndex(env []corev1.EnvVar, name string) int {
	for i := len(env) - 1; i >= 0; i-- {
		if env[i].Name == name {
			return i
		}
	}
	return -1
}

func keyRefReason(missing []string) string {
	from := "envFrom"
	if len(missing) > 0 {
		from += " " + strings.Join(missing, ", ")
	}
	return fmt.Sprintf("%s may come from %s, not in the input; an added env would override it; set the key by hand", vllmAPIKeyEnv, from)
}

func argItems(c model.Container) []argItem {
	var out []argItem
	for i, v := range c.Spec.Command {
		out = append(out, argItem{fieldCommand, i, v})
	}
	for i, v := range c.Spec.Args {
		out = append(out, argItem{fieldArgs, i, v})
	}
	return out
}

func itemPath(c model.Container, it argItem) string {
	return c.Path + "/" + it.field + "/" + strconv.Itoa(it.index)
}

func shellItem(c model.Container) (argItem, bool) {
	items := argItems(c)
	words := make([]string, len(items))
	for i, it := range items {
		words[i] = it.value
	}
	i, ok := model.ShellScriptIndex(words)
	if !ok {
		return argItem{}, false
	}
	return items[i], true
}

func vllmWords(c model.Container) ([]argItem, []string, int, bool) {
	items := argItems(c)
	if len(c.Commands) != 1 || len(c.Commands[0].Words) != len(items) {
		return nil, nil, 0, false
	}
	words := c.Commands[0].Words
	if start, ok := programArgStart(words, vllmProgram); ok {
		return items, words, start, true
	}
	if len(c.Spec.Command) == 0 {
		return items, words, 0, true
	}
	return items, words, 1, true
}

func loadResidual(a check.VLLMArgs) string {
	format := strings.ToLower(a.LoadFormat)
	switch {
	case check.HasPickleSuffix(a.Model):
		return reasonPickle
	case a.LoadFormatDynamic:
		return reasonDynamicLoad
	case a.ConfigFile && !a.LoadFormatSet:
		return reasonConfigLoad
	case a.LoadFormatSet && !slices.Contains(check.PickleFormats, format) && !slices.Contains(check.AutoFormats, format):
		return fmt.Sprintf("%s %s is not a pickle format; kshield does not change it; review how the weights are loaded", flagLoadFormat, a.LoadFormat)
	}
	return ""
}

func safeLoad(a check.VLLMArgs) bool {
	return a.LoadFormatSet && !a.LoadFormatDynamic && strings.EqualFold(a.LoadFormat, safeLoadFormat)
}

func reparse(c model.Container, command, args []string) check.VLLMArgs {
	spec := c.Spec
	spec.Command, spec.Args = command, args
	c.Spec = spec
	c.Commands = model.ResolveCommands(spec)
	return check.ParseVLLM(c)
}

type shellResult struct {
	script      string
	trust, load bool
}

func shellPlan(c model.Container, it argItem, a check.VLLMArgs) (shellResult, string) {
	if literalFlagValue(it.value, flagAPIKey) {
		return shellResult{}, reasonShellKey
	}
	trust, load := a.TrustRemoteCode, loadResidual(a) == ""
	for trust || load {
		edit := ShellEdit{Program: vllmProgram}
		if trust {
			edit.RemoveFlags = []string{flagTrust}
		}
		if load {
			edit.SetFlag, edit.SetValue = flagLoadFormat, safeLoadFormat
		}
		out, ok := EditShell(it.value, edit)
		if !ok {
			break
		}
		command, args := slices.Clone(c.Spec.Command), slices.Clone(c.Spec.Args)
		if it.field == fieldCommand {
			command[it.index] = out
		} else {
			args[it.index] = out
		}
		after := reparse(c, command, args)
		trustFailed := trust && after.TrustRemoteCode
		loadFailed := load && !safeLoad(after)
		if !trustFailed && !loadFailed {
			return shellResult{script: out, trust: trust, load: load}, ""
		}
		trust, load = trust && !trustFailed, load && !loadFailed
	}
	return shellResult{}, ""
}

func shellFix(w model.Workload, c model.Container, it argItem, a check.VLLMArgs, done func(shellResult) bool) ([]Op, string) {
	res, reason := shellPlan(c, it, a)
	switch {
	case reason != "":
		return nil, reason
	case !done(res) || res.script == it.value:
		return nil, reasonShellEdit
	}
	return []Op{Set(w.Object.U.Object, itemPath(c, it), res.script)}, ""
}

func listFix(w model.Workload, c model.Container, a check.VLLMArgs, edit ShellEdit) ([]Op, check.VLLMArgs, string) {
	items, words, start, ok := vllmWords(c)
	if !ok {
		return nil, a, reasonArgv
	}
	edits, found := flagEdits(words, start, edit)
	appendSet := edit.SetFlag != "" && !found
	if appendSet && a.Opaque {
		return nil, a, reasonOpaqueLoad
	}
	obj := w.Object.U.Object
	values := make([]string, len(items))
	removed := make([]bool, len(items))
	for i, it := range items {
		values[i] = it.value
	}
	var ops []Op
	for _, e := range edits {
		p := itemPath(c, items[e.index])
		if e.remove {
			removed[e.index] = true
			ops = append(ops, Remove(p))
			continue
		}
		values[e.index] = e.text
		ops = append(ops, Set(obj, p, e.text))
	}
	var command, args []string
	for i, it := range items {
		switch {
		case removed[i]:
		case it.field == fieldCommand:
			command = append(command, values[i])
		default:
			args = append(args, values[i])
		}
	}
	if appendSet {
		field := fieldCommand
		if len(c.Spec.Args) > 0 {
			field = fieldArgs
		}
		p := c.Path + "/" + field + "/-"
		ops = append(ops, Set(obj, p, edit.SetFlag), Set(obj, p, edit.SetValue))
		if field == fieldArgs {
			args = append(args, edit.SetFlag, edit.SetValue)
		} else {
			command = append(command, edit.SetFlag, edit.SetValue)
		}
	}
	return ops, reparse(c, command, args), ""
}

func fixTrustRemoteCode(w model.Workload, c model.Container, _ *check.Input) ([]Op, string) {
	a := check.ParseVLLM(c)
	if !a.Found || !a.TrustRemoteCode {
		return nil, ""
	}
	if it, ok := shellItem(c); ok {
		return shellFix(w, c, it, a, func(r shellResult) bool { return r.trust })
	}
	ops, after, reason := listFix(w, c, a, ShellEdit{RemoveFlags: []string{flagTrust}})
	switch {
	case reason != "":
		return nil, reason
	case after.TrustRemoteCode:
		return nil, reasonArgvEdit
	}
	return ops, ""
}

func fixLoadFormat(w model.Workload, c model.Container, _ *check.Input) ([]Op, string) {
	a := check.ParseVLLM(c)
	if !a.Found {
		return nil, ""
	}
	if reason := loadResidual(a); reason != "" {
		return nil, reason
	}
	if it, ok := shellItem(c); ok {
		return shellFix(w, c, it, a, func(r shellResult) bool { return r.load })
	}
	ops, after, reason := listFix(w, c, a, ShellEdit{SetFlag: flagLoadFormat, SetValue: safeLoadFormat})
	switch {
	case reason != "":
		return nil, reason
	case !safeLoad(after):
		return nil, reasonArgvEdit
	}
	return ops, ""
}

func fixRayExposure(w model.Workload, f check.Finding, _ *check.Input, _ string) ([]Op, string) {
	obj := w.Object.U.Object
	group := apiGroupOf(f.Object.APIVersion)
	switch {
	case f.Object.Kind == kindIngress && group == networkingGroup:
		return nil, reasonRayIngress
	case f.Object.Kind == kindService && group == "":
		return serviceOps(obj), ""
	case group != rayGroup:
	case strings.HasSuffix(f.Path, rayServiceType):
		return []Op{Set(obj, f.Path, string(corev1.ServiceTypeClusterIP))}, ""
	case strings.HasSuffix(f.Path, rayEnableIngress):
		return []Op{Set(obj, f.Path, false)}, ""
	}
	return nil, "the finding path " + f.Path + " names no Ray service type, Ray ingress or Service of the object"
}

func serviceOps(obj map[string]any) []Op {
	ops := []Op{Set(obj, "/spec/type", string(corev1.ServiceTypeClusterIP))}
	ports, _ := lookupPath(obj, "/spec/ports").([]any)
	for i, p := range ports {
		if m, ok := p.(map[string]any); ok {
			if _, ok := m["nodePort"]; ok {
				ops = append(ops, Remove("/spec/ports/"+strconv.Itoa(i)+"/nodePort"))
			}
		}
	}
	spec, _ := obj["spec"].(map[string]any)
	for _, field := range serviceExternalFields {
		if _, ok := spec[field]; ok {
			ops = append(ops, Remove("/spec/"+field))
		}
	}
	return ops
}

func fixBroadEgress(w model.Workload, f check.Finding, in *check.Input, mode string) ([]Op, string) {
	if mode != modeEnforce {
		return nil, reasonAuditEgress
	}
	obj := w.Object.U.Object
	if _, ok := lookupPath(obj, f.Path).(map[string]any); !ok {
		return nil, "the finding path " + f.Path + " names no egress rule of the policy"
	}
	ops := []Op{Remove(f.Path)}
	list := path.Dir(f.Path)
	switch group := apiGroupOf(f.Object.APIVersion); {
	case f.Object.Kind == kindNetworkPolicy && group == networkingGroup:
		if types, _ := lookupPath(obj, policyTypesPath).([]any); len(types) == 0 {
			ops = append(ops, Set(obj, policyTypesPath, defaultPolicyTypes))
		}
	case group == ciliumGroup:
		rule, _ := lookupPath(obj, path.Dir(list)).(map[string]any)
		deny, _ := rule[egressDenyKey].([]any)
		items, _ := lookupPath(obj, list).([]any)
		if len(deny) == 0 && broadRules(f, in, list) >= len(items) {
			ops = append(ops, Set(obj, list+"/-", denyAllEgressRule()))
		}
	}
	return ops, ""
}

// source: https://github.com/cilium/cilium/blob/v1.20.3/Documentation/security/policy/layer3.rst@v1.20.3
// source: https://github.com/cilium/cilium/blob/v1.20.3/examples/policies/l3/egress-default-deny/egress-default-deny.yaml@v1.20.3
func denyAllEgressRule() map[string]any {
	return map[string]any{}
}

func broadRules(f check.Finding, in *check.Input, list string) int {
	c, ok := check.ByID(netBroadCheckID)
	if in == nil || !ok {
		return 1
	}
	n := 0
	for _, g := range check.Evaluate(c, in).Findings {
		if g.Object == f.Object && path.Dir(g.Path) == list {
			n++
		}
	}
	return n
}
