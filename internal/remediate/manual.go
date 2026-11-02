package remediate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
	"github.com/sv222/kshield/internal/report"
)

const (
	apiKeyCheckID   = "KS-AI-001"
	trustCheckID    = "KS-AI-002"
	loadCheckID     = "KS-AI-003"
	shmCheckID      = "KS-WL-005"
	managedByLabel  = "app.kubernetes.io/managed-by"
	managedByHelm   = "Helm"
	nsPlaceholder   = "<namespace of the InferenceService>"
	apiKeyValueHint = "<random API key>"

	helmPluginDir       = "kshield-postrender"
	helmPostRenderFlags = "--post-renderer kshield-postrender --post-renderer-args <absolute path of this bundle dir> --post-renderer-args <namespace>"
	helmScanSteps       = `helm template <release> <chart> -n <namespace> -f <values.yaml> >rendered.yaml
kshield scan manifest -f rendered.yaml -n <namespace> --format json --out scan.json
kshield remediate --from scan.json --out <bundle dir>
`
	helmPluginYAML = `apiVersion: v1
name: kshield-postrender
version: 0.1.0
type: postrenderer/v1
runtime: subprocess
runtimeConfig:
  platformCommand:
  - command: ${HELM_PLUGIN_DIR}/postrender.sh
`
	helmPostRenderScript = `#!/usr/bin/env bash
set -euo pipefail
bundle=${1:?usage: postrender.sh <bundle dir> <namespace>}
namespace=${2:?usage: postrender.sh <bundle dir> <namespace>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/ns"
cat >"$work/ns/helm.yaml"
printf 'resources:\n- helm.yaml\ntransformers:\n- namespace.yaml\n' >"$work/ns/kustomization.yaml"
printf 'apiVersion: builtin\nkind: NamespaceTransformer\nmetadata:\n  name: kshield-namespace\n  namespace: %s\nunsetOnly: true\nsetRoleBindingSubjects: none\nfieldSpecs:\n- path: metadata/namespace\n  create: true\n' "$namespace" >"$work/ns/namespace.yaml"
cp -R "$bundle/." "$work/bundle"
kustomize build "$work/ns" >"$work/bundle/base/manifests.yaml"
kustomize build "$work/bundle"
`

	stepsWL011 = "Keep secret values out of the pod spec. Store each value in a Secret and read it with `valueFrom.secretKeyRef`. " +
		"`base/manifests.yaml` in this bundle already reads the values from Secrets: create them as shown under \"Before you apply\". " +
		"Then rotate every value, because it is in your manifests and their history."
	stepsWL012 = "Pin each image by digest. Get the digest of the tag you run with `crane digest <image>:<tag>` or `docker buildx imagetools inspect <image>:<tag>`, " +
		"then set `image: <image>@sha256:<digest>`. Update the digest on purpose, through your change process."
	stepsWL013 = "Set `resources.limits.memory` on each AI container. Size it from the measured peak use plus headroom. " +
		"With a limit, memory pressure stops only this container, not other pods on the node."
	stepsWL014 = "Give the pod GPUs through the NVIDIA device plugin (or the GPU Operator): request them with `resources.limits: {nvidia.com/gpu: <n>}`. " +
		"Then remove the hostPath `/dev/nvidia*` volumes, `privileged: true` and a literal `NVIDIA_VISIBLE_DEVICES`. " +
		"Scan again: KS-WL-002 can then be patched."
	stepsAI001 = "Turn on vLLM authentication: create a Secret with a long random key and set `VLLM_API_KEY` from it with `valueFrom.secretKeyRef`, " +
		"or pass `--api-key $(VLLM_API_KEY)`. Clients send the key as `Authorization: Bearer <key>`."
	stepsAI004 = "Do not expose an inference API outside the cluster without authentication. Set `VLLM_API_KEY` (KS-AI-001), " +
		"or put an authenticating proxy or API gateway in front of it, " +
		"or change the Service to `type: ClusterIP` and remove the Ingress path."
	stepsAI006 = "Turn on Ray TLS: create a CA and certificates for the Ray pods (for example with cert-manager), mount them into the head and every worker group, " +
		"and set `RAY_USE_TLS=1`, `RAY_TLS_SERVER_CERT`, `RAY_TLS_SERVER_KEY` and `RAY_TLS_CA_CERT` on every Ray container."
	stepsAI007 = "Ollama has no authentication of its own. Keep its Service `type: ClusterIP`, " +
		"and put an authenticating proxy in front of port 11434 for clients outside the namespace."
	stepsAI008 = "Set `QDRANT__SERVICE__API_KEY` from a Secret with `valueFrom.secretKeyRef`. " +
		"Turn on TLS with `QDRANT__SERVICE__ENABLE_TLS=true`, and point `QDRANT__TLS__CERT` and `QDRANT__TLS__KEY` at a mounted certificate Secret."
	stepsAI009 = "Set `common.security.authorizationEnabled: true` in the Milvus configuration (`milvus.yaml`, or `extraConfigFiles` in the Helm values). " +
		"Then change the password of the default `root` user."
	stepsNET003 = "Turn on Cilium transparent encryption with the Helm values `encryption.enabled=true` and `encryption.type=wireguard` (or `ipsec`). " +
		"Check it with `cilium encrypt status`."
	stepsPRE001 = "Install Tetragon at the version pinned in kshield `versions.env` and check that its DaemonSet pods are Ready on every node. " +
		"Without Tetragon the TracingPoliciesNamespaced in this bundle do nothing."
	stepsPRE002 = "Use Cilium as the CNI. On another CNI the CiliumNetworkPolicies in this bundle do nothing, " +
		"and egress control falls back to Kubernetes NetworkPolicy, which has no FQDN rules."
	stepsPRE003 = "Install Kyverno at the version pinned in kshield `versions.env` and check that its admission controller pods are Ready. " +
		"Without Kyverno the kshield-admission Policy in this bundle does nothing."
	stepsPRE004 = "Boot the nodes with BPF LSM on: a kernel with `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` kernel command line. " +
		"Tetragon policies on LSM hooks need it."
)

var podSecurityChecks = []string{"KS-WL-001", "KS-WL-002", "KS-WL-003", "KS-WL-004", "KS-WL-005", "KS-WL-009"}

var manualSteps = map[string]string{
	"KS-WL-011":  stepsWL011,
	"KS-WL-012":  stepsWL012,
	"KS-WL-013":  stepsWL013,
	"KS-WL-014":  stepsWL014,
	"KS-AI-001":  stepsAI001,
	"KS-AI-004":  stepsAI004,
	"KS-AI-006":  stepsAI006,
	"KS-AI-007":  stepsAI007,
	"KS-AI-008":  stepsAI008,
	"KS-AI-009":  stepsAI009,
	"KS-NET-003": stepsNET003,
	"KS-PRE-001": stepsPRE001,
	"KS-PRE-002": stepsPRE002,
	"KS-PRE-003": stepsPRE003,
	"KS-PRE-004": stepsPRE004,
}

func manualCheckIDs() []string {
	var out []string
	for _, c := range check.All() {
		if c.Fix == check.FixManual {
			out = append(out, c.ID)
		}
	}
	return out
}

type manualWriter struct {
	strings.Builder
}

func (m *manualWriter) f(format string, a ...any) {
	_, _ = fmt.Fprintf(m, format, a...)
}

func code(s string) string {
	return "`" + s + "`"
}

func findingLine(f report.Finding) string {
	s := code(f.Object.String())
	if f.Group != "" {
		s += " group " + code(f.Group)
	}
	if f.Container != "" {
		s += " container " + code(f.Container)
	}
	if f.Path != "" {
		s += " (" + code(f.Path) + ")"
	}
	return s
}

func (b *builder) manual() []byte {
	var m manualWriter
	m.f("# kshield remediation\n\n")
	m.f("Mode: %s. Profile: %s (sha256 %s). scan.json sha256: %s.\n\n", code(b.mode), code(b.report.Profile.ID), code(b.report.Profile.SHA256), code(b.scanSum))
	if b.cluster {
		m.f("Source: a cluster scan. `base/manifests.yaml` holds only the live objects that the patches change, read from the cluster just now. ")
		m.f("It has no `status`, no server-set metadata and no Secret or ConfigMap.\n\n")
		m.f("Replica counts are as scanned. If a HorizontalPodAutoscaler manages an owner, delete `spec.replicas` of that owner from `base/manifests.yaml` before you apply, or the apply resets the count. ")
		m.f("If a GitOps controller (for example Argo CD or Flux) manages an owner, put the patch in its source repository instead: the controller reverts a direct apply.\n\n")
	}
	b.beforeApply(&m)
	b.rollout(&m)
	b.helm(&m)
	b.residuals(&m)
	b.manualItems(&m)
	return []byte(m.String())
}

func (b *builder) patched(checkID string) []*item {
	var out []*item
	for _, it := range b.items {
		if it.checkID == checkID && it.action == ActionPatch {
			out = append(out, it)
		}
	}
	return out
}

func (b *builder) beforeApply(m *manualWriter) {
	m.f("## Before you apply\n\n")
	empty := true
	var seen []string
	var keys []string
	for _, it := range b.patched(apiKeyCheckID) {
		ns, name := it.finding.Object.Namespace, APIKeySecretName(b.in, it.finding.Object)
		if ns == "" {
			ns = nsPlaceholder
		}
		if id := ns + "/" + name; !slices.Contains(seen, id) {
			seen = append(seen, id)
			keys = append(keys, fmt.Sprintf("kubectl create secret generic %s -n %s --from-literal=%s='%s'\n", name, ns, APIKeySecretKey, apiKeyValueHint))
		}
	}
	if len(keys) > 0 {
		empty = false
		m.f("### API key Secrets (KS-AI-001)\n\n")
		m.f("The patch sets `VLLM_API_KEY` from these Secrets. Create each one before you apply the patch, or the pod does not start. ")
		m.f("Use a long random key. Clients then send it as `Authorization: Bearer <key>`.\n\n")
		m.f("```sh\n%s```\n\n", strings.Join(keys, ""))
	}
	if len(b.moved) > 0 {
		empty = false
		m.f("### Secret values moved out of the input (KS-WL-011)\n\n")
		m.f("`base/manifests.yaml` holds no literal secret values of the input. Each one now comes from a Secret. ")
		m.f("Create these Secrets with the values from your manifests. Then rotate the values, because they are in your manifests and their history.\n\n")
		m.f("```sh\n")
		var owners []load.ObjectRef
		for _, mv := range b.moved {
			if !slices.Contains(owners, mv.owner) {
				owners = append(owners, mv.owner)
			}
		}
		for _, o := range owners {
			ns := o.Namespace
			if ns == "" {
				ns = nsPlaceholder
			}
			m.f("kubectl create secret generic %s -n %s", envSecretName(b.in, o), ns)
			var done []string
			for _, mv := range b.moved {
				if mv.owner == o && !slices.Contains(done, mv.key) {
					done = append(done, mv.key)
					m.f(" \\\n  --from-literal=%s='<%s>'", mv.key, mv.source)
				}
			}
			m.f("\n")
		}
		m.f("```\n\n")
	}
	if len(b.excluded) > 0 {
		empty = false
		m.f("### Secrets left out of the bundle\n\n")
		m.f("These Secrets of the input are not in `base/manifests.yaml`, so the bundle holds no secret values. ")
		m.f("`kustomize build` does not output them; they stay as they are in the cluster.\n\n")
		for _, ref := range b.excluded {
			m.f("- %s\n", code(ref.String()))
		}
		m.f("\n")
	}
	if len(b.generated) > 0 {
		empty = false
		m.f("### Generated objects left out of the bundle\n\n")
		m.f("These objects have `metadata.ownerReferences`: a controller creates them and reverts changes to them. ")
		m.f("`base/manifests.yaml` leaves them out and kshield never patches them. Fix their owners; their findings below name the owner.\n\n")
		for _, ref := range b.generated {
			m.f("- %s\n", code(ref.String()))
		}
		m.f("\n")
	}
	if trusts := b.patched(trustCheckID); len(trusts) > 0 {
		empty = false
		m.f("### Remote code (KS-AI-002)\n\n")
		m.f("The patch removes `--trust-remote-code`. vLLM then cannot load a model that needs custom Python code from its repository (a custom model class or tokenizer). ")
		m.f("Check each model below first. If a model needs custom code, do not apply this patch to it: review that code, or use a model that vLLM supports without it.\n\n")
		for _, it := range trusts {
			m.f("- %s\n", findingLine(report.Finding{Object: it.finding.Object, Group: it.finding.Group, Container: it.finding.Container}))
		}
		m.f("\n")
	}
	if loads := b.patched(loadCheckID); len(loads) > 0 {
		empty = false
		m.f("### Model weights (KS-AI-003)\n\n")
		m.f("The patch sets `--load-format safetensors`. vLLM then fails at start when the model repository has only `.bin` or `.pt` weights. ")
		m.f("Check that each model below has `.safetensors` files, or convert it first.\n\n")
		for _, it := range loads {
			m.f("- %s\n", findingLine(report.Finding{Object: it.finding.Object, Group: it.finding.Group, Container: it.finding.Container}))
		}
		m.f("\n")
	}
	if uids := b.imageUIDItems(); len(uids) > 0 {
		empty = false
		m.f("### Image user IDs (KS-WL-001)\n\n")
		m.f("The patch runs these containers as the uid and gid of their image, not as %d. ", NonRootUID)
		m.f("The uid comes from a measured image: the files of `%s` are owned by uid %d (`milvus`), and other users cannot run its binary. ", milvusMeasuredImage, stackUID[model.Milvus])
		m.f("Check the uid of your image (`docker run --rm --entrypoint id <image>`) and change the patch if it differs.\n\n")
		for _, u := range uids {
			m.f("- %s: uid %d\n", findingLine(report.Finding{Object: u.it.finding.Object, Group: u.it.finding.Group, Container: u.it.finding.Container}), u.uid)
		}
		m.f("\n")
	}
	if empty {
		m.f("Nothing to create or check before you apply.\n\n")
	}
}

type imageUID struct {
	it  *item
	uid int64
}

func (b *builder) imageUIDItems() []imageUID {
	var out []imageUID
	for _, it := range b.patched("KS-WL-001") {
		for _, op := range it.ops {
			if uid, ok := runAsUserOf(op.Path, op.Value); ok && uid != NonRootUID {
				out = append(out, imageUID{it: it, uid: uid})
			}
		}
	}
	return out
}

func runAsUserOf(p string, v any) (int64, bool) {
	switch v := v.(type) {
	case int64:
		return v, strings.HasSuffix(p, "/runAsUser")
	case map[string]any:
		for k, sub := range v {
			if uid, ok := runAsUserOf(p+"/"+k, sub); ok {
				return uid, true
			}
		}
	}
	return 0, false
}

func (b *builder) rollout(m *manualWriter) {
	m.f("## Rollout order\n\n")
	m.f("Run these steps from this directory.\n\n")
	m.f("1. Patch the workloads: `kustomize build . | kubectl apply -f -`. Use the kustomize version pinned in kshield `versions.env`. ")
	m.f("A JSON 6902 `test` op fails the build when the manifests changed after the scan.\n")
	m.f("2. Apply the policies in audit mode: `kubectl apply -f infrastructure-policies.yaml`. Audit mode records and never blocks.\n")
	m.f("3. Review what the policies record in each namespace: Kyverno policy reports (`kubectl get policyreports -n <namespace>`), ")
	m.f("Tetragon events (`kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact`) ")
	m.f("and Hubble flows (`hubble observe --namespace <namespace>`).\n")
	m.f("4. Switch to enforce one namespace at a time: run `kshield remediate --from <scan.json> --mode enforce --out <new dir>` ")
	if b.cluster {
		m.f("with the same `--allow-fqdn` and `--allow-cidr` flags. ")
	} else {
		m.f("with the same `-f`, `--allow-fqdn` and `--allow-cidr` flags. ")
	}
	m.f("In the new dir, build and apply the whole enforce bundle (`kustomize build . | kubectl apply -f -`), ")
	m.f("because its KS-NET-002 enforce patches are in `workload-patch-6902/`. Then apply the policies of that namespace from its `infrastructure-policies.yaml`. ")
	m.f("The KS-NET-002 enforce patches in the bundle cover every namespace at once; only the policies go one namespace at a time. ")
	m.f("On a CNI that is not Cilium, apply these patches only when every namespace is ready.\n\n")
	switch names := b.bundleNamespaces(); {
	case len(names) > 0:
		ns := make([]string, len(names))
		for i, n := range names {
			ns[i] = code(n)
		}
		m.f("Namespaces with policies in this bundle: %s.\n\n", strings.Join(ns, ", "))
	case len(b.kept) > 0:
		m.f("This bundle has no policies.\n\n")
	default:
		m.f("This bundle has no policies: no namespace needs them.\n\n")
	}
	if len(b.kept) > 0 {
		refs := make([]string, len(b.kept))
		for i, r := range b.kept {
			refs[i] = code(r.String())
		}
		m.f("Audit mode never replaces a policy that is already in the input, so this bundle leaves out %s. ", strings.Join(refs, ", "))
		m.f("Keep the existing objects; the `--mode enforce` bundle of step 4 replaces them.\n\n")
	}
	if b.mode == modeEnforce {
		m.f("This bundle is in `enforce` mode. Apply an audit bundle (`--mode audit`) first, and use this one only for step 4.\n\n")
	}
	m.f("Before you switch a namespace to enforce:\n\n")
	m.f("- The shell-exec guard kills exec probes and lifecycle hooks that run a shell, and entrypoint shells under `tini` or `dumb-init`. ")
	m.f("Change exec probes to `httpGet` or `tcpSocket`, or keep that namespace in audit.\n")
	if refs := b.rayWorkloads(); len(refs) > 0 {
		names := make([]string, len(refs))
		for i, r := range refs {
			names[i] = code(r.String())
		}
		m.f("- Ray starts shells from its Python processes: the dashboard, the client server, the autoscaler v2 monitor, `multiprocessing` spawn children and a `ray start` fork. ")
		m.f("In enforce mode the shell-exec guard kills them, and the Ray head does not start (measured with `rayproject/ray:2.52.0`). ")
		m.f("kshield has no allow-list for Ray. Keep the namespaces of these workloads in audit: %s.\n", strings.Join(names, ", "))
	}
	m.f("- The egress policy allows DNS through kube-dns, the same namespace, the other AI namespaces and the `--allow-fqdn` and `--allow-cidr` values. ")
	m.f("Add `--allow-cidr` for NodeLocal DNSCache (`169.254.20.10/32`) and for pod or service CIDRs outside RFC 1918 (for example `100.64.0.0/10`).\n")
	m.f("- On a CNI that is not Cilium, the CiliumNetworkPolicies do nothing. There, the KS-NET-002 enforce patch removes the broad egress rules of a NetworkPolicy ")
	m.f("and keeps `policyTypes: [Ingress, Egress]`. With no egress rule left, this blocks all egress, DNS included.\n")
	m.f("- Check that Tetragon loaded the enforce policies: `kubectl get tracingpoliciesnamespaced -n <namespace>` and the Tetragon agent logs. ")
	m.f("The egress-connect `Override` action needs BPF `fmod_ret` support in the node kernel.\n")
	m.f("- The `%s` rule of the `%s` Policy enforces the Pod Security Standards `restricted` profile. ", podSecurityRuleName, admissionPolicyName)
	m.f("In enforce mode it rejects new pods that break that profile: pods of a workload with a residual item of KS-WL-001 to KS-WL-005 or KS-WL-009 ")
	m.f("(for example a privileged GPU container, a hostPath `/dev` or a volume mounted under `/root`), and pods with any hostPath volume. ")
	m.f("Fix these workloads first, or keep that namespace in audit. ")
	if refs := b.podSecurityRejects(); len(refs) > 0 {
		names := make([]string, len(refs))
		for i, r := range refs {
			names[i] = code(r.String())
		}
		m.f("Workloads of this bundle: %s.\n", strings.Join(names, ", "))
	} else {
		m.f("No workload of this bundle has such a residual item or a hostPath volume.\n")
	}
	if refs := b.otherWorkloads(); len(refs) > 0 {
		names := make([]string, len(refs))
		for i, r := range refs {
			names[i] = code(r.String())
		}
		m.f("- kshield checks and patches AI workloads only, but the policies of a namespace apply to all its pods: ")
		m.f("the egress policy, the shell-exec guard and the `%s` rule. ", podSecurityRuleName)
		m.f("Other workloads in the namespaces with policies: %s. ", strings.Join(names, ", "))
		m.f("kshield does not patch them: in enforce mode the `%s` rule rejects their new pods that break the `restricted` profile, ", podSecurityRuleName)
		m.f("so set their security context to that profile first. ")
		m.f("Run an operator or controller among them (for example the KubeRay operator) in a namespace without these policies, ")
		m.f("or give only its pods an egress rule to the API server: a CiliumNetworkPolicy with an `endpointSelector` on its pod labels and `toEntities: [%s]`. ", entityAPIServer)
		m.f("This bundle adds an API server rule only for a RayCluster with the in-tree autoscaler, and that rule is the `%s` policy, which selects only the Ray head pods (`%s: %s`) of the namespace.\n", apiServerPolicyName, rayHeadLabel, rayHeadValue)
	}
	m.f("- `policies/README.md` in the kshield repository lists the limits of each policy.\n\n")
}

func (b *builder) podSecurityRejects() []load.ObjectRef {
	var out []load.ObjectRef
	add := func(ref load.ObjectRef) {
		if slices.Contains(b.policyNS, ref.Namespace) && !owned(b.objects[ref]) && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	for _, it := range b.items {
		if it.action == ActionManual && it.residual && slices.Contains(podSecurityChecks, it.checkID) {
			add(it.finding.Object)
		}
	}
	for _, w := range b.fix.Workloads {
		for i, v := range w.Spec.Volumes {
			if v.HostPath != nil && !b.volumePatched(w, i) {
				add(w.Owner)
			}
		}
	}
	slices.SortFunc(out, compareRefs)
	return out
}

func (b *builder) otherWorkloads() []load.ObjectRef {
	ai := map[load.ObjectRef]bool{}
	for _, w := range b.in.Workloads {
		if w.IsAI() {
			ai[w.Owner] = true
		}
	}
	var out []load.ObjectRef
	for _, w := range b.in.Workloads {
		ref := w.Owner
		if ai[ref] || !slices.Contains(b.policyNS, ref.Namespace) || owned(b.objects[ref]) || slices.Contains(out, ref) {
			continue
		}
		out = append(out, ref)
	}
	slices.SortFunc(out, compareRefs)
	return out
}

func (b *builder) rayWorkloads() []load.ObjectRef {
	var out []load.ObjectRef
	for _, w := range b.in.Workloads {
		ref := w.Owner
		if !w.HasStack(model.Ray) || !slices.Contains(b.policyNS, ref.Namespace) || owned(b.objects[ref]) || slices.Contains(out, ref) {
			continue
		}
		out = append(out, ref)
	}
	slices.SortFunc(out, compareRefs)
	return out
}

func (b *builder) volumePatched(w model.Workload, i int) bool {
	return slices.ContainsFunc(b.patched(shmCheckID), func(it *item) bool {
		j, ok := volumeIndex(w, it.cf.Path)
		return ok && j == i && it.finding.Object == w.Owner && it.finding.Group == w.Group
	})
}

func (b *builder) helmManaged(ref load.ObjectRef) bool {
	o := b.objects[ref]
	return o != nil && o.U != nil && o.U.GetLabels()[managedByLabel] == managedByHelm
}

func (b *builder) helm(m *manualWriter) {
	var refs, moved []load.ObjectRef
	for _, t := range b.targets {
		if (t.smp != nil || len(t.json) > 0) && b.helmManaged(t.ref) {
			refs = append(refs, t.ref)
		}
	}
	for _, mv := range b.moved {
		if b.helmManaged(mv.owner) && !slices.Contains(moved, mv.owner) {
			moved = append(moved, mv.owner)
		}
	}
	if len(refs) == 0 && len(moved) == 0 {
		return
	}
	m.f("## Helm-managed objects\n\n")
	if len(moved) > 0 {
		m.f("These objects carry the label `%s: %s`. ", managedByLabel, managedByHelm)
		m.f("kshield moved literal secret values of these objects to Secrets in `base/manifests.yaml` only:\n\n")
		for _, r := range moved {
			m.f("- %s\n", code(r.String()))
		}
		m.f("\nHelm renders the literal values again at every upgrade, and the post-renderer plugin uses the output of Helm, so the move does not reach the cluster. ")
		m.f("A JSON 6902 `test` op on an `args` or `command` item that held such a value does not match that output, and the build fails. ")
		m.f("Move each value out of the chart values into a Secret first (many charts have an `existingSecret` value or take `env` items with `valueFrom.secretKeyRef`), ")
		m.f("then render, scan and run `kshield remediate` again.\n\n")
	}
	if len(refs) > 0 {
		helmPatches(m, refs)
	}
}

func helmPatches(m *manualWriter, refs []load.ObjectRef) {
	m.f("These objects carry the label `%s: %s`:\n\n", managedByLabel, managedByHelm)
	for _, r := range refs {
		m.f("- %s\n", code(r.String()))
	}
	m.f("\nDo not patch them with step 1 of \"Rollout order\": the next `helm upgrade` renders the chart again and reverts the patches. ")
	m.f("Apply the patches at every `helm upgrade` through a Helm post-renderer plugin instead. ")
	m.f("Helm 4 takes the name of a `postrenderer/v1` plugin in `--post-renderer`, not a path, and passes each `--post-renderer-args` value to the plugin command as an argument. ")
	m.f("The plugin below puts the output of Helm in place of `base/manifests.yaml` and runs `kustomize build` with `kustomization.yaml` and the patches of this bundle. ")
	m.f("kshield checked it with the Helm and kustomize versions pinned in kshield `versions.env`.\n\n")
	m.f("1. Scan each Helm release on its own. Render it with the release name, namespace and values of the release, scan it with the same namespace, and run `kshield remediate` on that scan:\n\n")
	m.f("```sh\n%s```\n\n", helmScanSteps)
	m.f("A strategic merge patch whose object is not in the output of Helm makes `kustomize build` fail. ")
	m.f("A JSON 6902 patch whose object is not there is skipped with no error. So use a bundle only with the release it was made from.\n\n")
	m.f("2. Create the plugin directory %s with two files.\n\n", code(helmPluginDir))
	m.f("%s:\n\n```yaml\n%s```\n\n", code(helmPluginDir+"/plugin.yaml"), helmPluginYAML)
	m.f("%s:\n\n```bash\n%s```\n\n", code(helmPluginDir+"/postrender.sh"), helmPostRenderScript)
	m.f("The script first sets `metadata.namespace` to the release namespace on each object without one, as `helm upgrade -n` does, so the patch targets match. ")
	m.f("kustomize also sets that namespace on every cluster-scoped custom resource (for example `ClusterServingRuntime`). ")
	m.f("Only the `helm template` output of step 4 shows it: `helm upgrade` and the API server drop the namespace of a cluster-scoped object on apply.\n\n")
	m.f("3. Install the plugin. `helm plugin install` links the plugin directory, so keep the directory in place. `kustomize` must be on the `PATH` of `helm`.\n\n")
	m.f("```sh\nchmod +x %s/postrender.sh\nhelm plugin install ./%s\n```\n\n", helmPluginDir, helmPluginDir)
	m.f("4. Check the output, then upgrade with the same flags:\n\n")
	m.f("```sh\nhelm template <release> <chart> -n <namespace> -f <values.yaml> %s\n", helmPostRenderFlags)
	m.f("helm upgrade <release> <chart> -n <namespace> -f <values.yaml> %s\n```\n\n", helmPostRenderFlags)
	m.f("5. Keep the bundle dir: every `helm upgrade` needs it. After a change of the chart or the values, render, scan and run `kshield remediate` again. ")
	m.f("A JSON 6902 `test` op that does not match the new output of Helm makes `kustomize build` fail, so the upgrade stops with an error.\n\n")
	m.f("The plugin does not apply `infrastructure-policies.yaml`. Apply it as in step 2 of \"Rollout order\".\n\n")
}

func (b *builder) residuals(m *manualWriter) {
	m.f("## Residual items\n\n")
	n := 0
	for _, it := range b.items {
		if it.action != ActionManual || !it.residual {
			continue
		}
		if n == 0 {
			m.f("kshield could not fix these findings automatically. Fix each one by hand; the reason says why.\n\n")
		}
		n++
		m.f("- %s %s: %s\n", code(it.checkID), findingLine(it.finding), it.reason)
	}
	if n == 0 {
		m.f("None.\n")
	}
	m.f("\n")
}

func (b *builder) manualItems(m *manualWriter) {
	m.f("## Manual items\n")
	var ids []string
	for _, it := range b.items {
		if it.action == ActionManual && !it.residual && !slices.Contains(ids, it.checkID) {
			ids = append(ids, it.checkID)
		}
	}
	if len(ids) == 0 {
		m.f("\nNone.\n")
		return
	}
	for _, id := range ids {
		var title, display string
		for _, it := range b.items {
			if it.checkID == id {
				title, display = it.title, it.display
				break
			}
		}
		m.f("\n### %s (%s): %s\n\n%s\n\n", id, display, title, manualSteps[id])
		for _, it := range b.items {
			if it.checkID != id || it.action != ActionManual || it.residual {
				continue
			}
			m.f("- %s: %s\n", findingLine(it.finding), it.finding.Message)
			if it.reason != "" {
				m.f("  - %s\n", it.reason)
			}
		}
	}
}
