package remediate

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/model"
)

const (
	tmpDir           = "/tmp"
	shmDir           = "/dev/shm"
	devDir           = "/dev"
	dropAll          = "ALL"
	netBindService   = "NET_BIND_SERVICE"
	runtimeDefault   = "RuntimeDefault"
	gpuCheckID       = "KS-WL-014"
	rayGroup         = "ray.io"
	rayHeadGroup     = "head"
	rayHeadSpec      = "/headGroupSpec/template/spec"
	reasonGPU        = "privileged is used for GPU access; move to the NVIDIA device plugin first"
	reasonDev        = "hostPath /dev also carries devices; replace it by hand"
	reasonAutoscaler = "the Ray autoscaler needs the API token"
	reasonRootMount  = "a volume is mounted under /root; a non-root user cannot reach it; move the mount out of /root and point HOME/HF_HOME/OLLAMA_MODELS at it first"
	reasonRootROFS   = "a volume is mounted under /root and the process keeps HOME=/root; a read-only root filesystem would block writes there; move the mount out of /root first"
	reasonRuntimeSA  = "ServingRuntime has no automountServiceAccountToken; set automountServiceAccountToken: false on the ServiceAccount the InferenceService uses"
	rootDir          = "/root"
	kserveGroup      = "serving.kserve.io"
)

var sysAdmin = []string{"SYS_ADMIN", "CAP_SYS_ADMIN"}

type envDefault struct {
	name, value string
}

var cacheEnv = []envDefault{
	{"HOME", CacheDir},
	{"HF_HOME", CacheDir + "/huggingface"},
	{"XDG_CACHE_HOME", CacheDir + "/xdg"},
}

type writableDir struct {
	volume, path string
}

var baseDirs = []writableDir{
	{"kshield-tmp", tmpDir},
	{"kshield-cache", CacheDir},
}

var stackDirs = map[model.Stack][]writableDir{
	model.Qdrant: {{"kshield-qdrant-storage", "/qdrant/storage"}, {"kshield-qdrant-snapshots", "/qdrant/snapshots"}},
	model.Milvus: {{"kshield-milvus-data", "/var/lib/milvus"}},
	model.Ollama: {{"kshield-ollama", "/root/.ollama"}},
}

const milvusMeasuredImage = "milvusdb/milvus:v3.0.3"

var stackUID = map[model.Stack]int64{
	model.Milvus: 999,
}

func nonRootUID(stacks ...model.Stack) int64 {
	for _, s := range stacks {
		if uid, ok := stackUID[s]; ok {
			return uid
		}
	}
	return NonRootUID
}

func securityContextPath(c model.Container) string {
	return c.Path + "/securityContext"
}

func fixRunAsRoot(w model.Workload, c model.Container, _ *check.Input) ([]Op, string) {
	if mountsUnder(c, rootDir) {
		return nil, reasonRootMount
	}
	obj := w.Object.U.Object
	sc := securityContextPath(c)
	var ops []Op
	if s := c.Spec.SecurityContext; s == nil || s.RunAsNonRoot == nil || !*s.RunAsNonRoot {
		ops = append(ops, Set(obj, sc+"/runAsNonRoot", true))
	}
	if uid := runAsUser(w, c); uid == nil || *uid == 0 {
		ops = append(ops, Set(obj, sc+"/runAsUser", nonRootUID(c.Stack)))
		if gid := runAsGroup(w, c); gid == nil || *gid == 0 {
			ops = append(ops, Set(obj, sc+"/runAsGroup", nonRootUID(c.Stack)))
		}
	}
	if !servingRuntime(w) && hasClaim(w) && (w.Spec.SecurityContext == nil || w.Spec.SecurityContext.FSGroup == nil) {
		ops = append(ops, Set(obj, w.SpecPath+"/securityContext/fsGroup", nonRootUID(w.Stacks...)))
	}
	return ops, ""
}

func runAsUser(w model.Workload, c model.Container) *int64 {
	if s := c.Spec.SecurityContext; s != nil && s.RunAsUser != nil {
		return s.RunAsUser
	}
	if s := w.Spec.SecurityContext; s != nil {
		return s.RunAsUser
	}
	return nil
}

func runAsGroup(w model.Workload, c model.Container) *int64 {
	if s := c.Spec.SecurityContext; s != nil && s.RunAsGroup != nil {
		return s.RunAsGroup
	}
	if s := w.Spec.SecurityContext; s != nil {
		return s.RunAsGroup
	}
	return nil
}

func hasClaim(w model.Workload) bool {
	if slices.ContainsFunc(w.Spec.Volumes, func(v corev1.Volume) bool {
		return v.PersistentVolumeClaim != nil || v.Ephemeral != nil
	}) {
		return true
	}
	return len(claimTemplateNames(w)) > 0
}

func claimTemplateNames(w model.Workload) []string {
	if w.Owner.Kind != "StatefulSet" || apiGroupOf(w.Owner.APIVersion) != "apps" {
		return nil
	}
	list, _ := lookupPath(w.Object.U.Object, "/spec/volumeClaimTemplates").([]any)
	var out []string
	for _, item := range list {
		m, _ := item.(map[string]any)
		md, _ := m["metadata"].(map[string]any)
		if name, ok := md["name"].(string); ok {
			out = append(out, name)
		}
	}
	return out
}

func fixPrivileged(w model.Workload, c model.Container, in *check.Input) ([]Op, string) {
	obj := w.Object.U.Object
	sc := securityContextPath(c)
	s := c.Spec.SecurityContext
	privileged := s != nil && s.Privileged != nil && *s.Privileged
	if privileged && usesGPU(w, c, in) {
		return nil, reasonGPU
	}
	var ops []Op
	if s == nil || s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation {
		ops = append(ops, Set(obj, sc+"/allowPrivilegeEscalation", false))
	}
	if privileged {
		ops = append(ops, Set(obj, sc+"/privileged", false))
	}
	if s != nil && s.Capabilities != nil && slices.ContainsFunc(s.Capabilities.Add, func(a corev1.Capability) bool {
		return slices.ContainsFunc(sysAdmin, func(n string) bool { return strings.EqualFold(string(a), n) })
	}) {
		ops = append(ops, capAddOps(obj, sc+"/capabilities", s.Capabilities)...)
	}
	return ops, ""
}

func usesGPU(w model.Workload, c model.Container, in *check.Input) bool {
	gpu, ok := check.ByID(gpuCheckID)
	if in == nil || !ok {
		return false
	}
	mounts := map[string]bool{}
	for _, m := range c.Spec.VolumeMounts {
		mounts[m.Name] = true
	}
	for _, f := range check.Evaluate(gpu, in).Findings {
		if f.Object != w.Owner || f.Group != w.Group {
			continue
		}
		if strings.HasPrefix(f.Path, c.Path+"/") {
			return true
		}
		if i, ok := volumeIndex(w, f.Path); ok && mounts[w.Spec.Volumes[i].Name] {
			return true
		}
	}
	return false
}

func fixCapabilities(w model.Workload, c model.Container, _ *check.Input) ([]Op, string) {
	obj := w.Object.U.Object
	p := securityContextPath(c) + "/capabilities"
	var caps *corev1.Capabilities
	if s := c.Spec.SecurityContext; s != nil {
		caps = s.Capabilities
	}
	var ops []Op
	if caps == nil || !slices.ContainsFunc(caps.Drop, func(d corev1.Capability) bool { return strings.EqualFold(string(d), dropAll) }) {
		ops = append(ops, Set(obj, p+"/drop", []any{dropAll}))
	}
	if caps == nil {
		return ops, ""
	}
	return append(ops, capAddOps(obj, p, caps)...), ""
}

func capAddOps(obj map[string]any, p string, caps *corev1.Capabilities) []Op {
	var kept []any
	extra := false
	for _, a := range caps.Add {
		if string(a) == netBindService {
			kept = append(kept, string(a))
		} else {
			extra = true
		}
	}
	switch {
	case !extra:
		return nil
	case len(kept) == 0:
		return []Op{Remove(p + "/add")}
	}
	return []Op{Set(obj, p+"/add", kept)}
}

func fixHostNamespaces(w model.Workload, f check.Finding, _ *check.Input, _ string) ([]Op, string) {
	switch field := strings.TrimPrefix(f.Path, w.SpecPath+"/"); field {
	case "hostPID", "hostNetwork":
		if servingRuntime(w) {
			return nil, runtimeLacks(w, field)
		}
		fallthrough
	case "hostIPC":
		return []Op{Set(w.Object.U.Object, w.SpecPath+"/"+field, false)}, ""
	}
	return nil, "the finding path " + f.Path + " names no host namespace field of the workload"
}

func fixShmHostPath(w model.Workload, f check.Finding, _ *check.Input, _ string) ([]Op, string) {
	i, ok := volumeIndex(w, f.Path)
	if !ok || w.Spec.Volumes[i].HostPath == nil {
		return nil, "the finding path " + f.Path + " names no hostPath volume of the workload"
	}
	v := w.Spec.Volumes[i]
	switch p := path.Clean(v.HostPath.Path); {
	case p == devDir:
		return nil, reasonDev
	case p != shmDir:
		return nil, fmt.Sprintf("hostPath %s is not %s itself; replace it by hand", v.HostPath.Path, shmDir)
	}
	for _, c := range w.Containers {
		for _, m := range c.Spec.VolumeMounts {
			if m.Name == v.Name && path.Clean(m.MountPath) != shmDir {
				return nil, fmt.Sprintf("volume %q is also mounted outside %s; replace it by hand", v.Name, shmDir)
			}
		}
	}
	vp := w.SpecPath + "/volumes/" + strconv.Itoa(i)
	return []Op{
		Remove(vp + "/hostPath"),
		Set(w.Object.U.Object, vp+"/emptyDir", map[string]any{"medium": string(corev1.StorageMediumMemory), "sizeLimit": shmSize(w, v.Name)}),
	}, ""
}

func fixShmSizeLimit(w model.Workload, f check.Finding, _ *check.Input, _ string) ([]Op, string) {
	i, ok := volumeIndex(w, f.Path)
	if !ok || w.Spec.Volumes[i].EmptyDir == nil {
		return nil, "the finding path " + f.Path + " names no emptyDir volume of the workload"
	}
	p := w.SpecPath + "/volumes/" + strconv.Itoa(i) + "/emptyDir/sizeLimit"
	return []Op{Set(w.Object.U.Object, p, shmSize(w, w.Spec.Volumes[i].Name))}, ""
}

func shmSize(w model.Workload, volume string) string {
	var best *resource.Quantity
	for _, c := range w.Containers {
		if !slices.ContainsFunc(c.Spec.VolumeMounts, func(m corev1.VolumeMount) bool {
			return m.Name == volume && path.Clean(m.MountPath) == shmDir
		}) {
			continue
		}
		if q, ok := c.Spec.Resources.Limits[corev1.ResourceMemory]; ok && (best == nil || q.Cmp(*best) > 0) {
			best = &q
		}
	}
	if best == nil {
		return DefaultShmSize
	}
	return best.String()
}

func fixShareProcessNamespace(w model.Workload, _ check.Finding, _ *check.Input, _ string) ([]Op, string) {
	if servingRuntime(w) {
		return nil, runtimeLacks(w, "shareProcessNamespace")
	}
	return []Op{Set(w.Object.U.Object, w.SpecPath+"/shareProcessNamespace", false)}, ""
}

func fixReadOnlyRootFS(w model.Workload, c model.Container, in *check.Input) ([]Op, string) {
	if mountsUnder(c, rootDir) {
		return nil, reasonRootROFS
	}
	var added []writableDir
	for _, d := range slices.Concat(baseDirs, stackDirs[c.Stack]) {
		if !mounted(c, d.path) {
			added = append(added, d)
		}
	}
	if reason := readOnlyCacheEnv(c, added); reason != "" {
		return nil, reason
	}
	obj := w.Object.U.Object
	var ops []Op
	if s := c.Spec.SecurityContext; s == nil || s.ReadOnlyRootFilesystem == nil || !*s.ReadOnlyRootFilesystem {
		ops = append(ops, Set(obj, securityContextPath(c)+"/readOnlyRootFilesystem", true))
	}
	taken := volumeNames(w)
	for _, d := range added {
		name := freeName(d.volume, taken)
		ops = append(ops,
			Set(obj, w.SpecPath+"/volumes/-", map[string]any{"name": name, "emptyDir": map[string]any{}}),
			Set(obj, c.Path+"/volumeMounts/-", map[string]any{"name": name, "mountPath": d.path}),
		)
	}
	for _, e := range cacheEnv {
		if !envSet(w, c, in, e.name) {
			ops = append(ops, Set(obj, c.Path+"/env/-", map[string]any{"name": e.name, "value": e.value}))
		}
	}
	return ops, ""
}

func readOnlyCacheEnv(c model.Container, added []writableDir) string {
	var writable []string
	for _, m := range c.Spec.VolumeMounts {
		if !m.ReadOnly {
			writable = append(writable, path.Clean(m.MountPath))
		}
	}
	for _, d := range added {
		writable = append(writable, d.path)
	}
	var reasons []string
	for _, e := range cacheEnv {
		v, ok := literalEnv(c, e.name)
		if !ok {
			continue
		}
		if p := path.Clean(v); !path.IsAbs(p) || !slices.ContainsFunc(writable, func(m string) bool { return under(p, m) }) {
			reasons = append(reasons, fmt.Sprintf("%s points at %s, which becomes read-only; mount a volume there or unset it first", e.name, v))
		}
	}
	return strings.Join(reasons, "; ")
}

func literalEnv(c model.Container, name string) (string, bool) {
	for i := len(c.Spec.Env) - 1; i >= 0; i-- {
		e := c.Spec.Env[i]
		if e.Name != name {
			continue
		}
		if e.ValueFrom != nil || e.Value == "" || strings.Contains(e.Value, "$(") {
			return "", false
		}
		return e.Value, true
	}
	return "", false
}

func mounted(c model.Container, dir string) bool {
	return slices.ContainsFunc(c.Spec.VolumeMounts, func(m corev1.VolumeMount) bool {
		mp := path.Clean(m.MountPath)
		return mp == dir || strings.HasPrefix(dir, mp+"/")
	})
}

func mountsUnder(c model.Container, dir string) bool {
	return slices.ContainsFunc(c.Spec.VolumeMounts, func(m corev1.VolumeMount) bool {
		return under(path.Clean(m.MountPath), dir)
	})
}

func envSet(w model.Workload, c model.Container, in *check.Input, name string) bool {
	if slices.ContainsFunc(c.Spec.Env, func(v corev1.EnvVar) bool { return v.Name == name }) {
		return true
	}
	if len(c.Spec.EnvFrom) == 0 {
		return false
	}
	if in == nil {
		return true
	}
	found, missing := check.EnvFromKey(in, w.Owner.Namespace, c, name)
	return found || len(missing) > 0
}

func volumeNames(w model.Workload) map[string]bool {
	out := map[string]bool{}
	for _, v := range w.Spec.Volumes {
		out[v.Name] = true
	}
	for _, n := range claimTemplateNames(w) {
		out[n] = true
	}
	return out
}

func freeName(base string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		if n := base + "-" + strconv.Itoa(i); !taken[n] {
			return n
		}
	}
}

func fixSeccomp(w model.Workload, c model.Container, _ *check.Input) ([]Op, string) {
	return []Op{Set(w.Object.U.Object, securityContextPath(c)+"/seccompProfile/type", runtimeDefault)}, ""
}

func fixAutomountToken(w model.Workload, _ check.Finding, _ *check.Input, _ string) ([]Op, string) {
	if servingRuntime(w) {
		return nil, reasonRuntimeSA
	}
	if rayAutoscaling(w) {
		return nil, reasonAutoscaler
	}
	return []Op{Set(w.Object.U.Object, w.SpecPath+"/automountServiceAccountToken", false)}, ""
}

func servingRuntime(w model.Workload) bool {
	return apiGroupOf(w.Owner.APIVersion) == kserveGroup && (w.Owner.Kind == "ServingRuntime" || w.Owner.Kind == "ClusterServingRuntime")
}

func runtimeLacks(w model.Workload, field string) string {
	return fmt.Sprintf("%s has no %s field; remove %s from the manifest by hand", w.Owner.Kind, field, field)
}

func rayAutoscaling(w model.Workload) bool {
	if w.Group != rayHeadGroup || apiGroupOf(w.Owner.APIVersion) != rayGroup || !strings.HasSuffix(w.SpecPath, rayHeadSpec) {
		return false
	}
	on, _ := lookupPath(w.Object.U.Object, strings.TrimSuffix(w.SpecPath, rayHeadSpec)+"/enableInTreeAutoscaling").(bool)
	return on
}

func volumeIndex(w model.Workload, p string) (int, bool) {
	rest, ok := strings.CutPrefix(p, w.SpecPath+"/volumes/")
	if !ok {
		return 0, false
	}
	seg, _, _ := strings.Cut(rest, "/")
	i, ok := index(seg)
	return i, ok && i < len(w.Spec.Volumes)
}

func lookupPath(obj map[string]any, p string) any {
	segs, err := splitPath(p)
	if err != nil {
		return nil
	}
	v, _ := lookup(obj, segs)
	return v
}

func apiGroupOf(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}
