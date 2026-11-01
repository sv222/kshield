package scan

import (
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/load"
)

const (
	groupApps       = "apps"
	groupBatch      = "batch"
	groupNetworking = "networking.k8s.io"
	groupRay        = "ray.io"
	groupKServe     = "serving.kserve.io"
	groupCilium     = "cilium.io"
	groupKyverno    = "kyverno.io"

	resConfigMaps  = "configmaps"
	resDaemonSets  = "daemonsets"
	resDeployments = "deployments"

	notJudgedFormat  = "not judged: cannot %s %s %s in %s: %s"
	readFailedReason = "read failed"
	allNamespacesTag = "all namespaces"
	anyNamespace     = "*"
	anyResource      = "*"
)

type dep struct {
	group, resource string
	outOfScope      bool
	prereq          bool
	when            string
}

const inferenceServiceKey = groupKServe + "/InferenceService"

func gr(group, resource string) dep {
	return dep{group: group, resource: resource}
}

func prereqDep(resource string) dep {
	return dep{group: groupApps, resource: resource, prereq: true}
}

var (
	workloadDeps = []dep{
		gr("", "pods"),
		gr(groupApps, resDeployments),
		gr(groupApps, "statefulsets"),
		gr(groupApps, resDaemonSets),
		gr(groupApps, "replicasets"),
		gr(groupBatch, "jobs"),
		gr(groupBatch, "cronjobs"),
		gr(groupRay, "rayclusters"),
		gr(groupRay, "rayservices"),
		gr(groupRay, "rayjobs"),
		gr(groupKServe, "inferenceservices"),
		gr(groupKServe, "servingruntimes"),
		{group: groupKServe, resource: "clusterservingruntimes", when: inferenceServiceKey},
	}
	exposureDeps = []dep{
		gr("", "services"),
		gr(groupNetworking, "ingresses"),
	}
	policyDeps = []dep{
		gr(groupNetworking, "networkpolicies"),
		gr(groupCilium, "ciliumnetworkpolicies"),
		gr(groupCilium, "ciliumclusterwidenetworkpolicies"),
	}
	tracingDeps = []dep{
		gr(groupCilium, "tracingpolicies"),
		gr(groupCilium, "tracingpoliciesnamespaced"),
	}
	kyvernoDeps = []dep{
		gr(groupKyverno, "policies"),
		gr(groupKyverno, "clusterpolicies"),
		gr("", "namespaces"),
	}
	configDeps = []dep{gr("", resConfigMaps)}
)

func deps(lists ...[]dep) []dep {
	return slices.Concat(append([][]dep{workloadDeps}, lists...)...)
}

var clusterDeps = map[string][]dep{
	"KS-WL-001":  deps(),
	"KS-WL-002":  deps(),
	"KS-WL-003":  deps(),
	"KS-WL-004":  deps(),
	"KS-WL-005":  deps(),
	"KS-WL-006":  deps(),
	"KS-WL-007":  deps(),
	"KS-WL-008":  deps(),
	"KS-WL-009":  deps(),
	"KS-WL-010":  deps([]dep{gr("", "serviceaccounts")}),
	"KS-WL-014":  deps(),
	"KS-AI-004":  deps(exposureDeps, configDeps),
	"KS-AI-005":  deps(exposureDeps),
	"KS-AI-006":  deps(),
	"KS-AI-007":  deps(exposureDeps),
	"KS-AI-008":  deps(configDeps),
	"KS-AI-009":  deps(configDeps),
	"KS-NET-001": deps(policyDeps),
	"KS-NET-002": deps(policyDeps),
	"KS-NET-003": deps([]dep{prereqDep(resDaemonSets), {group: "", resource: resConfigMaps, outOfScope: true}}),
	"KS-RT-001":  deps(tracingDeps),
	"KS-RT-002":  deps(tracingDeps),
	"KS-RT-003":  deps(kyvernoDeps),
	"KS-PRE-001": deps([]dep{prereqDep(resDaemonSets)}),
	"KS-PRE-002": deps([]dep{prereqDep(resDaemonSets)}),
	"KS-PRE-003": deps([]dep{prereqDep(resDeployments)}),
	"KS-PRE-004": deps(),
}

type judge struct {
	failed     []cluster.FailedRead
	kinds      map[string]bool
	errs       []string
	namespaces []string
	extra      []string
	reasons    map[cluster.FailedRead]failure
}

type failure struct {
	verb, reason string
}

func newJudge(opt ClusterOptions, objs []load.Object) *judge {
	kinds := map[string]bool{}
	for _, o := range objs {
		gk := schema.FromAPIVersionAndKind(o.Ref.APIVersion, o.Ref.Kind).GroupKind()
		kinds[gk.Group+"/"+gk.Kind] = true
	}
	return &judge{
		failed:     opt.Failed,
		kinds:      kinds,
		errs:       opt.Errors,
		namespaces: opt.Namespaces,
		reasons:    map[cluster.FailedRead]failure{},
	}
}

func (j *judge) inScope(ns string) bool {
	return ns == "" || len(j.namespaces) == 0 || slices.Contains(j.namespaces, ns)
}

func (j *judge) matches(d dep, f cluster.FailedRead) bool {
	switch {
	case d.group != f.Group, f.Resource != "" && f.Resource != d.resource:
		return false
	case d.when != "" && !j.kinds[d.when]:
		return false
	case len(j.namespaces) > 0 && isPrerequisiteList(f):
		return d.prereq
	}
	return d.outOfScope || j.inScope(f.Namespace)
}

func isPrerequisiteList(f cluster.FailedRead) bool {
	return f.Group == groupApps && f.Namespace == "" && (f.Resource == resDaemonSets || f.Resource == resDeployments)
}

func (j *judge) failures(c check.Check) []cluster.FailedRead {
	var out []cluster.FailedRead
	for _, f := range j.failed {
		if slices.ContainsFunc(clusterDeps[c.ID], func(d dep) bool { return j.matches(d, f) }) {
			out = append(out, f)
		}
	}
	return out
}

func (j *judge) reason(f cluster.FailedRead) failure {
	if r, ok := j.reasons[f]; ok {
		return r
	}
	verb, reason, ok := f.Match(j.errs)
	if !ok {
		reason = readFailedReason
		j.extra = append(j.extra, f.Prefix()+reason)
	}
	r := failure{verb: verb, reason: reason}
	j.reasons[f] = r
	return r
}

func (j *judge) apply(c check.Check, res check.Result) check.Result {
	fails := j.failures(c)
	if len(fails) == 0 {
		return res
	}
	out := check.Result{Applicable: true}
	for _, f := range fails {
		out.Findings = append(out.Findings, j.finding(f))
	}
	slices.SortStableFunc(out.Findings, check.CompareFindings)
	return out
}

func (j *judge) finding(f cluster.FailedRead) check.Finding {
	name, where := anyNamespace, allNamespacesTag
	if f.Namespace != "" {
		name, where = f.Namespace, f.Namespace
	}
	resource := f.Resource
	if resource == "" {
		resource = anyResource
	}
	gv := schema.GroupVersion{Group: f.Group, Version: f.Version}
	why := j.reason(f)
	return check.Finding{
		Object:   load.ObjectRef{APIVersion: "v1", Kind: "Namespace", Name: name},
		Message:  fmt.Sprintf(notJudgedFormat, why.verb, gv, resource, where, why.reason),
		Strength: check.Unknown,
	}
}

func (j *judge) extraErrors() []string {
	return slices.Clone(j.extra)
}
