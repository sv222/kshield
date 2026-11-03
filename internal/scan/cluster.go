package scan

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/report"
)

const (
	podSpecPath   = "/spec"
	LivePodPrefix = report.LivePodPrefix
)

type ClusterOptions struct {
	ProfileID     string
	Deterministic bool
	Now           func() time.Time
	Info          report.ClusterInfo
	Errors        []string
	Failed        []cluster.FailedRead
	Kubeconfig    string
	Context       string
	Namespaces    []string
	NodeProbe     bool
	Probe         cluster.ProbeOptions
	Client        *cluster.Client
}

func CheckProfile(id string) error {
	p, err := profile.Load(id)
	if err != nil {
		return err
	}
	return validate(p, check.All())
}

func Cluster(ctx context.Context, opt ClusterOptions) (*report.Report, []load.Object, error) {
	if err := CheckProfile(opt.ProfileID); err != nil {
		return nil, nil, err
	}
	c := opt.Client
	if c == nil {
		var err error
		if c, err = cluster.Connect(opt.Kubeconfig, opt.Context); err != nil {
			return nil, nil, err
		}
	}
	snap, err := cluster.Read(ctx, c, cluster.ReadOptions{Namespaces: opt.Namespaces})
	if err != nil {
		return nil, nil, err
	}
	var facts *check.ClusterFacts
	errs := slices.Concat(opt.Errors, snap.Errors)
	info := report.ClusterInfo{
		Context:    c.Context,
		Server:     c.Server,
		Namespaces: slices.Compact(slices.Sorted(slices.Values(opt.Namespaces))),
		NodeProbe:  opt.NodeProbe,
	}
	if opt.NodeProbe {
		probe := opt.Probe
		if probe.Namespace == "" {
			probe.Namespace = cluster.DefaultProbeNamespace
		}
		f, probeErrs := cluster.Probe(ctx, c, probe)
		facts = &f
		errs = append(errs, probeErrs...)
		info.ProbeNamespace = probe.Namespace
	}
	opt.Info = info
	opt.Errors = errs
	opt.Failed = slices.Concat(opt.Failed, snap.Failed)
	r, err := ClusterObjects(snap.Objects, facts, opt)
	if err != nil {
		return nil, nil, err
	}
	return r, snap.Objects, nil
}

func ClusterObjects(objs []load.Object, facts *check.ClusterFacts, opt ClusterOptions) (*report.Report, error) {
	r, _, err := ClusterObjectsInput(objs, facts, opt)
	return r, err
}

func ClusterObjectsInput(objs []load.Object, facts *check.ClusterFacts, opt ClusterOptions) (*report.Report, *check.Input, error) {
	p, err := profile.Load(opt.ProfileID)
	if err != nil {
		return nil, nil, err
	}
	return clusterObjectsInput(objs, facts, opt, p, check.All())
}

func clusterObjects(objs []load.Object, facts *check.ClusterFacts, opt ClusterOptions, p *profile.Profile, checks []check.Check) (*report.Report, error) {
	r, _, err := clusterObjectsInput(objs, facts, opt, p, checks)
	return r, err
}

func clusterObjectsInput(objs []load.Object, facts *check.ClusterFacts, opt ClusterOptions, p *profile.Profile, checks []check.Check) (*report.Report, *check.Input, error) {
	if err := validate(p, checks); err != nil {
		return nil, nil, err
	}
	if facts == nil {
		facts = &check.ClusterFacts{}
	}
	total := len(objs)
	objs, skipped := splitShapes(objs)
	opt.Errors = slices.Concat(opt.Errors, skipped)
	resolved := cluster.Resolve(objs)
	workloads, err := model.Extract(resolved.Objects)
	if err != nil {
		return nil, nil, err
	}
	live, err := newLivePass(objs, resolved, facts)
	if err != nil {
		return nil, nil, err
	}
	in := &check.Input{Objects: resolved.Objects, Workloads: workloads, Cluster: facts}
	info := opt.Info
	info.Namespaces = slices.Clone(info.Namespaces)
	if info.Namespaces == nil {
		info.Namespaces = []string{}
	}
	clock := Options{Deterministic: opt.Deterministic, Now: opt.Now}
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          toolInfo(clock),
		Profile:       report.ProfileInfo{ID: p.ID, Version: p.Version, Title: p.Title, SHA256: p.SHA256},
		Scan: report.ScanInfo{
			Mode:         report.ModeCluster,
			Inputs:       []string{},
			InputDigests: []load.Digest{},
			StartedAt:    startedAt(clock),
			Objects:      total,
			AIWorkloads:  countAI(workloads),
			Cluster:      &info,
		},
		Checks: []report.CheckResult{},
	}
	j := newJudge(opt, objs)
	for _, c := range checks {
		r.Checks = append(r.Checks, checkResult(c, p.Checks[c.ID], j.apply(c, live.merge(c, check.Evaluate(c, in))), nil))
	}
	r.Errors = append(append([]string{}, opt.Errors...), j.extraErrors()...)
	slices.Sort(r.Errors)
	r.Summary = summarize(r.Checks)
	r.Summary.Incomplete = len(r.Errors) > 0
	return r, in, nil
}

func splitShapes(objs []load.Object) ([]load.Object, []string) {
	var errs []string
	kept := make([]load.Object, 0, len(objs))
	for _, o := range objs {
		if _, err := model.Extract([]load.Object{o}); err != nil {
			errs = append(errs, fmt.Sprintf("cluster: read workloads of %s %s: %v", o.Ref.APIVersion, o.Ref, err))
			continue
		}
		kept = append(kept, o)
	}
	return kept, errs
}

type podOwner struct {
	ref      load.ObjectRef
	pod      string
	group    string
	workload *model.Workload
}

type livePass struct {
	in     *check.Input
	owners map[load.ObjectRef]podOwner
	pods   map[load.ObjectRef]model.Workload
}

type findingKey struct {
	object                 load.ObjectRef
	group, container, path string
	onPod                  bool
}

func keyOf(f check.Finding) findingKey {
	return findingKey{object: f.Object, group: f.Group, container: f.Container, path: f.Path}
}

func compareRefs(a, b load.ObjectRef) int {
	return cmp.Or(cmp.Compare(a.String(), b.String()), cmp.Compare(a.APIVersion, b.APIVersion))
}

func newLivePass(objs []load.Object, resolved cluster.Resolved, facts *check.ClusterFacts) (*livePass, error) {
	byRef := make(map[load.ObjectRef]load.Object, len(objs))
	for _, o := range objs {
		if _, ok := byRef[o.Ref]; !ok {
			byRef[o.Ref] = o
		}
	}
	lp := &livePass{owners: map[load.ObjectRef]podOwner{}, pods: map[load.ObjectRef]model.Workload{}}
	var pods []load.Object
	for _, ref := range slices.SortedFunc(maps.Keys(resolved.Live), compareRefs) {
		ws, err := model.Extract([]load.Object{byRef[ref]})
		if err != nil {
			return nil, err
		}
		for _, p := range resolved.Live[ref] {
			po := podOwner{ref: ref, pod: p.Ref.Name, group: model.PodGroup(ref, p.U.GetLabels())}
			if i := slices.IndexFunc(ws, func(w model.Workload) bool { return w.Group == po.group }); i >= 0 {
				po.workload = &ws[i]
			}
			lp.owners[p.Ref] = po
			pods = append(pods, p)
		}
	}
	podWorkloads, err := model.Extract(pods)
	if err != nil {
		return nil, err
	}
	for _, w := range podWorkloads {
		lp.pods[w.Owner] = w
	}
	lp.in = &check.Input{Objects: resolved.Objects, Workloads: podWorkloads, Cluster: facts}
	return lp, nil
}

func (lp *livePass) merge(c check.Check, res check.Result) check.Result {
	if len(lp.in.Workloads) == 0 {
		return res
	}
	live := check.Evaluate(c, lp.in)
	if !live.Applicable {
		return res
	}
	if !res.Applicable {
		res.Findings = nil
	}
	seen := make(map[findingKey]bool, len(res.Findings))
	for _, f := range res.Findings {
		seen[keyOf(f)] = true
	}
	added := false
	for _, f := range live.Findings {
		o, ok := lp.owners[f.Object]
		if !ok {
			continue
		}
		m, key := lp.mapFinding(o, f)
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Findings = append(res.Findings, m)
		added = true
	}
	if added {
		res.Applicable = true
		slices.SortStableFunc(res.Findings, check.CompareFindings)
	}
	return res
}

func (lp *livePass) mapFinding(o podOwner, f check.Finding) (check.Finding, findingKey) {
	f.Message = LivePodPrefix + o.pod + ": " + f.Message
	if path, ok := lp.ownerPath(o, f); ok {
		f.Object, f.Group, f.Path = o.ref, o.group, path
		return f, keyOf(f)
	}
	return f, findingKey{object: o.ref, group: o.group, container: f.Container, path: f.Path, onPod: true}
}

func (lp *livePass) ownerPath(o podOwner, f check.Finding) (string, bool) {
	if o.workload == nil {
		return "", false
	}
	rest, ok := under(f.Path, podSpecPath)
	if !ok {
		return f.Path, true
	}
	for _, c := range lp.pods[f.Object].Containers {
		tail, ok := under(f.Path, c.Path)
		if !ok {
			continue
		}
		i := slices.IndexFunc(o.workload.Containers, func(t model.Container) bool { return t.Init == c.Init && t.Spec.Name == c.Spec.Name })
		if i < 0 {
			return "", false
		}
		return o.workload.Containers[i].Path + tail, true
	}
	return o.workload.SpecPath + rest, true
}

func under(path, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	return rest, ok && (rest == "" || strings.HasPrefix(rest, "/"))
}
