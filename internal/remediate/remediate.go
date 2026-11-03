package remediate

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/model"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const (
	RemediationSchema = "kshield.remediation/v1"

	ActionPatch  = "patch"
	ActionPolicy = "policy"
	ActionManual = "manual"

	FileBase          = "base/manifests.yaml"
	FileWorkloadPatch = "workload-patch.yaml"
	Dir6902           = "workload-patch-6902"
	FileKustomization = "kustomization.yaml"
	FilePolicies      = "infrastructure-policies.yaml"
	FileRemediation   = "remediation.json"
	FileManual        = "MANUAL.md"

	stdinInput    = "-"
	coreGroup     = "core"
	noNamespace   = "_"
	fileSeparator = ","

	probeOnlyCheck = "KS-PRE-004"
	kindPod        = "Pod"

	reasonPodOwner  = "a running Pod cannot be changed in place; change its owner %s"
	reasonPodSource = "a running Pod cannot be changed in place; change its source (it has no owner)"
	reasonPodGone   = "a running Pod cannot be changed in place, and %s is not in the cluster any more; change the owner or source that created it"

	reasonNoNamespace = "the object has no namespace; kshield writes namespaced policies only; cover it by hand"
	reasonConflict    = "the fix could not be rendered together with the other fixes of the object: %v"
	reasonOwnedIn     = "%s has metadata.ownerReferences, so its controller reverts a patch; fix the owner %s instead"
	reasonOwnedOut    = "%s has metadata.ownerReferences, so its controller reverts a patch; fix the owner %s by hand (it is not in the input)"
	reasonKeptPolicy  = "an existing %s/%s already has this name; audit mode never changes it; switch it to enforce by hand or run with --mode enforce"
)

var (
	ErrIncomplete   = errors.New("the scan in scan.json is incomplete (summary.incomplete: true)")
	ErrMismatch     = errors.New("scan.json does not match the inputs")
	ErrClusterFiles = errors.New("remediate: a cluster scan cannot be matched to files; scan the files with scan manifest")

	checkPolicies = map[string]load.ObjectRef{
		"KS-NET-001": {APIVersion: ciliumAPIVersion, Kind: kindCNP, Name: egressPolicyName},
		"KS-RT-001":  {APIVersion: tetragonAPIVersion, Kind: kindTracingNS, Name: shellExecPolicyName},
		"KS-RT-002":  {APIVersion: tetragonAPIVersion, Kind: kindTracingNS, Name: connectPolicyName},
		"KS-RT-003":  {APIVersion: kyvernoAPIVersion, Kind: kindKyvernoPolicy, Name: admissionPolicyName},
	}
)

type Options struct {
	ScanJSON  []byte
	Inputs    []string
	Namespace string
	Mode      string
	AllowFQDN []string
	AllowCIDR []string
	Stdin     io.Reader
	Objects   []load.Object
}

type Bundle struct {
	Files map[string][]byte
}

type item struct {
	checkID  string
	display  string
	title    string
	fix      check.Fix
	residual bool
	finding  report.Finding
	cf       check.Finding
	action   string
	file     string
	reason   string
	ops      []Op
}

type patchTarget struct {
	ref   load.ObjectRef
	obj   *load.Object
	items []*item
	smp   map[string]any
	json  []Op
}

type builder struct {
	cluster     bool
	raw         []load.Object
	literalRefs []load.ObjectRef
	mode        string
	scanSum     string
	report      *report.Report
	in          *check.Input
	fix         *check.Input
	fixers      map[string]Fixer
	objects     map[load.ObjectRef]*load.Object
	items       []*item
	targets     []*patchTarget
	policyNS    []string
	policies    []map[string]any
	kept        []load.ObjectRef
	moved       []movedValue
	excluded    []load.ObjectRef
	generated   []load.ObjectRef
	literals    []string
}

type flatFinding struct {
	check     string
	object    load.ObjectRef
	group     string
	container string
	path      string
	verdict   string
}

func Run(opt Options) (*Bundle, error) {
	mode := opt.Mode
	if mode == "" {
		mode = modeAudit
	}
	popt := PolicyOptions{Mode: mode, AllowFQDN: opt.AllowFQDN, AllowCIDR: opt.AllowCIDR}
	if _, err := Policies(nil, popt); err != nil {
		return nil, err
	}
	sr, err := readScan(opt.ScanJSON)
	if err != nil {
		return nil, err
	}
	clusterScan := sr.Scan.Mode == report.ModeCluster
	var rescan *report.Report
	var in *check.Input
	if clusterScan {
		rescan, in, err = clusterRescan(opt, sr)
	} else {
		rescan, in, err = manifestRescan(opt, sr)
	}
	if err != nil {
		return nil, err
	}
	if rescan.Profile.SHA256 != sr.Profile.SHA256 {
		return nil, fmt.Errorf("profile %s: sha256 %s differs from the sha256 %s in scan.json", sr.Profile.ID, rescan.Profile.SHA256, sr.Profile.SHA256)
	}
	var keep func(report.CheckResult, report.Finding) bool
	if clusterScan {
		keep = comparedFinding
	}
	if err := compareScans(sr, rescan, keep); err != nil {
		return nil, err
	}
	if clusterScan {
		rescan = mergeClusterChecks(rescan, sr)
	}
	sum := sha256.Sum256(opt.ScanJSON)
	newBuilder := func(literalRefs []load.ObjectRef) *builder {
		return &builder{
			cluster:     clusterScan,
			mode:        mode,
			scanSum:     hex.EncodeToString(sum[:]),
			report:      rescan,
			in:          in,
			raw:         opt.Objects,
			literalRefs: literalRefs,
			fixers:      Fixers(),
		}
	}
	b := newBuilder(nil)
	if err := b.process(); err != nil {
		return nil, err
	}
	if clusterScan {
		if refs := b.literalTargets(); len(refs) > 0 {
			b = newBuilder(refs)
			if err := b.process(); err != nil {
				return nil, err
			}
		}
	}
	popt.PeerNamespaces, popt.APIServerNamespaces = PolicyPeers(in)
	if b.policies, err = Policies(b.policyNS, popt); err != nil {
		return nil, err
	}
	if mode != modeEnforce {
		b.keepExisting()
	}
	return b.bundle()
}

func (b *builder) process() error {
	b.policyNS = PolicyNamespaces(b.in)
	if err := b.collect(); err != nil {
		return err
	}
	if err := b.redactInput(); err != nil {
		return err
	}
	for _, it := range b.items {
		b.decide(it)
	}
	return b.render()
}

func (b *builder) literalTargets() []load.ObjectRef {
	var out []load.ObjectRef
	for _, f := range b.literalFindings() {
		for _, t := range b.targets {
			if (t.smp != nil || len(t.json) > 0) && t.ref == f.Object && !slices.Contains(out, t.ref) {
				out = append(out, t.ref)
			}
		}
	}
	return out
}

func (b *builder) literalFindings() []check.Finding {
	c, ok := check.ByID(secretEnvCheck)
	if !ok {
		return nil
	}
	return check.Evaluate(c, &check.Input{Objects: b.in.Objects, Workloads: b.in.Workloads}).Findings
}

func manifestRescan(opt Options, sr *report.Report) (*report.Report, *check.Input, error) {
	if len(opt.Objects) > 0 {
		return nil, nil, errors.New("live objects belong to a cluster scan; scan.json is a manifest scan")
	}
	inputs := opt.Inputs
	if len(inputs) == 0 {
		if slices.Contains(sr.Scan.Inputs, stdinInput) {
			return nil, nil, errors.New("scan.json was read from stdin; pass the same manifests again with -f")
		}
		inputs = sr.Scan.Inputs
	}
	if len(inputs) == 0 {
		return nil, nil, errors.New("scan.json lists no inputs; pass the manifests with -f")
	}
	ns := opt.Namespace
	if ns == "" {
		ns = sr.Scan.Namespace
	}
	return scan.ManifestInput(scan.Options{Inputs: inputs, Namespace: ns, ProfileID: sr.Profile.ID, Deterministic: true, Stdin: opt.Stdin})
}

func clusterRescan(opt Options, sr *report.Report) (*report.Report, *check.Input, error) {
	if len(opt.Inputs) > 0 {
		return nil, nil, ErrClusterFiles
	}
	return scan.ClusterObjectsInput(opt.Objects, nil, scan.ClusterOptions{ProfileID: sr.Profile.ID, Deterministic: true})
}

func isPod(ref load.ObjectRef) bool {
	return ref.Kind == kindPod && ref.APIVersion == "v1"
}

func comparedFinding(c report.CheckResult, f report.Finding) bool {
	return c.Fix != string(check.FixManual) && !isPod(f.Object) && !strings.HasPrefix(f.Message, scan.LivePodPrefix)
}

func mergeClusterChecks(rescan, sr *report.Report) *report.Report {
	out := *rescan
	out.Checks = make([]report.CheckResult, len(rescan.Checks))
	for i, c := range rescan.Checks {
		j := slices.IndexFunc(sr.Checks, func(s report.CheckResult) bool { return s.ID == c.ID })
		switch {
		case j < 0:
			out.Checks[i] = c
		case c.Fix == string(check.FixManual):
			out.Checks[i] = sr.Checks[j]
		default:
			m := c
			m.Findings = nil
			for _, f := range c.Findings {
				if !isPod(f.Object) {
					m.Findings = append(m.Findings, f)
				}
			}
			for _, f := range sr.Checks[j].Findings {
				if isPod(f.Object) {
					m.Findings = append(m.Findings, f)
				}
			}
			slices.SortStableFunc(m.Findings, func(a, b report.Finding) int {
				return cmp.Or(cmp.Compare(a.Object.String(), b.Object.String()), cmp.Compare(a.Group, b.Group), cmp.Compare(a.Path, b.Path), cmp.Compare(a.Container, b.Container))
			})
			out.Checks[i] = m
		}
	}
	return &out
}

func (b *builder) keepExisting() {
	var out []map[string]any
	for _, p := range b.policies {
		u := unstructured.Unstructured{Object: p}
		ref := load.ObjectRef{APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName()}
		if b.findObject(ref) != nil {
			b.kept = append(b.kept, ref)
			continue
		}
		out = append(out, p)
	}
	b.policies = out
	for _, it := range b.items {
		ref, ok := checkPolicies[it.checkID]
		if !ok || it.action != ActionPolicy {
			continue
		}
		ref.Namespace = it.finding.Object.Namespace
		if slices.Contains(b.kept, ref) {
			it.action, it.file, it.reason = ActionManual, "", fmt.Sprintf(reasonKeptPolicy, ref.Kind, ref.Name)
		}
	}
}

func (b *builder) bundleNamespaces() []string {
	var out []string
	for _, p := range b.policies {
		u := unstructured.Unstructured{Object: p}
		if ns := u.GetNamespace(); ns != "" && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	slices.Sort(out)
	return out
}

func ReadScan(data []byte) (*report.Report, error) {
	return readScan(data)
}

func readScan(data []byte) (*report.Report, error) {
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("scan.json: %w", err)
	}
	if r.SchemaVersion != report.SchemaVersion {
		return nil, fmt.Errorf("scan.json: schemaVersion %q, want %s", r.SchemaVersion, report.SchemaVersion)
	}
	switch r.Scan.Mode {
	case report.ModeManifest:
	case report.ModeCluster:
	default:
		return nil, fmt.Errorf("scan.json: unknown scan mode %q", r.Scan.Mode)
	}
	if r.Summary.Incomplete {
		return nil, ErrIncomplete
	}
	return &r, nil
}

func flatten(r *report.Report, keep func(report.CheckResult, report.Finding) bool) []flatFinding {
	var out []flatFinding
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if keep != nil && !keep(c, f) {
				continue
			}
			out = append(out, flatFinding{c.ID, f.Object, f.Group, f.Container, f.Path, f.Verdict})
		}
	}
	return out
}

func compareScans(want, got *report.Report, keep func(report.CheckResult, report.Finding) bool) error {
	a, b := flatten(want, keep), flatten(got, keep)
	for i := range max(len(a), len(b)) {
		if i < len(a) && i < len(b) && a[i] == b[i] {
			continue
		}
		var f flatFinding
		if i < len(a) {
			f = a[i]
		} else {
			f = b[i]
		}
		return fmt.Errorf("%w: %s %s %s", ErrMismatch, f.check, f.object, f.path)
	}
	for i := range max(len(want.Checks), len(got.Checks)) {
		switch {
		case i >= len(want.Checks):
			return fmt.Errorf("%w: check %s is not in scan.json", ErrMismatch, got.Checks[i].ID)
		case i >= len(got.Checks):
			return fmt.Errorf("%w: check %s is not in this kshield", ErrMismatch, want.Checks[i].ID)
		case want.Checks[i].ID != got.Checks[i].ID:
			return fmt.Errorf("%w: check %s", ErrMismatch, want.Checks[i].ID)
		}
	}
	return nil
}

func (b *builder) collect() error {
	for _, cr := range b.report.Checks {
		findings := cr.Findings
		if cr.ID == secretEnvCheck {
			extra, err := b.literalReportFindings()
			if err != nil {
				return err
			}
			findings = slices.Concat(findings, extra)
		}
		if len(findings) == 0 {
			continue
		}
		c, ok := check.ByID(cr.ID)
		if !ok {
			return fmt.Errorf("check %s is not in the catalog", cr.ID)
		}
		var cfs []check.Finding
		if b.cluster {
			cfs = checkFindings(findings)
		} else {
			cfs = check.Evaluate(c, b.in).Findings
		}
		if len(cfs) != len(findings) {
			return fmt.Errorf("check %s: %d findings on the second run, %d in the report", cr.ID, len(cfs), len(findings))
		}
		for i, f := range findings {
			it := &item{checkID: cr.ID, display: cr.Display, title: cr.Title, fix: c.Fix, finding: f, cf: cfs[i], action: ActionManual}
			b.items = append(b.items, it)
		}
	}
	return nil
}

func (b *builder) literalReportFindings() ([]report.Finding, error) {
	if !b.cluster || len(b.literalRefs) == 0 {
		return nil, nil
	}
	p, err := profile.Load(b.report.Profile.ID)
	if err != nil {
		return nil, err
	}
	var out []report.Finding
	for _, f := range b.literalFindings() {
		if !slices.Contains(b.literalRefs, f.Object) {
			continue
		}
		out = append(out, report.Finding{
			Object:    f.Object,
			Group:     f.Group,
			Container: f.Container,
			Path:      f.Path,
			Message:   f.Message,
			Verdict:   scan.FindingVerdict(p.Checks[secretEnvCheck].Severity, f.Strength),
		})
	}
	return out, nil
}

func checkFindings(fs []report.Finding) []check.Finding {
	out := make([]check.Finding, len(fs))
	for i, f := range fs {
		out[i] = check.Finding{Object: f.Object, Group: f.Group, Container: f.Container, Path: f.Path, Message: f.Message}
	}
	return out
}

func (b *builder) decide(it *item) {
	f := it.finding
	fixer := b.fixers[it.checkID]
	it.residual = fixer != nil || it.fix != check.FixManual
	obj := b.objects[f.Object]
	if b.cluster && isPod(f.Object) && (fixer != nil || it.fix != check.FixPolicy) {
		it.reason = b.podReason(f.Object)
		return
	}
	if (fixer != nil || it.fix != check.FixPolicy) && owned(obj) {
		it.reason = b.ownedReason(obj)
		return
	}
	switch {
	case fixer != nil:
		ops, res := fixer(findWorkload(b.fix, f, obj), it.cf, b.fix, b.mode)
		if res != nil {
			it.reason = res.Reason
			return
		}
		it.action, it.ops = ActionPatch, ops
		b.addTarget(obj, it)
	case it.fix == check.FixPolicy:
		if f.Object.Namespace != "" && slices.Contains(b.policyNS, f.Object.Namespace) {
			it.action, it.file = ActionPolicy, FilePolicies
			return
		}
		it.reason = reasonNoNamespace
	}
}

func findWorkload(in *check.Input, f report.Finding, obj *load.Object) model.Workload {
	for _, w := range in.Workloads {
		if w.Owner == f.Object && w.Group == f.Group {
			return w
		}
	}
	return model.Workload{Owner: f.Object, Object: obj}
}

func (b *builder) ownedReason(obj *load.Object) string {
	cur := obj
	seen := map[load.ObjectRef]bool{obj.Ref: true}
	for {
		ref, ok := controllerRef(cur)
		if !ok {
			return fmt.Sprintf(reasonOwnedIn, obj.Ref, cur.Ref)
		}
		next := b.findObject(ref)
		if next == nil {
			return fmt.Sprintf(reasonOwnedOut, obj.Ref, ref)
		}
		if seen[next.Ref] {
			return fmt.Sprintf(reasonOwnedOut, obj.Ref, ref)
		}
		seen[next.Ref] = true
		cur = next
	}
}

func controllerRef(o *load.Object) (load.ObjectRef, bool) {
	refs := o.U.GetOwnerReferences()
	if len(refs) == 0 {
		return load.ObjectRef{}, false
	}
	r := refs[0]
	for _, x := range refs {
		if x.Controller != nil && *x.Controller {
			r = x
			break
		}
	}
	ref := load.ObjectRef{APIVersion: r.APIVersion, Kind: r.Kind, Name: r.Name}
	if !load.IsClusterScoped(r.Kind) {
		ref.Namespace = o.Ref.Namespace
	}
	return ref, true
}

func (b *builder) findObject(ref load.ObjectRef) *load.Object {
	return findIn(b.in.Objects, ref)
}

func findIn(objs []load.Object, ref load.ObjectRef) *load.Object {
	for i := range objs {
		o := &objs[i]
		if o.U != nil && o.Ref.Kind == ref.Kind && o.Ref.Name == ref.Name && o.Ref.Namespace == ref.Namespace && apiGroupOf(o.Ref.APIVersion) == apiGroupOf(ref.APIVersion) {
			return o
		}
	}
	return nil
}

func (b *builder) podReason(pod load.ObjectRef) string {
	cur := findIn(b.raw, pod)
	if cur == nil {
		return fmt.Sprintf(reasonPodGone, pod)
	}
	seen := map[load.ObjectRef]bool{cur.Ref: true}
	var top load.ObjectRef
	for {
		ref, ok := controllerRef(cur)
		if !ok {
			break
		}
		top = ref
		next := findIn(b.raw, ref)
		if next == nil || seen[next.Ref] {
			break
		}
		seen[next.Ref] = true
		cur = next
	}
	if top == (load.ObjectRef{}) {
		return reasonPodSource
	}
	return fmt.Sprintf(reasonPodOwner, top)
}

func (b *builder) addTarget(obj *load.Object, it *item) {
	for _, t := range b.targets {
		if t.ref == obj.Ref {
			t.items = append(t.items, it)
			return
		}
	}
	b.targets = append(b.targets, &patchTarget{ref: obj.Ref, obj: obj, items: []*item{it}})
}

func compareRefs(a, b load.ObjectRef) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.APIVersion, b.APIVersion),
	)
}

func (b *builder) render() error {
	slices.SortStableFunc(b.targets, func(x, y *patchTarget) int { return compareRefs(x.ref, y.ref) })
	for _, t := range b.targets {
		var all []Op
		for _, it := range t.items {
			all = append(all, it.ops...)
		}
		smp, j, err := Render(Target{Ref: t.ref, Original: t.obj.U.Object, Ops: all})
		if err != nil {
			var acc []Op
			for _, it := range t.items {
				trial := slices.Concat(acc, it.ops)
				if _, _, err := Render(Target{Ref: t.ref, Original: t.obj.U.Object, Ops: trial}); err != nil {
					it.action, it.ops, it.reason = ActionManual, nil, fmt.Sprintf(reasonConflict, err)
					continue
				}
				acc = trial
			}
			if smp, j, err = Render(Target{Ref: t.ref, Original: t.obj.U.Object, Ops: acc}); err != nil {
				return err
			}
		}
		t.smp, t.json = smp, j
		for _, it := range t.items {
			if it.action == ActionPatch {
				it.file = t.fileFor(it.ops)
			}
		}
	}
	return nil
}

func (t *patchTarget) fileFor(ops []Op) string {
	in6902, inSMP := false, false
	for _, op := range ops {
		if slices.ContainsFunc(t.json, func(q Op) bool {
			return q.Op != OpTest && (under(op.Path, q.Path) || under(q.Path, op.Path))
		}) {
			in6902 = true
		} else {
			inSMP = true
		}
	}
	switch {
	case in6902 && inSMP:
		return patchFileName(t.ref) + fileSeparator + FileWorkloadPatch
	case in6902:
		return patchFileName(t.ref)
	}
	return FileWorkloadPatch
}

func splitAPIVersion(apiVersion string) (string, string) {
	group, version, found := strings.Cut(apiVersion, "/")
	if !found {
		return "", group
	}
	return group, version
}

func patchFileName(ref load.ObjectRef) string {
	group, _ := splitAPIVersion(ref.APIVersion)
	if group == "" {
		group = coreGroup
	}
	ns := ref.Namespace
	if ns == "" {
		ns = noNamespace
	}
	return Dir6902 + "/" + strings.Join([]string{group, ref.Kind, ns, ref.Name}, "_") + ".yaml"
}
