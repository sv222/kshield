# Cluster corpus

Every directory under `test/cluster-corpus/` that holds an `expected.yaml` is one case.
`TestClusterCorpus` (`test/cluster_corpus_test.go`) walks all cases and runs the cluster report builder `scan.ClusterObjects` in-process with `--deterministic`, as `kshield scan cluster` does after it has read the cluster.

The corpus lives outside `test/corpus/`, so `TestCorpus` and the remediation re-scan loop never see it.

A case directory has these files:

- `input.yaml` - the objects as the API server returns them: with `metadata.uid`, `metadata.ownerReferences` and, for Pods, `status.phase`.
- `facts.yaml` (optional) - the cluster facts (`check.ClusterFacts`). Without it the facts are empty.
- `expected.yaml` - the ground truth, in the same format as `test/corpus/README.md` describes. Write it by hand from the rules and the input, before you look at scanner output.

```yaml
probeRan: true
nodes:
  - {node: kind-control-plane, lsm: [lockdown, capability, bpf], bpfLSMConfig: "y", unknown: ""}
```

- `probeRan` - the node probe ran.
- `nodes` - one entry per node: `node` (the Node name), `lsm` (the active LSM list), `bpfLSMConfig` (`y`, `n` or empty when unreadable), `unknown` (a reason; not empty means the node could not be judged).

The runner gives the scan one `errors` line `node probe <node>: <reason>` per node with `unknown` set, as the node probe does. Every UNKNOWN finding must have an `errors` line that names its object, and a report with an UNKNOWN finding must be incomplete; the runner fails the case otherwise.

The same rules as the manifest corpus apply: `Manifest`-tier checks are N/A here, a mismatch is a product bug until proven otherwise, and an expected set changes only with a reviewed reason in the pull request.

## Owners

`owners/` pins how a cluster scan picks the object it judges. The controller `ownerReferences` entry is matched by UID and followed up to the top-most owner. Findings name that owner: a Deployment, not its ReplicaSets or Pods. A running Pod that differs from its controller template adds a finding on the controller with the message prefix `live pod <name>:`. A Pod whose controller is not in the input is judged as itself. A live finding that has no real path on the controller (a container the template does not have, such as an injected sidecar, or a pod group the controller does not have) stays on the live Pod, once per controller. Members of a pure controller cycle are judged as roots.

The corpus pins the finding fields `check`, `object`, `group`, `container` and `verdict` only. It does not pin `path` or `message`; the unit tests in `internal/scan/cluster_test.go` do.
