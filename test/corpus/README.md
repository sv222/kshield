# Corpus

Every directory under `test/corpus/` that holds an `expected.yaml` is one case.
`TestCorpus` (`test/corpus_test.go`) walks all cases and scans each one in-process with `--deterministic`.

A case directory has two files:

- `input.yaml` - the manifests to scan. Chart cases use `rendered.yaml` (the output of `helm template`) instead. Exactly one of the two must exist.
- `expected.yaml` - the ground truth. Write it by hand from the rules and the input, before you look at scanner output.

```yaml
namespace: ai-inference
checks: [KS-WL-001]
expect:
  - {check: KS-WL-001, object: Deployment/ai-inference/vllm, container: vllm, verdict: FAIL}
na: []
```

- `namespace` - default namespace for objects that have none (default: `default`).
- `checks` - the check IDs this case is about, or `all`. Findings of other checks are ignored.
- `expect` - one entry per finding: `check`, `object` (`Kind/namespace/name`), optional `group` and `container` (empty means the finding is on the object), and `verdict` (`FAIL`, `WARN` or `INFO`). Order does not matter, but count does: the diff is a multiset. When a rule gives two findings with the same five fields (for example KS-WL-004 for `hostIPC` and `hostPID` on one pod, or KS-AI-008 for no API key and no TLS), list the entry twice.
- `na` - checks that must have the verdict `N/A`.

The test fails with the case path and every missing and extra entry. A mismatch is a product bug until proven otherwise. An expected set changes only with a reviewed reason in the pull request.

## Baselines

`baseline/toxic` is the insecure AI stack (vLLM, Qdrant, RayCluster) with no policies. `TestToxicGolden` (`test/golden_test.go`) also pins its text and JSON reports byte for byte in `test/golden/`. Run it with `-update` to rewrite them, then review the diff.

`baseline/hardened` is the same stack, fixed, with zero findings. The fixture generator uses it byte for byte as its base. Two parts of it are placeholders for the manifest scan only, not for a real cluster:

- The Tetragon guards (`kshield-shell-exec`, `kshield-egress-connect`) are not deployable. They would kill KubeRay's `/bin/bash -lc` start, bash exec probes and Qdrant's entrypoint script. The real guards come from `kshield remediate` and were checked on a Kind cluster.
- The image digests are format-valid placeholders, not real registry digests.

## Re-scan residuals

`TestRescanCorpus` (`internal/remediate/rescan_test.go`) runs the remediation re-scan loop on every case above and on the fixturegen seeds 1001-1003, in `audit` and `enforce` mode: scan, `remediate`, kustomize build, then scan the built objects plus the input Secrets plus `infrastructure-policies.yaml`. A policy replaces a built object with the same API group, kind, namespace and name, as `kubectl apply` does.

`rescan.yaml` lists the findings that stay FAIL after remediation by design (the residual rules of remediation). It exists only where a residual applies. Write it by hand from the input and the residual rules, before you look at the loop output.

```yaml
residuals:
  - {check: KS-WL-001, object: Deployment/ai-inference/ollama, container: ollama, mode: both}
```

- `check`, `object` (`Kind/namespace/name`) and `container` (empty for pod-level and object-level findings) name the finding. Matching uses these three fields, as a set.
- `mode` - `audit`, `enforce` or `both`.
- Residuals are FAIL findings of `patch` and `policy` checks, and in enforce mode WARN findings of KS-NET-001 and KS-RT-001..003. Any other WARN left by a residual rule needs no entry.
- Seed residuals live in `fixturegen/seed-<n>/rescan.yaml`.

The loop fails when a FAIL of a `patch` or `policy` check has no residual, when a residual has no FAIL (or, in enforce mode, no WARN on KS-NET-001 or KS-RT-001..003), when enforce mode leaves such a WARN without a residual, when the re-scan has a finding (check, object, container) that the first scan did not have or a worse verdict, when an item with action `patch` in `remediation.json` still has a finding of any verdict for the same check, object and container in the re-scan (unless a residual names it), or when a second `remediate` on the patched output writes a workload patch or a JSON 6902 file. A failure is a product bug until proven otherwise. A `rescan.yaml` changes only with a reviewed reason in the pull request.

`remediate/raycluster-reordered` holds a RayCluster (groups `cpu` and `gpu`, two containers in `gpu`) and two reordered copies. `TestRescanRayClusterReordered` checks that the JSON 6902 patch applies to the original and fails the kustomize build on both copies.
