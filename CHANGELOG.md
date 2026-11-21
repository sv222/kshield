# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-21

### Added

- The `nis2` profile: the same scan, reports and evidence bundles with NIS2 display IDs (`NIS2-K8S-001` and up) and references to Article 21 of Directive (EU) 2022/2555 and the Annex of Commission Implementing Regulation (EU) 2024/2690. `--profile nis2` works on `scan manifest`, `scan cluster`, `checks list` and `checks explain`. 38 of the 40 checks are mapped; KS-WL-006 and KS-WL-013 stay out because no point of NIS2 Art. 21 or of the Annex fits them. The full mapping is in `docs/MAPPING-REVIEW-nis2.md`. NIS2 applies to essential and important entities; for financial entities DORA is lex specialis (Art. 4 of the Directive).
- `checks explain` shows an applicability note for profiles that carry one (`checks explain NIS2-K8S-001 --profile nis2`).
- Engine detection for Triton, Text Generation Inference (including `text-generation-launcher` and `text-generation-router`), Text Embeddings Inference, LocalAI, SGLang, llama.cpp, lmdeploy and TensorRT-LLM, and for Ray Serve by command. Triton, TGI and the other new engines now get findings: a scan of manifests with these engines reports more findings than before, because every check runs on AI workloads only. A non-AI pod stays non-AI.
- The label or annotation `kshield.io/ai: "true"` and the flag `--workload-selector <label selector>` on `scan manifest` and `scan cluster` mark custom images as AI workloads. Engine findings on an opted-in workload are suspect (WARN). `kshield remediate` re-uses the selector recorded in `scan.json`.
- `scan manifest` reads Argo Rollout and ReplicationController workloads, and `remediate` patches them.
- KS-AI-010 (DORA-CH2-036): inference engine other than vLLM without an API key flag, engine env var or gateway auth evidence. It reads the Secret behind `envFrom`.
- KS-AI-011 (DORA-CH2-037): `--debug`, `--allow-http`, `OLLAMA_DEBUG` and `OLLAMA_ORIGINS` with `*` on an inference engine.
- KS-AI-012 (DORA-CH2-038): `--trust-remote-code`, pickle and Keras model files (`.bin`, `.pt`, `.pth`, `.pkl`, `.pickle`, `.ckpt`, `.h5`, `.keras`) on engines other than vLLM, and `s3://` or `gs://` model sources on every engine.
- KS-WL-015 (DORA-CH2-034): hostPath volume outside `/dev`, `/dev/shm` and the GPU devices that KS-WL-005 and KS-WL-014 cover.
- KS-WL-016 (DORA-CH2-035): hostPort on an AI container, with a `remediate` patch that removes it.
- KS-NET-004 (DORA-CH2-039): no NetworkPolicy or Cilium policy restricts ingress to the workload. A policy rule that allows every source does not count.
- KS-AI-004 also checks engines other than vLLM, and accepts the Ingress annotations `auth-signin`, `auth-secret` and `oauth2` as auth evidence besides `auth-url` and `auth-type`.
- The label or annotation `kshield.io/gateway-auth: "true"` on a workload makes KS-AI-001, KS-AI-004, KS-AI-007, KS-AI-010 and KS-AI-013 report INFO that names the annotation, instead of FAIL or WARN. kshield does not verify the gateway. On an Ingress it counts as auth evidence.
- `scan.json` records the `workloadSelector` of the scan when one is set.
- `docs/hardened-engines.md` and the hardened Ollama and vLLM examples in `examples/hardened/`.
- Corpus cases from ai-guard-k8s (regression files, the offending and clean samples) and the TGI, TEI, LocalAI and Triton charts. The chart renderer can render a chart from a git commit.
- KS-AI-013 (DORA-CH2-040): a Gateway API `HTTPRoute` with a Gateway parent that reaches an AI engine Service with no auth evidence. FAIL when nothing protects it, WARN when a Kong plugin is not in the input or the parent Gateway is outside the scanned namespaces.
- Istio auth evidence: an `AuthorizationPolicy` (ALLOW with principals or request principals, DENY of requests without a principal, or a CUSTOM provider) that selects the workload, its Service or the ingress Gateway counts. A policy that relies on JWT principals needs a `RequestAuthentication` on the same target.
- Kong auth evidence: a `KongPlugin` or `KongClusterPlugin` with an auth plugin, bound by `konghq.com/plugins` on an Ingress, Service or HTTPRoute, or by an `ExtensionRef` filter on an HTTPRoute.
- Envoy Gateway auth evidence: a `SecurityPolicy` with `jwt`, `oidc`, `basicAuth`, `apiKeyAuth` or `extAuth` that targets the HTTPRoute or its Gateway.
- KS-AI-001, KS-AI-004, KS-AI-007 and KS-AI-010 report INFO that names the Istio policy or Kong plugin instead of FAIL or WARN when such evidence protects the workload, its Ingress or its Service.
- `scan cluster` reads Istio `authorizationpolicies` and `requestauthentications`, Kong `kongplugins` and `kongclusterplugins`, Gateway API `httproutes` and `gateways`, and Envoy Gateway `securitypolicies` when the CRDs exist. `deploy/rbac/kshield-scan.yaml` has the new get and list rules. A forbidden read gives UNKNOWN for KS-AI-004, KS-AI-007 and KS-AI-013 and exit code 3.
- `kshield remediate --apply` applies the policies of the bundle with server-side apply (field manager `kshield`, no force). It prints the context and the objects, asks for confirmation (`--yes` skips it, no terminal needs `--yes`), checks that the Kyverno, Cilium and Tetragon kinds exist (`--skip-missing-crds`), and supports `--dry-run`, `--apply-patches` (workload patches restart pods, so they are off by default) and `--force-conflicts`. Exit code 4 means the apply failed. A real apply first runs a server-side dry run of every object and applies nothing if one is rejected.
- `deploy/rbac/kshield-apply.yaml`: example ClusterRoles for `--apply` with create and patch only.

### Changed

- The sign-off decision words of the mapping review are `author review` or `rejected`; author review is not a legal or compliance review. The old sign-off row of the DORA review file is removed, the table is empty and waits for a new sign-off for the current profile sha256.
- The `dora` profile has 40 checks (7 new). The profile sha256 changed, so `docs/MAPPING-REVIEW.md` needs a new sign-off.
- Scans stay read-only. `remediate` writes a bundle and changes the cluster only with `--apply`.
- An Istio, Kong or Envoy Gateway object that protects an exposure is reported as INFO, and an Ingress with an auth annotation is still skipped without a finding, as before.

## [0.3.0] - 2026-11-20

### Added

- Enforce mode exempts the pods of a KubeRay RayCluster (the `ray.io/cluster` label) from the `kshield-shell-exec` sigkill guard, so the Ray head, worker and driver pods start under enforce; a bare `ray start` pod without the label stays guarded, and audit mode records every pod as before.
- In enforce mode each `kshield-egress-apiserver` policy also allows the Ray head to reach the pods of its own cluster on 6379 (GCS), 8265 (dashboard), 8266 (job submit), 10001 (Ray client) and 8000 (Ray Serve).

### Fixed

- The KS-RT-001 check no longer rates the head and worker sites of a RayService or RayJob as covered by the enforce shell-exec guard: KubeRay labels those pods with `ray.io/cluster` too, so the guard exempts them, and the check now reports the workloads as unguarded like a RayCluster (the model carries the label with an empty value, because the name of the generated child cluster is unknown from the CR).

## [0.2.0] - 2026-11-18

### Added

- `MANUAL.md` lists which non-AI workloads of a policy namespace break the Pod Security Standards `restricted` profile and which conform, and `remediation.json` carries the same list as `pssNonAI`.
- The Ray API server egress policy is one per autoscaling RayCluster and selects on both `ray.io/node-type: head` and `ray.io/cluster`.

### Fixed

- Ollama false negative: custom images without an `ollama` name or command are now detected via port 11434, `OLLAMA_` env vars and `.ollama` mounts.
- The KS-WL-001 patch no longer refuses Ollama containers whose `.ollama` volume is mounted under `/root`; the mount moves to `/ollama`.

## [0.1.0] - 2026-11-04

### Added

- `kshield scan manifest` scans Kubernetes YAML files, directories or stdin for risks in AI workloads: vLLM, Ollama, KubeRay (RayCluster, RayService, RayJob), KServe, Qdrant and Milvus.
- `kshield scan cluster` scans a live cluster with read-only requests, with namespace filters and an optional `--node-probe` that reads the LSM list and kernel config of each node.
- 33 checks in the `dora` profile: workload hardening, AI serving risks, network egress, runtime guards and cluster prerequisites. Each check cites verbatim excerpts of DORA (Regulation (EU) 2022/2554) and RTS (EU) 2024/1774.
- Report formats: text, JSON (`kshield.report/v1`), self-contained HTML, PDF and SARIF 2.1.0.
- `--deterministic` for byte-identical output and `--fail-on` for CI gating.
- Evidence packs (`--evidence`) with all five reports and a sha256 manifest, optional Ed25519 signing, `kshield evidence keygen` and `kshield evidence verify`.
- `kshield remediate` writes a kustomize bundle with workload patches, Cilium, Tetragon and Kyverno policies in audit or enforce mode, and a `MANUAL.md` for the steps that need a human.
- `kshield checks list`, `kshield checks explain` and `kshield profiles list`.
- Read-only RBAC manifests in `deploy/rbac/`.
