# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
