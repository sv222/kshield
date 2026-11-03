# kshield remediation

Mode: `audit`. Profile: `dora` (sha256 `a4c816e97c89586b6edfb2bce79c2e18d351b41c350879466df41fb6785c3a90`). scan.json sha256: `452914acb97462fce166a4a17a7ec7bad94e2d8ca44d412889f3b9d495160806`.

## Before you apply

### API key Secrets (KS-AI-001)

The patch sets `VLLM_API_KEY` from these Secrets. Create each one before you apply the patch, or the pod does not start. Use a long random key. Clients then send it as `Authorization: Bearer <key>`.

```sh
kubectl create secret generic vllm-vllm-api-key -n ai-inference --from-literal=api-key='<random API key>'
```

### Remote code (KS-AI-002)

The patch removes `--trust-remote-code`. vLLM then cannot load a model that needs custom Python code from its repository (a custom model class or tokenizer). Check each model below first. If a model needs custom code, do not apply this patch to it: review that code, or use a model that vLLM supports without it.

- `Deployment/ai-inference/vllm` container `vllm`

### Model weights (KS-AI-003)

The patch sets `--load-format safetensors`. vLLM then fails at start when the model repository has only `.bin` or `.pt` weights. Check that each model below has `.safetensors` files, or convert it first.

- `Deployment/ai-inference/vllm` container `vllm`

## Rollout order

Run these steps from this directory.

1. Patch the workloads: `kustomize build . | kubectl apply -f -`. Use the kustomize version pinned in kshield `versions.env`. A JSON 6902 `test` op fails the build when the manifests changed after the scan.
2. Apply the policies in audit mode: `kubectl apply -f infrastructure-policies.yaml`. Audit mode records and never blocks.
3. Review what the policies record in each namespace: Kyverno policy reports (`kubectl get policyreports -n <namespace>`), Tetragon events (`kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact`) and Hubble flows (`hubble observe --namespace <namespace>`).
4. Switch to enforce one namespace at a time: run `kshield remediate --from <scan.json> --mode enforce --out <new dir>` with the same `-f`, `--allow-fqdn` and `--allow-cidr` flags. In the new dir, build and apply the whole enforce bundle (`kustomize build . | kubectl apply -f -`), because its KS-NET-002 enforce patches are in `workload-patch-6902/`. Then apply the policies of that namespace from its `infrastructure-policies.yaml`. The KS-NET-002 enforce patches in the bundle cover every namespace at once; only the policies go one namespace at a time. On a CNI that is not Cilium, apply these patches only when every namespace is ready.

Namespaces with policies in this bundle: `ai-inference`.

Before you switch a namespace to enforce:

- The shell-exec guard kills exec probes and lifecycle hooks that run a shell, and entrypoint shells under `tini` or `dumb-init`. Change exec probes to `httpGet` or `tcpSocket`, or keep that namespace in audit.
- Ray starts shells from its Python processes: the dashboard, the client server, the autoscaler v2 monitor, `multiprocessing` spawn children and a `ray start` fork. In enforce mode the shell-exec guard kills them, and the Ray head does not start (measured with `rayproject/ray:2.52.0`). kshield has no allow-list for Ray. Keep the namespaces of these workloads in audit: `RayCluster/ai-inference/rc`.
- The egress policy allows DNS through kube-dns, the same namespace, the other AI namespaces and the `--allow-fqdn` and `--allow-cidr` values. Add `--allow-cidr` for NodeLocal DNSCache (`169.254.20.10/32`) and for pod or service CIDRs outside RFC 1918 (for example `100.64.0.0/10`).
- On a CNI that is not Cilium, the CiliumNetworkPolicies do nothing. There, the KS-NET-002 enforce patch removes the broad egress rules of a NetworkPolicy and keeps `policyTypes: [Ingress, Egress]`. With no egress rule left, this blocks all egress, DNS included.
- Check that Tetragon loaded the enforce policies: `kubectl get tracingpoliciesnamespaced -n <namespace>` and the Tetragon agent logs. The egress-connect `Override` action needs BPF `fmod_ret` support in the node kernel.
- The `kshield-pod-security` rule of the `kshield-admission` Policy enforces the Pod Security Standards `restricted` profile. In enforce mode it rejects new pods that break that profile: pods of a workload with a residual item of KS-WL-001 to KS-WL-005 or KS-WL-009 (for example a privileged GPU container, a hostPath `/dev` or a volume mounted under `/root`), and pods with any hostPath volume. Fix these workloads first, or keep that namespace in audit. Workloads of this bundle: `RayCluster/ai-inference/rc`.
- `policies/README.md` in the kshield repository lists the limits of each policy.

## Residual items

None.

## Manual items

### KS-WL-012 (DORA-CH2-012): Image not pinned by digest

Pin each image by digest. Get the digest of the tag you run with `crane digest <image>:<tag>` or `docker buildx imagetools inspect <image>:<tag>`, then set `image: <image>@sha256:<digest>`. Update the digest on purpose, through your change process.

- `Deployment/ai-inference/qdrant` container `qdrant` (`/spec/template/spec/containers/0/image`): image "qdrant/qdrant:v1.19.2" has no @sha256: digest
- `Deployment/ai-inference/vllm` container `vllm` (`/spec/template/spec/containers/0/image`): image "vllm/vllm-openai:v0.31.0" has no @sha256: digest
- `RayCluster/ai-inference/rc` group `cpu` container `ray-worker` (`/spec/workerGroupSpecs/0/template/spec/containers/0/image`): image "rayproject/ray:2.50.0" has no @sha256: digest
- `RayCluster/ai-inference/rc` group `gpu` container `ray-worker` (`/spec/workerGroupSpecs/1/template/spec/containers/0/image`): image "rayproject/ray:2.50.0-gpu" has no @sha256: digest
- `RayCluster/ai-inference/rc` group `head` container `ray-head` (`/spec/headGroupSpec/template/spec/containers/0/image`): image "rayproject/ray:2.50.0" has no @sha256: digest

### KS-WL-013 (DORA-CH2-013): No memory limit on AI workload

Set `resources.limits.memory` on each AI container. Size it from the measured peak use plus headroom. With a limit, memory pressure stops only this container, not other pods on the node.

- `Deployment/ai-inference/qdrant` container `qdrant` (`/spec/template/spec/containers/0/resources/limits/memory`): resources.limits.memory is not set
- `Deployment/ai-inference/vllm` container `vllm` (`/spec/template/spec/containers/0/resources/limits/memory`): resources.limits.memory is not set
- `RayCluster/ai-inference/rc` group `cpu` container `ray-worker` (`/spec/workerGroupSpecs/0/template/spec/containers/0/resources/limits/memory`): resources.limits.memory is not set
- `RayCluster/ai-inference/rc` group `gpu` container `ray-worker` (`/spec/workerGroupSpecs/1/template/spec/containers/0/resources/limits/memory`): resources.limits.memory is not set
- `RayCluster/ai-inference/rc` group `head` container `ray-head` (`/spec/headGroupSpec/template/spec/containers/0/resources/limits/memory`): resources.limits.memory is not set

### KS-WL-014 (DORA-CH2-014): GPU access via hostPath /dev/nvidia* or privileged, not device plugin

Give the pod GPUs through the NVIDIA device plugin (or the GPU Operator): request them with `resources.limits: {nvidia.com/gpu: <n>}`. Then remove the hostPath `/dev/nvidia*` volumes, `privileged: true` and a literal `NVIDIA_VISIBLE_DEVICES`. Scan again: KS-WL-002 can then be patched.

- `RayCluster/ai-inference/rc` group `gpu` (`/spec/workerGroupSpecs/1/template/spec/volumes/0`): volume "nvidia0" mounts hostPath /dev/nvidia0 (request GPUs through the device plugin with nvidia.com/gpu limits)

### KS-AI-004 (DORA-CH2-018): Inference API exposed outside cluster (Service LoadBalancer/NodePort, Ingress) without auth

Do not expose an inference API outside the cluster without authentication. Set `VLLM_API_KEY` (KS-AI-001), or put an authenticating proxy or API gateway in front of it, or change the Service to `type: ClusterIP` and remove the Ingress path.

- `Service/ai-inference/vllm` (`/spec/type`): Service type NodePort exposes Deployment/ai-inference/vllm outside the cluster: vLLM container vllm has no --api-key and no VLLM_API_KEY

### KS-AI-006 (DORA-CH2-020): Ray TLS off (RAY_USE_TLS not 1)

Turn on Ray TLS: create a CA and certificates for the Ray pods (for example with cert-manager), mount them into the head and every worker group, and set `RAY_USE_TLS=1`, `RAY_TLS_SERVER_CERT`, `RAY_TLS_SERVER_KEY` and `RAY_TLS_CA_CERT` on every Ray container.

- `RayCluster/ai-inference/rc` group `cpu` container `ray-worker` (`/spec/workerGroupSpecs/0/template/spec/containers/0/env`): RAY_USE_TLS is not set: Ray traffic is not encrypted
- `RayCluster/ai-inference/rc` group `gpu` container `ray-worker` (`/spec/workerGroupSpecs/1/template/spec/containers/0/env`): RAY_USE_TLS is not set: Ray traffic is not encrypted
- `RayCluster/ai-inference/rc` group `head` container `ray-head` (`/spec/headGroupSpec/template/spec/containers/0/env`): RAY_USE_TLS is not set: Ray traffic is not encrypted

### KS-AI-008 (DORA-CH2-022): Qdrant without API key or TLS

Set `QDRANT__SERVICE__API_KEY` from a Secret with `valueFrom.secretKeyRef`. Turn on TLS with `QDRANT__SERVICE__ENABLE_TLS=true`, and point `QDRANT__TLS__CERT` and `QDRANT__TLS__KEY` at a mounted certificate Secret.

- `Deployment/ai-inference/qdrant` container `qdrant` (`/spec/template/spec/containers/0/env`): Qdrant has no API key: QDRANT__SERVICE__API_KEY is not set and no mounted ConfigMap or Secret sets service.api_key
- `Deployment/ai-inference/qdrant` container `qdrant` (`/spec/template/spec/containers/0/env`): Qdrant serves without TLS: QDRANT__SERVICE__ENABLE_TLS is not true and no mounted ConfigMap or Secret sets service.enable_tls: true
