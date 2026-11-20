# Run Ollama and vLLM without root

This page shows what Ollama and vLLM need to run as a non-root user in a hardened pod. It comes with two complete manifests:

- [`examples/hardened/ollama.yaml`](../examples/hardened/ollama.yaml)
- [`examples/hardened/vllm.yaml`](../examples/hardened/vllm.yaml)

Each file has a Namespace, a Deployment, a ClusterIP Service and an ingress NetworkPolicy. The vLLM file also has a Secret. Copy a file, then change the image tag, the model and the limits. The vLLM Secret holds a placeholder: replace `REPLACE_WITH_A_RANDOM_KEY` before you apply it.

## What kshield says about the examples

```bash
kshield scan manifest -f examples/hardened/vllm.yaml
```

All workload checks pass or warn. Two WARN findings remain on purpose: the image is not pinned by digest (KS-WL-012), and the vLLM example sets no `--load-format` (KS-AI-003). Pin the digest and add `--load-format safetensors` for your own model.

The scan also reports FAIL for KS-NET-001 and KS-RT-001 to KS-RT-003. Those checks look for egress default-deny, Tetragon guards and the Kyverno admission guard. They are cluster policies, not part of a workload manifest. `kshield remediate` writes them. A test in CI scans each example together with the generated policies and expects no FAIL.

The Ollama example sets the annotation `kshield.io/gateway-auth: "true"`. Ollama has no authentication of its own, so without the annotation KS-AI-010 reports a WARN. The annotation is a claim by the manifest author that the NetworkPolicy or a gateway limits who can call the engine. kshield cannot check it, so it reports INFO and names the annotation.

The `kshield.io/ai: "true"` label marks the workload as an AI workload. The examples use known engine images, so kshield finds them without the label. The label helps for custom images.

## Test results

The manifests were tested on 2026-10-14 on a single-node kind v0.33.0 cluster (Kubernetes 1.37.0, default kindnet CNI, a host without AVX-512, 12 GB RAM). Kyverno 1.19.1 ran with one admission controller. The runs used the ai-guard-k8s project that kshield replaces. Since then only the label and annotation names changed to the kshield names. The examples were not run again with kshield.

| | Ollama | vLLM |
|---|---|---|
| Image | `ollama/ollama:0.40.4` | `vllm/vllm-openai-cpu:v0.31.0-x86_64` |
| Model | `qwen2.5:0.5b`, pulled inside the running pod | `facebook/opt-125m`, `--dtype=float32` |
| Admission | admitted, Ready, UID 10001 | admitted, Ready, UID 10001 |
| Inference | `/api/generate` and `/v1/chat/completions` answered through the Service in about 3 s | `/v1/completions` answered through the Service. The first request took about 2 minutes, later requests 0.5 s |
| Auth | none in the engine (by design) | `/v1/models` and `/v1/completions` gave 401 without a key and with a wrong key, 200 with the key |
| NetworkPolicy | a client pod without the allowed label timed out | same |

Both containers ran with `runAsNonRoot`, a non-zero UID, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault` and `readOnlyRootFilesystem: true`. The writable paths are `emptyDir` volumes. Neither engine needed an exception.

## What the engines need

### Ollama

- Set `HOME=/data` and `OLLAMA_MODELS=/data/models`, and mount an `emptyDir` at `/data`. The image runs as root by default and keeps its key and models under `/root/.ollama`. A non-root user cannot write there.
- Set `OLLAMA_HOST=0.0.0.0:11434` to reach the engine from other pods. By default it listens on localhost only.
- Ollama has no authentication. Keep the Service `type: ClusterIP`, limit clients with a NetworkPolicy, and put an authenticating proxy in front for clients outside the namespace.
- Do not set `OLLAMA_ORIGINS` to `*`. Any web page in a visitor's browser could then call the engine (KS-AI-011).

### vLLM

- Set `enableServiceLinks: false`. Without it, a Service named `vllm` injects the variable `VLLM_PORT=tcp://<ip>:8000` into the pod. vLLM reads `VLLM_PORT` as its own setting and exits with `VLLM_PORT ... appears to be a URI`. The pod crash-loops. The same risk exists for any Service whose name makes a `VLLM_*` variable.
- Put `HOME`, `HF_HOME`, `VLLM_CACHE_ROOT` and similar cache paths on an `emptyDir`.
- Mount an `emptyDir` with `medium: Memory` and a `sizeLimit` at `/dev/shm`. Do not use a hostPath for it (KS-WL-005).
- The vLLM docs suggest `--cap-add SYS_NICE` and `seccomp=unconfined` for Docker. Neither was needed. With `RuntimeDefault` the logs show `get_mempolicy` and `set_mempolicy` "Operation not permitted" warnings. vLLM then skips NUMA binding and does not fail. The test host had one NUMA node. Multi-socket hosts were not tested.
- The flags `--enforce-eager`, `--max-model-len=512`, `VLLM_CPU_KVCACHE_SPACE=1` and `VLLM_CPU_OMP_THREADS_BIND=nobind` keep memory low on a small host. It was not tested which of them are required.
- The API key covers the `/v1` routes only. In the test `/health`, `/metrics`, `/version` and `/ping` answered 200 without a key, and `/tokenize` answered 405 (not 401) to an unauthenticated GET. This matches the vLLM security documentation. Keep the Service internal.

## Not tested

- GPU images, larger models, real memory use under load and more than one replica.
- Cilium policies and egress limits. The example NetworkPolicy covers ingress only, because the model download needs egress.
- Other CNIs, other Kubernetes versions, Helm charts and Ingress.
