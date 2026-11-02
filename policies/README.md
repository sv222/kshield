# kshield infrastructure policies

`kshield remediate` writes these policies to `infrastructure-policies.yaml`. It writes one set of four objects per AI namespace that has a KS-NET-001, KS-RT-001, KS-RT-002 or KS-RT-003 finding. The code is `internal/remediate/policy.go`.

Pinned versions (`versions.env`): Cilium v1.20.3, Tetragon v1.7.1, Kyverno v1.19.1. Each object passes the schema of the vendored CRD in `test/crds/`. Admission on a real API server and the runtime behavior were tested in Kind clusters with Cilium, Tetragon and Kyverno during development. The head-only Ray API server rule (`kshield-egress-apiserver`) has unit tests but no cluster run.

## The four objects

| Object | Name | Check that rates it | What it does |
|---|---|---|---|
| `CiliumNetworkPolicy` (`cilium.io/v2`) | `kshield-egress` | KS-NET-001, KS-NET-002 | Selects every pod of the namespace (`endpointSelector: {}`). Allows egress to kube-dns (`k8s:io.kubernetes.pod.namespace: kube-system`, `k8s:k8s-app: kube-dns`) on 53/UDP and 53/TCP with DNS visibility (`matchPattern: "*"`), to every pod of the same namespace (`toEndpoints: [{}]`), to every pod of each other namespace of the input that runs an AI workload, to each `--allow-fqdn` name (`toFQDNs` `matchName`) and to each `--allow-cidr` block (`toCIDR`). |
| `CiliumNetworkPolicy` (`cilium.io/v2`) | `kshield-egress-apiserver`, only in a namespace with a RayCluster, RayService or RayJob with in-tree autoscaling on | KS-NET-001 | Selects only the Ray head pods (`endpointSelector.matchLabels: {ray.io/node-type: head}`; KubeRay sets this label on the head pod). Allows egress to the `kube-apiserver` entity for the Ray autoscaler. Same `enableDefaultDeny` as `kshield-egress`. Worker pods and every other pod of the namespace get no API server rule. |
| `TracingPolicyNamespaced` (`cilium.io/v1alpha1`) | `kshield-shell-exec`, label `kshield.io/guard: shell-exec` | KS-RT-001 | kprobe `security_bprm_check`. Catches the exec of a shell (`/sh`, `/bash`, `/dash`, `/ash`, `/zsh`, `/ksh`, `/busybox`) by a process that is not a shell and not PID 1 of the container. See the shell-guard table below. |
| `TracingPolicyNamespaced` (`cilium.io/v1alpha1`) | `kshield-egress-connect`, label `kshield.io/guard: egress-connect` | KS-RT-002 | kprobe `security_socket_connect`, arg 0 `socket`, arg 1 `sockaddr` (the destination), `options: [{name: disable-kprobe-multi, value: "1"}]`. Catches a TCP `connect()` (`Protocol` `IPPROTO_TCP` on arg 0) to an address outside `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`, `0.0.0.0/32`, `::/128` and the `--allow-cidr` blocks (operator `NotSAddr`: Tetragon v1.7.1 matches the address of a `sockaddr` argument only with the `SAddr` operators). UDP `connect()` is not matched. |
| Kyverno `Policy` (`kyverno.io/v1`) | `kshield-admission`, label `kshield.io/guard: admission` | KS-RT-003 | `background: true`. Rule `kshield-pod-security`: Pod Security Standard `restricted`, version `latest` (no root, no host namespaces, no hostPath such as a `/dev/shm` hostPath, no privilege escalation). Rule `kshield-no-pickle-load`: denies a Pod when a container's `command` and `args`, joined with spaces, hold `--trust-remote-code` or `--load-format` with a pickle format of vLLM v0.31.0 (`pt`, `npcache`, any case, also in quotes). |

The Kyverno object is a namespaced `Policy`, not a `ClusterPolicy`, so you can switch one namespace to enforce at a time. It has no `exclude` and no `namespaceSelector`, because KS-RT-003 rates those only as approximated (WARN).

## Audit and enforce

| Object | `--mode audit` (default) | `--mode enforce` |
|---|---|---|
| `kshield-egress` | `enableDefaultDeny: {egress: false, ingress: false}`: the allow rules are recorded, no traffic is denied | `enableDefaultDeny: {egress: true, ingress: false}`: egress that no rule allows is dropped |
| `kshield-shell-exec` | `matchActions: [{action: Post}]`: event only | `Sigkill` |
| `kshield-egress-connect` | `Post`: event only | `Override` with `argError: -1`: the `connect()` call fails with `EPERM`; the process keeps running |
| `kshield-admission` | every rule `validate.failureAction: Audit`: policy report only | every rule `Enforce`: the API server rejects the Pod |

Audit mode never blocks anything and never changes existing egress policies. The scanner rates the audit form as WARN (present, not enforcing) and the enforce form as PASS.

Enforce mode of `kshield-egress-connect` uses `Override` on a `security_` hook. Tetragon v1.7.1 accepts that only when the kernel supports BPF `fmod_ret` programs (`bpf.HasModifyReturn()`) and the kprobe is not attached through `kprobe_multi` (`pkg/sensors/tracing/generickprobe.go`, `validateOverride`). `kprobe_multi` is on by default on x86_64 nodes that support it, so the policy sets the spec option `disable-kprobe-multi` (in both modes, so audit and enforce load the same way). If the kernel has no `fmod_ret`, Tetragon refuses the enforce policy. The manifest scan cannot see that: KS-RT-002 rates the manifest, not the loaded guard. Check the Tetragon log or `tetra tracingpolicy list` after you apply it.

Rollout order: patch the workloads, apply the policies in audit mode, review the Kyverno policy reports, Tetragon events and Hubble flows, then run `kshield remediate --mode enforce` for one namespace at a time. Enforce mode kills exec probes and lifecycle hooks that run a shell; see "Known limits" before you switch.

## Shell guard

Most inference containers start through a shell wrapper (`sh -c "vllm serve ..."`). A rule "kill every exec of `/bin/sh`" kills them at start. The guard judges who starts the shell:

| Shell exec in a guarded pod | Verdict | How the selector gives it |
|---|---|---|
| Container entrypoint: the shell is PID 1 of the container (namespace PID), exec'd by the runtime at start | allowed | `matchPIDs` `NotIn [1]` with `isNamespacePID: true` skips PID 1 |
| A shell started by the entrypoint shell, with only shells between it and PID 1 (start-up scripts) | allowed, only partly expressed (see Known limits) | `matchBinaries` `NotPostfix` skips a process whose binary is a shell |
| A shell with a non-shell process in its ancestry inside the container (for example the vLLM `python3` process) | Sigkill: RCE / shell injection | the exec'ing process is `python3`: not a shell, not PID 1 |
| An exec session shell (`kubectl exec ... /bin/sh`), not descended from PID 1 | Sigkill | the exec'ing process is the runtime (`runc`), not PID 1 |

The selector is one Tetragon selector, so its parts are ANDed: `matchArgs` index 0 `Postfix` on the shell list, `matchBinaries` `NotPostfix` on the same list, `matchPIDs` `NotIn [1]` (`isNamespacePID: true`).

Status: tested in a Kind cluster with Cilium, Tetragon and Kyverno during development. An `sh -c` entrypoint and an entrypoint script that calls a second script stay up. A shell exec from a non-shell process and a shell exec from an exec session are killed. Each case has a control.

### Known limits of the shell guard

- Row 2 is only partly expressed: a second script started through `/usr/bin/env <shell>` (a `#!/usr/bin/env bash` shebang) is killed in enforce mode, because at the exec of `bash` the exec'ing binary is `/usr/bin/env` and its PID is not 1. A `matchParentBinaries` filter does not fix this: with a `sh -c "vllm serve ..."` entrypoint, the parent of `python3` is `sh`, so a `python3` -> `sh` RCE (row 3) would be allowed. A test with an env-shebang script is needed before the selector is final.
- Enforce mode kills exec probes and lifecycle hooks that run a shell (`exec: [bash, -c, ...]`; KubeRay adds `bash -c wget ...` exec probes), because they start through the runtime like an exec session (row 4). It also kills an entrypoint shell under `tini` or `dumb-init`, because then the shell is not PID 1. Review the audit-mode Tetragon events first; change exec probes to `httpGet` or `tcpSocket`, or keep that namespace in audit mode.
- The selector looks at the process that calls exec, not at the whole ancestry. A shell started by an allowed shell is allowed, also when that shell itself was started by `python3`: only the first shell in that chain is caught. In enforce mode the first shell is killed, so its children never start.
- PID 1 is often the vLLM `python3` process itself (`exec vllm serve` or a direct entrypoint). An in-place exec of a shell by PID 1 is allowed.
- PID 1 must be the container entrypoint. With `shareProcessNamespace: true` PID 1 is the pause process, and with `hostPID: true` the PIDs are host PIDs; then the entrypoint shell is not PID 1 and enforce mode kills it. KS-WL-004 and KS-WL-007 patches remove both fields; apply the workload patch first.
- Busybox applets (`/bin/sh` -> `busybox`) exec'd by a non-shell process match `/busybox` if `linux_binprm` reports the resolved path; then any busybox applet started by such a process is caught, not only a shell.
- Libraries that start a shell from Python (`subprocess(..., shell=True)`, for example in Triton compile paths) are caught too. Audit mode records them; an allow-list by exact binary and args is built only from recorded audit events.

## Limits of the egress guards

- In-cluster destinations: the CNP allows only kube-dns, the same namespace, the other AI namespaces of the input and (for Ray autoscaling, Ray head pods only) the API server. Any other in-cluster destination, for example an OpenTelemetry collector or a vector DB namespace that was not in the input, must be added by hand.
- `--allow-fqdn` refuses names that end in `.svc` or `.cluster.local` (exit 2): Cilium `toFQDNs` does not apply to in-cluster addresses, so such a rule would allow nothing.
- `kshield-egress-connect` does not know DNS names. In enforce mode the `connect()` to the public address of an `--allow-fqdn` name fails with `EPERM`, unless that address is also in `--allow-cidr`. Review the audit events before you switch to enforce.
- `169.254.0.0/16` stays blocked, because the cloud metadata service (`169.254.169.254`) holds node credentials. NodeLocal DNSCache (`169.254.20.10`) needs `--allow-cidr 169.254.20.10/32`, and its backends (`k8s-app: node-local-dns`) are not in the CNP DNS rule; add a rule for them by hand. A pod or service network outside the private ranges above (for example `100.64.0.0/10`) needs `--allow-cidr`, or enforce mode blocks in-cluster connects.
- Turn off phone-home before enforce, so the blocked connects do not fill the logs: `VLLM_NO_USAGE_STATS=1`, `DO_NOT_TRACK=1`, `HF_HUB_OFFLINE=1` (when the model is already local), `RAY_USAGE_STATS_ENABLED=0`.
- `kshield-egress-connect` matches TCP `connect()` only. UDP is left out on purpose: vLLM v0.31.0 `get_ip()` finds the pod IP with a UDP `connect()` to `8.8.8.8` / `2001:4860:4860::8888` (no packet is sent); an `EPERM` there gives `0.0.0.0` and stops the multi-node Ray executor ("Every node should have a unique IP address"). UDP egress is covered by the CNP in enforce mode.
- `0.0.0.0/32` and `::/128` are allowed, because Tetragon reads the address the process passes to `connect()`, and a connect to `0.0.0.0` reaches the local host on Linux.
- Each IPv4 range of the `kshield-egress-connect` allow list (the private ranges and every IPv4 `--allow-cidr`) is also allowed in its IPv4-mapped IPv6 form (`10.0.0.0/8` -> `::ffff:10.0.0.0/104`). gRPC C-core (Ray GCS and raylet, `grpcio`) connects to IPv4 peers through dual-stack sockets with `::ffff:` addresses, and Tetragon v1.7.1 matches those 16-byte addresses against the IPv6 ranges only. This was checked in a Kind cluster.
- `--allow-cidr 0.0.0.0/0`, `::/0` and any other `/0` block are refused (exit 2), because they allow every address and make KS-NET-002 fail.
- Cilium enables egress default-deny for a pod if any policy that selects it asks for it. Other policies in the namespace can therefore deny egress even in audit mode.

## Limits of the admission guard

- The Kyverno pickle rule reads only `command` and `args`. A flag that comes from an environment variable or a `--config` file is not seen. The workload patch (KS-AI-002, KS-AI-003) and the scanner cover those cases.
