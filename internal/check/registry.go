package check

import "slices"

var catalog = []Check{
	{ID: "KS-WL-001", Title: "Container may run as root (no runAsNonRoot: true, or UID 0)", Tier: Both, Fix: FixPatch, Run: wlRunAsRoot},
	{ID: "KS-WL-002", Title: "privileged: true or allowPrivilegeEscalation not false", Tier: Both, Fix: FixPatch, Run: wlPrivileged},
	{ID: "KS-WL-003", Title: "Capabilities not dropped (drop: [ALL] missing)", Tier: Both, Fix: FixPatch, Run: wlCapabilities},
	{ID: "KS-WL-004", Title: "hostIPC, hostPID or hostNetwork true", Tier: Both, Fix: FixPatch, Run: wlHostNamespaces},
	{ID: "KS-WL-005", Title: "/dev/shm from hostPath (or hostPath /dev)", Tier: Both, Fix: FixPatch, Run: wlHostPathDev},
	{ID: "KS-WL-006", Title: "Memory emptyDir for shm without sizeLimit", Tier: Both, Fix: FixPatch, Run: wlShmSizeLimit},
	{ID: "KS-WL-007", Title: "shareProcessNamespace: true on AI workload", Tier: Both, Fix: FixPatch, Run: wlShareProcessNamespace},
	{ID: "KS-WL-008", Title: "Root filesystem writable", Tier: Both, Fix: FixPatch, Run: wlReadOnlyRootFS},
	{ID: "KS-WL-009", Title: "No seccompProfile: RuntimeDefault", Tier: Both, Fix: FixPatch, Run: wlSeccomp},
	{ID: "KS-WL-010", Title: "Service account token auto-mounted", Tier: Both, Fix: FixPatch, Run: wlAutomountToken},
	{ID: "KS-WL-011", Title: "Secret values in plain env (HF_TOKEN, API keys)", Tier: Manifest, Fix: FixManual, Run: wlSecretEnv},
	{ID: "KS-WL-012", Title: "Image not pinned by digest", Tier: Manifest, Fix: FixManual, Run: wlImageDigest},
	{ID: "KS-WL-013", Title: "No memory limit on AI workload", Tier: Manifest, Fix: FixManual, Run: wlMemoryLimit},
	{ID: "KS-WL-014", Title: "GPU access via hostPath /dev/nvidia* or privileged, not device plugin", Tier: Both, Fix: FixManual, Run: wlGPUAccess},
	{ID: "KS-AI-001", Title: "vLLM API without auth (--api-key / VLLM_API_KEY unset)", Tier: Manifest, Fix: FixManual, Run: aiAPIKey},
	{ID: "KS-AI-002", Title: "vLLM --trust-remote-code set", Tier: Manifest, Fix: FixPatch, Run: aiTrustRemoteCode},
	{ID: "KS-AI-003", Title: "Model load may use pickle", Tier: Manifest, Fix: FixPatch, Run: aiPickleLoad},
	{ID: "KS-AI-004", Title: "Inference API exposed outside cluster (Service LoadBalancer/NodePort, Ingress) without auth", Tier: Both, Fix: FixManual, Run: aiExposed},
	{ID: "KS-AI-005", Title: "Ray GCS 6379, client 10001 or dashboard 8265 exposed beyond ClusterIP", Tier: Both, Fix: FixPatch, Run: aiRayExposed},
	{ID: "KS-AI-006", Title: "Ray TLS off (RAY_USE_TLS not 1)", Tier: Both, Fix: FixManual, Run: aiRayTLS},
	{ID: "KS-AI-007", Title: "Ollama 11434 exposed without an auth proxy", Tier: Both, Fix: FixManual, Run: aiOllamaExposed},
	{ID: "KS-AI-008", Title: "Qdrant without API key or TLS", Tier: Both, Fix: FixManual, Run: aiQdrant},
	{ID: "KS-AI-009", Title: "Milvus authorization disabled", Tier: Both, Fix: FixManual, Run: aiMilvusAuth},
	{ID: "KS-NET-001", Title: "AI namespace has no default-deny egress (no CNP/NetworkPolicy in input or cluster)", Tier: Both, Fix: FixPolicy, Run: netEgressDefaultDeny},
	{ID: "KS-NET-002", Title: "Egress allow-list too broad (world, 0.0.0.0/0)", Tier: Both, Fix: FixPolicy, Run: netBroadEgress},
	{ID: "KS-NET-003", Title: "Pod-to-pod encryption off (Cilium WireGuard/IPsec)", Tier: Cluster, Fix: FixManual, Run: netEncryption},
	{ID: "KS-RT-001", Title: "No runtime shell-exec guard on AI namespace (Tetragon)", Tier: Both, Fix: FixPolicy, Run: rtShellExecGuard},
	{ID: "KS-RT-002", Title: "No runtime egress-connect guard on AI namespace (Tetragon)", Tier: Both, Fix: FixPolicy, Run: rtEgressConnectGuard},
	{ID: "KS-RT-003", Title: "No admission guard for root, host namespaces, shm hostPath, pickle load (Kyverno)", Tier: Both, Fix: FixPolicy, Run: rtAdmissionGuard},
	{ID: "KS-PRE-001", Title: "Tetragon missing or unhealthy", Tier: Cluster, Fix: FixManual, Run: prePresenceTetragon},
	{ID: "KS-PRE-002", Title: "CNI is not Cilium (L7/FQDN egress not possible)", Tier: Cluster, Fix: FixManual, Run: prePresenceCilium},
	{ID: "KS-PRE-003", Title: "Kyverno missing or unhealthy", Tier: Cluster, Fix: FixManual, Run: prePresenceKyverno},
	{ID: "KS-PRE-004", Title: "Node kernel lacks BPF LSM (--node-probe)", Tier: Cluster, Fix: FixManual, Run: preBPFLSM},
}

func All() []Check {
	return slices.Clone(catalog)
}

func ByID(id string) (Check, bool) {
	for _, c := range catalog {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}
