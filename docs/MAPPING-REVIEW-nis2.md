# Mapping review - NIS2 Article 21 - Directive (EU) 2022/2555 and Implementing Regulation (EU) 2024/2690

- Profile: `nis2`
- Version: 1
- Profile sha256: `4939814c89490052918376b9c7002ad93b6f2ce8261d655159c0f0b38fb6a033`
- Checks: 38
- Checks left out: 2

This file lists each check of the profile in catalog order, with the regulation text that the check is mapped to. A mapping means that the check supports evidence for the cited requirement. It is not an audit and does not state compliance with any regulation.

The quotes are verbatim excerpts from `internal/regtext/sources`. `go run ./tools/mappingreview` writes everything above the sign-off marker. Do not edit that part by hand. The generator keeps everything from the marker line down as it is.

To sign off, read every mapping and add one row to the table under Sign-off: the date (YYYY-MM-DD), your name, the profile sha256 above, and the decision `author review` or `rejected`. The row also carries the review sha256 that `go run ./tools/mappingreview` prints. A change to the profile file changes its sha256, so it needs a new sign-off. Author review is not a legal or compliance review.

## NIS2-K8S-001 (KS-WL-001)

- Check: `KS-WL-001`
- Display ID: `NIS2-K8S-001`
- Title: Container may run as root (no runAsNonRoot: true, or UID 0)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-002 (KS-WL-002)

- Check: `KS-WL-002`
- Display ID: `NIS2-K8S-002`
- Title: privileged: true or allowPrivilegeEscalation not false
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-003 (KS-WL-003)

- Check: `KS-WL-003`
- Display ID: `NIS2-K8S-003`
- Title: Capabilities not dropped (drop: [ALL] missing)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-004 (KS-WL-004)

- Check: `KS-WL-004`
- Display ID: `NIS2-K8S-004`
- Title: hostIPC, hostPID or hostNetwork true
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.8.1

- Ref: `cir-annex-6-8-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall segment systems into networks or zones in accordance with the results of the risk assessment referred to in point 2.1. They shall segment their systems and networks from third parties’ systems and networks.

## NIS2-K8S-005 (KS-WL-005)

- Check: `KS-WL-005`
- Display ID: `NIS2-K8S-005`
- Title: /dev/shm from hostPath (or hostPath /dev)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

## NIS2-K8S-006 (KS-WL-007)

- Check: `KS-WL-007`
- Display ID: `NIS2-K8S-006`
- Title: shareProcessNamespace: true on AI workload
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

## NIS2-K8S-007 (KS-WL-008)

- Check: `KS-WL-008`
- Display ID: `NIS2-K8S-007`
- Title: Root filesystem writable
- Severity: warn

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-008 (KS-WL-009)

- Check: `KS-WL-009`
- Display ID: `NIS2-K8S-008`
- Title: No seccompProfile: RuntimeDefault
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-009 (KS-WL-010)

- Check: `KS-WL-010`
- Display ID: `NIS2-K8S-009`
- Title: Service account token auto-mounted
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### CIR (EU) 2024/2690 Annex 11.2.2(a)

- Ref: `cir-annex-11-2-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> assign and revoke access rights based on the principles of need-to-know, least privilege and separation of duties;

## NIS2-K8S-010 (KS-WL-011)

- Check: `KS-WL-011`
- Display ID: `NIS2-K8S-010`
- Title: Secret values in plain env (HF_TOKEN, API keys)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### CIR (EU) 2024/2690 Annex 11.2.2(a)

- Ref: `cir-annex-11-2-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> assign and revoke access rights based on the principles of need-to-know, least privilege and separation of duties;

## NIS2-K8S-011 (KS-WL-012)

- Check: `KS-WL-012`
- Display ID: `NIS2-K8S-011`
- Title: Image not pinned by digest
- Severity: warn

### NIS2 Art. 21(2)(e)

- Ref: `nis2-art21-2-e`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure;

### CIR (EU) 2024/2690 Annex 6.6.1(c)

- Ref: `cir-annex-6-6-1-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> security patches come from trusted sources and are checked for integrity;

## NIS2-K8S-012 (KS-WL-014)

- Check: `KS-WL-014`
- Display ID: `NIS2-K8S-012`
- Title: GPU access via hostPath /dev/nvidia* or privileged, not device plugin
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

## NIS2-K8S-013 (KS-AI-001)

- Check: `KS-AI-001`
- Display ID: `NIS2-K8S-013`
- Title: vLLM API without auth (--api-key / VLLM_API_KEY unset)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-014 (KS-AI-002)

- Check: `KS-AI-002`
- Display ID: `NIS2-K8S-014`
- Title: vLLM --trust-remote-code set
- Severity: fail

### NIS2 Art. 21(2)(e)

- Ref: `nis2-art21-2-e`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure;

### CIR (EU) 2024/2690 Annex 6.9.1

- Ref: `cir-annex-6-9-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall protect their network and information systems against malicious and unauthorised software.

## NIS2-K8S-015 (KS-AI-003)

- Check: `KS-AI-003`
- Display ID: `NIS2-K8S-015`
- Title: Model load may use pickle
- Severity: fail

### NIS2 Art. 21(2)(e)

- Ref: `nis2-art21-2-e`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure;

### CIR (EU) 2024/2690 Annex 6.9.1

- Ref: `cir-annex-6-9-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall protect their network and information systems against malicious and unauthorised software.

## NIS2-K8S-016 (KS-AI-004)

- Check: `KS-AI-004`
- Display ID: `NIS2-K8S-016`
- Title: Inference API exposed outside cluster (Service LoadBalancer/NodePort, Ingress) without auth
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-017 (KS-AI-005)

- Check: `KS-AI-005`
- Display ID: `NIS2-K8S-017`
- Title: Ray GCS 6379, client 10001 or dashboard 8265 exposed beyond ClusterIP
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-018 (KS-AI-006)

- Check: `KS-AI-006`
- Display ID: `NIS2-K8S-018`
- Title: Ray TLS off (RAY_USE_TLS not 1)
- Severity: fail

### NIS2 Art. 21(2)(h)

- Ref: `nis2-art21-2-h`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> policies and procedures regarding the use of cryptography and, where appropriate, encryption;

### CIR (EU) 2024/2690 Annex 9.2(a)

- Ref: `cir-annex-9-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> in accordance with the relevant entities’ classification of assets, the type, strength and quality of the cryptographic measures required to protect the relevant entities’ assets, including data at rest and data in transit;

## NIS2-K8S-019 (KS-AI-007)

- Check: `KS-AI-007`
- Display ID: `NIS2-K8S-019`
- Title: Ollama 11434 exposed without an auth proxy
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-020 (KS-AI-008)

- Check: `KS-AI-008`
- Display ID: `NIS2-K8S-020`
- Title: Qdrant without API key or TLS
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(h)

- Ref: `nis2-art21-2-h`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> policies and procedures regarding the use of cryptography and, where appropriate, encryption;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

### CIR (EU) 2024/2690 Annex 9.2(a)

- Ref: `cir-annex-9-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> in accordance with the relevant entities’ classification of assets, the type, strength and quality of the cryptographic measures required to protect the relevant entities’ assets, including data at rest and data in transit;

## NIS2-K8S-021 (KS-AI-009)

- Check: `KS-AI-009`
- Display ID: `NIS2-K8S-021`
- Title: Milvus authorization disabled
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-022 (KS-NET-001)

- Check: `KS-NET-001`
- Display ID: `NIS2-K8S-022`
- Title: AI namespace has no default-deny egress (no CNP/NetworkPolicy in input or cluster)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

### CIR (EU) 2024/2690 Annex 6.8.2(e)

- Ref: `cir-annex-6-8-2-e`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> restrict access and communications between and within zones to those necessary for the operation of the relevant entities or for safety;

## NIS2-K8S-023 (KS-NET-002)

- Check: `KS-NET-002`
- Display ID: `NIS2-K8S-023`
- Title: Egress allow-list too broad (world, 0.0.0.0/0)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.8.2(e)

- Ref: `cir-annex-6-8-2-e`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> restrict access and communications between and within zones to those necessary for the operation of the relevant entities or for safety;

## NIS2-K8S-024 (KS-NET-003)

- Check: `KS-NET-003`
- Display ID: `NIS2-K8S-024`
- Title: Pod-to-pod encryption off (Cilium WireGuard/IPsec)
- Severity: fail

### NIS2 Art. 21(2)(h)

- Ref: `nis2-art21-2-h`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> policies and procedures regarding the use of cryptography and, where appropriate, encryption;

### CIR (EU) 2024/2690 Annex 9.2(a)

- Ref: `cir-annex-9-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> in accordance with the relevant entities’ classification of assets, the type, strength and quality of the cryptographic measures required to protect the relevant entities’ assets, including data at rest and data in transit;

## NIS2-K8S-025 (KS-RT-001)

- Check: `KS-RT-001`
- Display ID: `NIS2-K8S-025`
- Title: No runtime shell-exec guard on AI namespace (Tetragon)
- Severity: fail

### NIS2 Art. 21(2)(b)

- Ref: `nis2-art21-2-b`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> incident handling;

### CIR (EU) 2024/2690 Annex 3.2.1

- Ref: `cir-annex-3-2-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall lay down procedures and use tools to monitor and log activities on their network and information systems to detect events that could be considered as incidents and respond accordingly to mitigate the impact.

## NIS2-K8S-026 (KS-RT-002)

- Check: `KS-RT-002`
- Display ID: `NIS2-K8S-026`
- Title: No runtime egress-connect guard on AI namespace (Tetragon)
- Severity: fail

### NIS2 Art. 21(2)(b)

- Ref: `nis2-art21-2-b`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> incident handling;

### CIR (EU) 2024/2690 Annex 3.2.1

- Ref: `cir-annex-3-2-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall lay down procedures and use tools to monitor and log activities on their network and information systems to detect events that could be considered as incidents and respond accordingly to mitigate the impact.

## NIS2-K8S-027 (KS-RT-003)

- Check: `KS-RT-003`
- Display ID: `NIS2-K8S-027`
- Title: No admission guard for root, host namespaces, shm hostPath, pickle load (Kyverno)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-028 (KS-PRE-001)

- Check: `KS-PRE-001`
- Display ID: `NIS2-K8S-028`
- Title: Tetragon missing or unhealthy
- Severity: fail

### NIS2 Art. 21(2)(b)

- Ref: `nis2-art21-2-b`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> incident handling;

### CIR (EU) 2024/2690 Annex 3.2.1

- Ref: `cir-annex-3-2-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall lay down procedures and use tools to monitor and log activities on their network and information systems to detect events that could be considered as incidents and respond accordingly to mitigate the impact.

## NIS2-K8S-029 (KS-PRE-002)

- Check: `KS-PRE-002`
- Display ID: `NIS2-K8S-029`
- Title: CNI is not Cilium (L7/FQDN egress not possible)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.8.1

- Ref: `cir-annex-6-8-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall segment systems into networks or zones in accordance with the results of the risk assessment referred to in point 2.1. They shall segment their systems and networks from third parties’ systems and networks.

## NIS2-K8S-030 (KS-PRE-003)

- Check: `KS-PRE-003`
- Display ID: `NIS2-K8S-030`
- Title: Kyverno missing or unhealthy
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(b)

- Ref: `cir-annex-6-3-2-b`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and implement processes and tools to enforce the laid down secure configurations for hardware, software, services and networks, for newly installed systems as well as for systems in operation over their lifetime.

## NIS2-K8S-031 (KS-PRE-004)

- Check: `KS-PRE-004`
- Display ID: `NIS2-K8S-031`
- Title: Node kernel lacks BPF LSM (--node-probe)
- Severity: warn

### NIS2 Art. 21(2)(b)

- Ref: `nis2-art21-2-b`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> incident handling;

### CIR (EU) 2024/2690 Annex 3.2.1

- Ref: `cir-annex-3-2-1`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> The relevant entities shall lay down procedures and use tools to monitor and log activities on their network and information systems to detect events that could be considered as incidents and respond accordingly to mitigate the impact.

## NIS2-K8S-032 (KS-WL-015)

- Check: `KS-WL-015`
- Display ID: `NIS2-K8S-032`
- Title: hostPath volume outside /dev, /dev/shm and GPU devices
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

## NIS2-K8S-033 (KS-WL-016)

- Check: `KS-WL-016`
- Display ID: `NIS2-K8S-033`
- Title: hostPort on an AI container
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

## NIS2-K8S-034 (KS-AI-010)

- Check: `KS-AI-010`
- Display ID: `NIS2-K8S-034`
- Title: Inference engine other than vLLM without API key or gateway auth evidence
- Severity: warn

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## NIS2-K8S-035 (KS-AI-011)

- Check: `KS-AI-011`
- Display ID: `NIS2-K8S-035`
- Title: Debug or insecure flags on an inference engine (--debug, --allow-http, OLLAMA_DEBUG, OLLAMA_ORIGINS *)
- Severity: warn

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.3.2(a)

- Ref: `cir-annex-6-3-2-a`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> lay down and ensure security in configurations for their hardware, software, services and networks;

## NIS2-K8S-036 (KS-AI-012)

- Check: `KS-AI-012`
- Display ID: `NIS2-K8S-036`
- Title: Unsafe model source or format on an inference engine (--trust-remote-code, pickle or Keras file, s3:// or gs:// source)
- Severity: fail

### NIS2 Art. 21(2)(d)

- Ref: `nis2-art21-2-d`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers;

### NIS2 Art. 21(2)(e)

- Ref: `nis2-art21-2-e`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure;

## NIS2-K8S-037 (KS-NET-004)

- Check: `KS-NET-004`
- Display ID: `NIS2-K8S-037`
- Title: AI workload has no ingress isolation (no NetworkPolicy or Cilium policy restricts ingress)
- Severity: warn

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.8.2(e)

- Ref: `cir-annex-6-8-2-e`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> restrict access and communications between and within zones to those necessary for the operation of the relevant entities or for safety;

## NIS2-K8S-038 (KS-AI-013)

- Check: `KS-AI-013`
- Display ID: `NIS2-K8S-038`
- Title: HTTPRoute exposes an AI engine Service without auth evidence (Envoy Gateway SecurityPolicy, Istio, Kong, auth filter)
- Severity: fail

### NIS2 Art. 21(2)(i)

- Ref: `nis2-art21-2-i`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> human resources security, access control policies and asset management;

### NIS2 Art. 21(2)(g)

- Ref: `nis2-art21-2-g`
- Source: Directive (EU) 2022/2555 (NIS2)
- CELEX: 32022L2555
- URL: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>

> basic cyber hygiene practices and cybersecurity training;

### CIR (EU) 2024/2690 Annex 6.7.2(c)

- Ref: `cir-annex-6-7-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> configure controls to prevent accesses and network communication not required for the operation of the relevant entities;

### CIR (EU) 2024/2690 Annex 11.1.2(c)

- Ref: `cir-annex-11-1-2-c`
- Source: Commission Implementing Regulation (EU) 2024/2690
- CELEX: 32024R2690
- URL: <https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj>

> ensure that access is only granted to users that have been adequately authenticated.

## Checks left out of this profile

These registered checks have no fitting requirement in the sources of this profile and are not part of it.

- `KS-WL-006`: No point of NIS2 Art. 21 and no point of the Annex of CIR (EU) 2024/2690 covers emptyDir size limits.
- `KS-WL-013`: No point of NIS2 Art. 21 and no point of the Annex of CIR (EU) 2024/2690 covers memory limits or quotas.

<!-- kshield:signoff - everything below is kept by the generator -->

## Sign-off

| Date | Name | Profile sha256 | Review sha256 | Decision |
|---|---|---|---|---|
