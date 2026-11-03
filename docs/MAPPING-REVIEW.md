# Mapping review - DORA Chapter II - Regulation (EU) 2022/2554 and RTS (EU) 2024/1774

- Profile: `dora`
- Version: 1
- Profile sha256: `a4c816e97c89586b6edfb2bce79c2e18d351b41c350879466df41fb6785c3a90`
- Checks: 33

This file lists each check of the profile in catalog order, with the regulation text that the check is mapped to. A mapping means that the check supports evidence for the cited requirement. It is not an audit and does not state compliance with any regulation.

The quotes are verbatim excerpts from `internal/regtext/sources`. `go run ./tools/mappingreview` writes everything above the sign-off marker. Do not edit that part by hand. The generator keeps everything from the marker line down as it is.

To sign off, read every mapping and add one row to the table under Sign-off: the date (YYYY-MM-DD), your name, the profile sha256 above, and the decision `approved` or `rejected`. The row also carries the review sha256 that `go run ./tools/mappingreview` prints. A change to the profile file changes its sha256, so it needs a new sign-off.

## DORA-CH2-001 (KS-WL-001)

- Check: `KS-WL-001`
- Display ID: `DORA-CH2-001`
- Title: Container may run as root (no runAsNonRoot: true, or UID 0)
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-002 (KS-WL-002)

- Check: `KS-WL-002`
- Display ID: `DORA-CH2-002`
- Title: privileged: true or allowPrivilegeEscalation not false
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-003 (KS-WL-003)

- Check: `KS-WL-003`
- Display ID: `DORA-CH2-003`
- Title: Capabilities not dropped (drop: [ALL] missing)
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-004 (KS-WL-004)

- Check: `KS-WL-004`
- Display ID: `DORA-CH2-004`
- Title: hostIPC, hostPID or hostNetwork true
- Severity: fail

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-005 (KS-WL-005)

- Check: `KS-WL-005`
- Display ID: `DORA-CH2-005`
- Title: /dev/shm from hostPath (or hostPath /dev)
- Severity: fail

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-006 (KS-WL-006)

- Check: `KS-WL-006`
- Display ID: `DORA-CH2-006`
- Title: Memory emptyDir for shm without sizeLimit
- Severity: warn

### DORA Art. 9(2)

- Ref: `dora-art9-2`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall design, procure and implement ICT security policies, procedures, protocols and tools that aim to ensure the resilience, continuity and availability of ICT systems, in particular for those supporting critical or important functions, and to maintain high standards of availability, authenticity, integrity and confidentiality of data, whether at rest, in use or in transit.

## DORA-CH2-007 (KS-WL-007)

- Check: `KS-WL-007`
- Display ID: `DORA-CH2-007`
- Title: shareProcessNamespace: true on AI workload
- Severity: fail

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-008 (KS-WL-008)

- Check: `KS-WL-008`
- Display ID: `DORA-CH2-008`
- Title: Root filesystem writable
- Severity: warn

### DORA Art. 9(3)(b)

- Ref: `dora-art9-3-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> minimise the risk of corruption or loss of data, unauthorised access and technical flaws that may hinder business activity;

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-009 (KS-WL-009)

- Check: `KS-WL-009`
- Display ID: `DORA-CH2-009`
- Title: No seccompProfile: RuntimeDefault
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### RTS 2024/1774 Art. 11(2)(b)

- Ref: `rts-art11-2-b`
- Source: Commission Delegated Regulation (EU) 2024/1774
- CELEX: 32024R1774
- URL: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>

> the identification of a secure configuration baseline for ICT assets that minimise exposure of those ICT assets to cyber threats and measures to verify regularly that those baselines are effectively deployed;

## DORA-CH2-010 (KS-WL-010)

- Check: `KS-WL-010`
- Display ID: `DORA-CH2-010`
- Title: Service account token auto-mounted
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-011 (KS-WL-011)

- Check: `KS-WL-011`
- Display ID: `DORA-CH2-011`
- Title: Secret values in plain env (HF_TOKEN, API keys)
- Severity: fail

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-012 (KS-WL-012)

- Check: `KS-WL-012`
- Display ID: `DORA-CH2-012`
- Title: Image not pinned by digest
- Severity: warn

### DORA Art. 9(4)(e)

- Ref: `dora-art9-4-e`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement documented policies, procedures and controls for ICT change management, including changes to software, hardware, firmware components, systems or security parameters, that are based on a risk assessment approach and are an integral part of the financial entity’s overall change management process, in order to ensure that all changes to ICT systems are recorded, tested, assessed, approved, implemented and verified in a controlled manner;

### RTS 2024/1774 Art. 16(1)(c)

- Ref: `rts-art16-1-c`
- Source: Commission Delegated Regulation (EU) 2024/1774
- CELEX: 32024R1774
- URL: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>

> specify measures to mitigate the risk of unintentional alteration or intentional manipulation of the ICT systems during the development, maintenance, and deployment of those ICT systems in the production environment.

## DORA-CH2-013 (KS-WL-013)

- Check: `KS-WL-013`
- Display ID: `DORA-CH2-013`
- Title: No memory limit on AI workload
- Severity: warn

### DORA Art. 9(2)

- Ref: `dora-art9-2`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall design, procure and implement ICT security policies, procedures, protocols and tools that aim to ensure the resilience, continuity and availability of ICT systems, in particular for those supporting critical or important functions, and to maintain high standards of availability, authenticity, integrity and confidentiality of data, whether at rest, in use or in transit.

## DORA-CH2-014 (KS-WL-014)

- Check: `KS-WL-014`
- Display ID: `DORA-CH2-014`
- Title: GPU access via hostPath /dev/nvidia* or privileged, not device plugin
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-015 (KS-AI-001)

- Check: `KS-AI-001`
- Display ID: `DORA-CH2-015`
- Title: vLLM API without auth (--api-key / VLLM_API_KEY unset)
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### DORA Art. 9(4)(d)

- Ref: `dora-art9-4-d`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes;

## DORA-CH2-016 (KS-AI-002)

- Check: `KS-AI-002`
- Display ID: `DORA-CH2-016`
- Title: vLLM --trust-remote-code set
- Severity: fail

### DORA Art. 9(3)(b)

- Ref: `dora-art9-3-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> minimise the risk of corruption or loss of data, unauthorised access and technical flaws that may hinder business activity;

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-017 (KS-AI-003)

- Check: `KS-AI-003`
- Display ID: `DORA-CH2-017`
- Title: Model load may use pickle
- Severity: fail

### DORA Art. 9(3)(b)

- Ref: `dora-art9-3-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> minimise the risk of corruption or loss of data, unauthorised access and technical flaws that may hinder business activity;

### DORA Art. 9(3)(c)

- Ref: `dora-art9-3-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> prevent the lack of availability, the impairment of the authenticity and integrity, the breaches of confidentiality and the loss of data;

## DORA-CH2-018 (KS-AI-004)

- Check: `KS-AI-004`
- Display ID: `DORA-CH2-018`
- Title: Inference API exposed outside cluster (Service LoadBalancer/NodePort, Ingress) without auth
- Severity: fail

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-019 (KS-AI-005)

- Check: `KS-AI-005`
- Display ID: `DORA-CH2-019`
- Title: Ray GCS 6379, client 10001 or dashboard 8265 exposed beyond ClusterIP
- Severity: fail

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

## DORA-CH2-020 (KS-AI-006)

- Check: `KS-AI-006`
- Display ID: `DORA-CH2-020`
- Title: Ray TLS off (RAY_USE_TLS not 1)
- Severity: fail

### DORA Art. 9(3)(a)

- Ref: `dora-art9-3-a`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> ensure the security of the means of transfer of data;

## DORA-CH2-021 (KS-AI-007)

- Check: `KS-AI-007`
- Display ID: `DORA-CH2-021`
- Title: Ollama 11434 exposed without an auth proxy
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### DORA Art. 9(4)(d)

- Ref: `dora-art9-4-d`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes;

## DORA-CH2-022 (KS-AI-008)

- Check: `KS-AI-008`
- Display ID: `DORA-CH2-022`
- Title: Qdrant without API key or TLS
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### DORA Art. 9(4)(d)

- Ref: `dora-art9-4-d`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes;

### DORA Art. 9(3)(a)

- Ref: `dora-art9-3-a`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> ensure the security of the means of transfer of data;

## DORA-CH2-023 (KS-AI-009)

- Check: `KS-AI-009`
- Display ID: `DORA-CH2-023`
- Title: Milvus authorization disabled
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### DORA Art. 9(4)(d)

- Ref: `dora-art9-4-d`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies and protocols for strong authentication mechanisms, based on relevant standards and dedicated control systems, and protection measures of cryptographic keys whereby data is encrypted based on results of approved data classification and ICT risk assessment processes;

## DORA-CH2-024 (KS-NET-001)

- Check: `KS-NET-001`
- Display ID: `DORA-CH2-024`
- Title: AI namespace has no default-deny egress (no CNP/NetworkPolicy in input or cluster)
- Severity: fail

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

## DORA-CH2-025 (KS-NET-002)

- Check: `KS-NET-002`
- Display ID: `DORA-CH2-025`
- Title: Egress allow-list too broad (world, 0.0.0.0/0)
- Severity: fail

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

## DORA-CH2-026 (KS-NET-003)

- Check: `KS-NET-003`
- Display ID: `DORA-CH2-026`
- Title: Pod-to-pod encryption off (Cilium WireGuard/IPsec)
- Severity: fail

### DORA Art. 9(3)(a)

- Ref: `dora-art9-3-a`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> ensure the security of the means of transfer of data;

## DORA-CH2-027 (KS-RT-001)

- Check: `KS-RT-001`
- Display ID: `DORA-CH2-027`
- Title: No runtime shell-exec guard on AI namespace (Tetragon)
- Severity: fail

### DORA Art. 10(1)

- Ref: `dora-art10-1`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall have in place mechanisms to promptly detect anomalous activities, in accordance with Article 17, including ICT network performance issues and ICT-related incidents, and to identify potential material single points of failure.
>
> All detection mechanisms referred to in the first subparagraph shall be regularly tested in accordance with Article 25.

## DORA-CH2-028 (KS-RT-002)

- Check: `KS-RT-002`
- Display ID: `DORA-CH2-028`
- Title: No runtime egress-connect guard on AI namespace (Tetragon)
- Severity: fail

### DORA Art. 10(1)

- Ref: `dora-art10-1`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall have in place mechanisms to promptly detect anomalous activities, in accordance with Article 17, including ICT network performance issues and ICT-related incidents, and to identify potential material single points of failure.
>
> All detection mechanisms referred to in the first subparagraph shall be regularly tested in accordance with Article 25.

## DORA-CH2-029 (KS-RT-003)

- Check: `KS-RT-003`
- Display ID: `DORA-CH2-029`
- Title: No admission guard for root, host namespaces, shm hostPath, pickle load (Kyverno)
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### RTS 2024/1774 Art. 11(2)(b)

- Ref: `rts-art11-2-b`
- Source: Commission Delegated Regulation (EU) 2024/1774
- CELEX: 32024R1774
- URL: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>

> the identification of a secure configuration baseline for ICT assets that minimise exposure of those ICT assets to cyber threats and measures to verify regularly that those baselines are effectively deployed;

## DORA-CH2-030 (KS-PRE-001)

- Check: `KS-PRE-001`
- Display ID: `DORA-CH2-030`
- Title: Tetragon missing or unhealthy
- Severity: fail

### DORA Art. 10(1)

- Ref: `dora-art10-1`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall have in place mechanisms to promptly detect anomalous activities, in accordance with Article 17, including ICT network performance issues and ICT-related incidents, and to identify potential material single points of failure.
>
> All detection mechanisms referred to in the first subparagraph shall be regularly tested in accordance with Article 25.

## DORA-CH2-031 (KS-PRE-002)

- Check: `KS-PRE-002`
- Display ID: `DORA-CH2-031`
- Title: CNI is not Cilium (L7/FQDN egress not possible)
- Severity: fail

### DORA Art. 9(4)(b)

- Ref: `dora-art9-4-b`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> following a risk-based approach, establish a sound network and infrastructure management structure using appropriate techniques, methods and protocols that may include implementing automated mechanisms to isolate affected information assets in the event of cyber-attacks;

## DORA-CH2-032 (KS-PRE-003)

- Check: `KS-PRE-003`
- Display ID: `DORA-CH2-032`
- Title: Kyverno missing or unhealthy
- Severity: fail

### DORA Art. 9(4)(c)

- Ref: `dora-art9-4-c`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> implement policies that limit the physical or logical access to information assets and ICT assets to what is required for legitimate and approved functions and activities only, and establish to that end a set of policies, procedures and controls that address access rights and ensure a sound administration thereof;

### RTS 2024/1774 Art. 11(2)(b)

- Ref: `rts-art11-2-b`
- Source: Commission Delegated Regulation (EU) 2024/1774
- CELEX: 32024R1774
- URL: <https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj>

> the identification of a secure configuration baseline for ICT assets that minimise exposure of those ICT assets to cyber threats and measures to verify regularly that those baselines are effectively deployed;

## DORA-CH2-033 (KS-PRE-004)

- Check: `KS-PRE-004`
- Display ID: `DORA-CH2-033`
- Title: Node kernel lacks BPF LSM (--node-probe)
- Severity: warn

### DORA Art. 10(1)

- Ref: `dora-art10-1`
- Source: Regulation (EU) 2022/2554 (DORA)
- CELEX: 32022R2554
- URL: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>

> Financial entities shall have in place mechanisms to promptly detect anomalous activities, in accordance with Article 17, including ICT network performance issues and ICT-related incidents, and to identify potential material single points of failure.
>
> All detection mechanisms referred to in the first subparagraph shall be regularly tested in accordance with Article 25.

<!-- kshield:signoff - everything below is kept by the generator -->

## Sign-off

| Date | Name | Profile sha256 | Review sha256 | Decision |
|---|---|---|---|---|
| 2026-10-18 | Stanislav | a4c816e97c89586b6edfb2bce79c2e18d351b41c350879466df41fb6785c3a90 | f4af4a8037239c86080c98483525cd588e1b4997a1aee63db7d4412a5614f2a8 | approved |
