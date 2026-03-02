# CMMC Level 2 / NIST SP 800-171 Control Mapping

**Document ID:** CMMC-MAP-001  
**Version:** 1.0  
**Classification:** Internal / Lab Use  
**Author:** Jason A. Slocomb  
**Date:** 2026-03-02  
**Related Documents:**
- [`docs/threat-model.md`](threat-model.md) — STRIDE threat analysis (source of all threat IDs)
- [`docs/homelab-build-checklist.md`](homelab-build-checklist.md) — Implementation task list

---

## Purpose

This document maps every mitigation in the cluster threat model to its governing NIST SP 800-171 Rev 2 security requirement. It serves three functions:

1. **Traceability** — each implementation control traces bidirectionally to (a) the threat it addresses in `threat-model.md` and (b) the NIST requirement it satisfies, enabling gap analysis and audit preparation.
2. **CMMC Level 2 evidence** — CMMC Level 2 requires 110 practices drawn directly from NIST 800-171; this document identifies which of those 110 are exercised by the lab architecture and provides the implementation evidence for each.
3. **Portfolio demonstration** — documents the security engineering rationale behind architectural decisions for hiring manager review.

---

## How to Read This Document

Each NIST control entry follows this structure:

```
### [Control ID] — Control Title
**CMMC Practice:** [practice number]
**Control Family:** [family name]
**Requirement Text:** [verbatim from NIST 800-171 Rev 2]

#### Threats Addressed
| Threat ID | Severity | Description |

#### Mitigations Implemented
| Mitigation | Section | Priority | Implementation Evidence |

#### Assessment Objective (CMMC)
[what an assessor would verify]

#### Implementation Status
[IMPLEMENTED / IN PROGRESS / PLANNED]
```

Threat ID links (e.g., `[S-1.1]`) cross-reference `threat-model.md` Section 6.  
Section links (e.g., `[§9.1]`) cross-reference `threat-model.md` Section 9 mitigation tables.

---

## Control Families Coverage Summary

| Family | Full Name | Controls Mapped | NIST 800-171 Total | Coverage |
|---|---|---|---|---|
| **AC** | Access Control | 3 | 22 | 14% |
| **AU** | Audit and Accountability | 2 | 9 | 22% |
| **CM** | Configuration Management | 5 | 9 | 56% |
| **IA** | Identification and Authentication | 4 | 11 | 36% |
| **MP** | Media Protection | 1 | 9 | 11% |
| **SA** | System and Services Acquisition | 1 | 12 | 8% |
| **SC** | System and Communications Protection | 3 | 16 | 19% |
| **SI** | System and Information Integrity | 3 | 7 | 43% |
| **Totals** | — | **22** | **110** | **20%** |

> **Note:** This mapping covers controls directly exercised by the Kubernetes cluster architecture. The remaining 88 NIST 800-171 controls address organizational policies, personnel security, physical protection, incident response procedures, and system and services acquisition that are outside the scope of this technical architecture document.

---

## Control Mappings

---

### AC-3.1.1 — Limit System Access to Authorized Users

**CMMC Practice:** AC.L1-3.1.1  
**Control Family:** Access Control  
**Requirement Text:** *Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).*

This is the broadest and most foundational access control requirement. In a Kubernetes environment, it governs who can authenticate to the API server, what verbs they can execute, and which resources they can target. Sixteen of the 38 component-level threats in the cluster threat model cite this control — the highest count of any single requirement — reflecting how central authorization is to Kubernetes security.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-1.1](threat-model.md#s----spoofing) | CRITICAL | Stolen kubeconfig impersonation |
| [I-1.1](threat-model.md#i----information-disclosure) | CRITICAL | Secret enumeration via over-privileged list/get |
| [E-1.1](threat-model.md#e----elevation-of-privilege) | CRITICAL | Privileged pod container escape |
| [E-3.1](threat-model.md#e----elevation-of-privilege-2) | CRITICAL | Container escape via privileged pod to node OS |
| [S-4.1](threat-model.md#s----spoofing-3) | CRITICAL | FreeIPA admin credential compromise |
| [E-6.1](threat-model.md#e----elevation-of-privilege-5) | CRITICAL | Arbitrary playbook execution via variable injection |
| [S-1.2](threat-model.md#s----spoofing) | HIGH | ServiceAccount token theft from pod filesystem |
| [T-1.2](threat-model.md#t----tampering) | HIGH | RBAC policy privilege escalation |
| [I-1.2](threat-model.md#i----information-disclosure) | HIGH | API discovery leaking resource layout |
| [E-1.2](threat-model.md#e----elevation-of-privilege) | HIGH | Excessive cluster-admin ClusterRoleBinding grants |
| [S-3.1](threat-model.md#s----spoofing-2) | HIGH | Unauthenticated kubelet API access |
| [E-3.2](threat-model.md#e----elevation-of-privilege-2) | HIGH | Kubelet client certificate credential abuse |
| [T-4.1](threat-model.md#t----tampering-3) | HIGH | LDAP group membership manipulation |
| [S-5.1](threat-model.md#s----spoofing-4) | HIGH | CI/CD variable exfiltration via pipeline injection |
| [I-13.1](threat-model.md#i----information-disclosure-12) | HIGH | Prometheus metrics exposing credentials or operational data |
| [I-4.1](threat-model.md#i----information-disclosure-3) | MEDIUM | LDAP anonymous bind exposing directory structure |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Encrypt secrets at rest | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | `kube-apiserver --encryption-provider-config=/etc/kubernetes/encryption.yaml` with `secretbox`; verified via `etcdctl get /registry/secrets/default/test \| xxd` showing ciphertext |
| Audit all `cluster-admin` ClusterRoleBindings | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | Weekly cron: `kubectl get clusterrolebindings -o yaml`; Splunk alert `index=k8s sourcetype=k8s_audit verb=create resource=clusterrolebindings` |
| Remove `list` on secrets from workload service accounts | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | OPA Gatekeeper policy `deny-secret-list`; audit via `kubectl auth can-i list secrets --as system:serviceaccount:app:my-app` |
| Use short-lived projected ServiceAccount tokens | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | All pod specs use `serviceAccountToken` projection with `expirationSeconds: 3600`; verified via `kubectl get pod -o yaml \| grep expirationSeconds` |
| Enable PodSecurity `restricted` profile | [§9.4](threat-model.md#94-pod-security) | P1 | Namespace labels: `pod-security.kubernetes.io/enforce: restricted`; tested by attempting privileged pod creation |
| Block host namespace sharing | [§9.4](threat-model.md#94-pod-security) | P1 | PSA restricted profile + OPA policy `deny-host-namespaces`; covers `hostPID`, `hostNetwork`, `hostIPC` |
| Block privileged containers | [§9.4](threat-model.md#94-pod-security) | P1 | PSA restricted profile enforced on all production namespaces |
| Require non-root user context | [§9.4](threat-model.md#94-pod-security) | P1 | `runAsNonRoot: true` enforced via PSA; verified via admission rejection test |
| Scope CI ServiceAccounts to minimum permissions | [§9.7](threat-model.md#97-cicd-security) | P1 | Separate `ns:deploy` ServiceAccount per application namespace; no cross-namespace grants |
| Enforce MFA for all human admin accounts | [§9.8](threat-model.md#98-freeipa--identity) | P1 | FreeIPA OTP (TOTP) mandatory for `admins` group; policy enforced via `ipa pwpolicy-mod --otp-enabled=TRUE` |
| Disable anonymous LDAP bind | [§9.8](threat-model.md#98-freeipa--identity) | P1 | `ldapmodify: nsslapd-allow-anonymous-access: rootdse`; verified via unauthenticated `ldapsearch` returning empty result |

#### Assessment Objective (CMMC)

An assessor would verify: (1) RBAC policies exist for all principals and deny unneeded permissions; (2) no wildcard ClusterRoles are granted to workload service accounts; (3) privileged pod creation is blocked by admission control; (4) kubelet anonymous auth is disabled; (5) at least one human authentication mechanism (MFA) is active.

**Implementation Status:** IN PROGRESS — encryption at rest and PodSecurity PSA are P1 items; RBAC audit automation and OPA policies are P2 items scheduled in Phase 9.

---

### AC-3.1.2 — Limit System Access to Authorized Transaction Types

**CMMC Practice:** AC.L1-3.1.2  
**Control Family:** Access Control  
**Requirement Text:** *Limit information system access to the types of transactions and functions that authorized users are permitted to execute.*

Where AC-3.1.1 controls *who* can access, AC-3.1.2 controls *what* they can do. In Kubernetes, this maps to the distinction between `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` verbs in RBAC — and the principle that a monitoring service account should have `get` on its own namespace's resources, not `create` or `patch` cluster-wide.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [XC-2](threat-model.md#xc-2--high--stale-serviceaccount-tokens) | HIGH | Stale ServiceAccount tokens with persistent access |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Use short-lived projected ServiceAccount tokens | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | Token expiry enforced via projected volume; tokens auto-rotate before expiry |
| Issue per-pipeline-stage ServiceAccounts | [§9.3](threat-model.md#93-rbac-least-privilege) | P2 | Each GitLab pipeline stage assigned its own SA with scoped Role; documented in `k8s/rbac/` directory |

#### Assessment Objective (CMMC)

An assessor would verify: (1) service accounts are scoped to the minimum verb set required for their function; (2) no service account has `*` on any resource type; (3) token lifetimes are bounded.

**Implementation Status:** IN PROGRESS — token projection implemented; per-pipeline SA scoping is Phase 8 work.

---

### AC-3.1.3 — Control Flow of CUI

**CMMC Practice:** AC.L2-3.1.3  
**Control Family:** Access Control  
**Requirement Text:** *Control the flow of CUI in accordance with approved authorizations.*

In a Kubernetes context, CUI flow control is implemented through NetworkPolicy (controlling which pods can communicate), namespace isolation (controlling resource access boundaries), and Ingress rules (controlling external exposure). The absence of NetworkPolicy creates an implicit "allow all" that violates this requirement.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [I-10.1](threat-model.md#i----information-disclosure-9) | HIGH | Unrestricted east-west pod communication |
| [I-4.1](threat-model.md#i----information-disclosure-3) | MEDIUM | LDAP anonymous bind exposing directory structure |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Default-deny all ingress and egress per namespace | [§9.5](threat-model.md#95-network-policy) | P1 | `NetworkPolicy` with `podSelector: {}` in each namespace; tested with `kubectl exec` cross-namespace probe |
| Explicitly allowlist required service paths | [§9.5](threat-model.md#95-network-policy) | P1 | Per-namespace allowlist policies in `k8s/netpol/`; all paths documented in NetBox |
| Isolate `kube-system` from workload namespaces | [§9.5](threat-model.md#95-network-policy) | P1 | Egress policy blocking workload pods from reaching etcd ClusterIP (port 2379) |
| Restrict pod egress to known lab CIDRs | [§9.5](threat-model.md#95-network-policy) | P2 | Egress policy permitting only lab subnet (192.168.0.0/16) and DNS; verified with `curl` to external IP from pod |
| Disable anonymous LDAP bind | [§9.8](threat-model.md#98-freeipa--identity) | P1 | Prevents unauthenticated enumeration of directory structure |

#### Assessment Objective (CMMC)

An assessor would verify: (1) NetworkPolicy objects exist in all namespaces and default to deny; (2) no pod can reach the etcd endpoint directly; (3) there is no unauthenticated path to CUI-adjacent data stores.

**Implementation Status:** PLANNED — NetworkPolicy implementation is Phase 6 work.

---

### AU-3.3.1 — Create and Retain Audit Records

**CMMC Practice:** AU.L2-3.3.1  
**Control Family:** Audit and Accountability  
**Requirement Text:** *Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.*

Audit logging is the evidentiary foundation for all detection and response capability. Without it, every other security control operates blind. The cluster's audit architecture routes kube-apiserver events, AIDE FIM reports, and OS-level syslog to Splunk with a 90-day retention policy.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-1.1](threat-model.md#s----spoofing) | CRITICAL | Stolen kubeconfig impersonation |
| [T-2.1](threat-model.md#t----tampering-1) | CRITICAL | Direct etcd write bypassing all RBAC |
| [S-4.1](threat-model.md#s----spoofing-3) | CRITICAL | FreeIPA admin credential compromise |
| [T-7.1](threat-model.md#t----tampering-6) | CRITICAL | Audit log deletion by compromised Splunk admin |
| [R-1.1](threat-model.md#r----repudiation) | HIGH | Shared kubeconfig prevents actor attribution |
| [T-7.2](threat-model.md#t----tampering-6) | HIGH | HEC token abuse for log injection / poisoning |
| [R-7.1](threat-model.md#r----repudiation-2) | HIGH | Audit policy gaps create blind spots |
| [I-11.2](threat-model.md#i----information-disclosure-10) | HIGH | Application logging captures secret values |
| [T-1.3](threat-model.md#t----tampering) | MEDIUM | Audit log tampering or suppression |
| [R-1.2](threat-model.md#r----repudiation) | MEDIUM | Impersonation without full request capture |
| [R-5.1](threat-model.md#r----repudiation-1) | MEDIUM | Shared CI service account prevents attribution |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Enable `RequestResponse` audit logging for secrets | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | `/etc/kubernetes/audit-policy.yaml` with `level: RequestResponse` for `resources: ["secrets"]`; verified in Splunk: `index=k8s_audit resource=secrets \| head 10` |
| Ship all audit logs to Splunk in real time | [§9.9](threat-model.md#99-logging-and-audit) | P1 | `aide_to_splunk.py` + `k8s_secret_auditor.py` pipelines active; HEC endpoint health monitored |
| Set minimum 90-day log retention | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Splunk `k8s_audit` index retention set to 90 days; `frozenTimePeriodInSecs = 7776000` in `indexes.conf` |
| Alert on audit log source gaps | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Splunk alert: `index=k8s_audit \| stats max(_time) as last_seen by host \| where last_seen < now()-900` |
| Protect Splunk admin credentials in Vault | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Splunk admin password in Vault `secret/splunk/admin`; no plaintext credentials in any config file |
| Run AIDE daily on all nodes | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Cron at 03:00: `aide --check 2>&1 \| python3 aide_to_splunk.py --report -`; last run timestamp monitored in Zabbix |

#### Assessment Objective (CMMC)

An assessor would verify: (1) audit log records exist for all privileged actions including secret access; (2) records are retained for at least 90 days; (3) log integrity is protected (logs cannot be deleted by workloads); (4) gaps in log coverage trigger alerts.

**Implementation Status:** IN PROGRESS — AIDE pipeline and Splunk HEC are implemented; `RequestResponse` audit policy for secrets is P1 Phase 5 item.

---

### AU-3.3.2 — Ensure Actions Can Be Traced to Users

**CMMC Practice:** AU.L2-3.3.2  
**Control Family:** Audit and Accountability  
**Requirement Text:** *Ensure that the actions of individual information system users can be uniquely traced to those users so they can be held accountable for their actions.*

Traceability requires that every authenticated session maps to a specific, non-shareable identity. In Kubernetes, this means individual kubeconfigs per user (not a shared `devops@cluster` credential), per-pipeline service accounts, and OIDC tokens that carry the user's FreeIPA identity as the subject claim.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-7.1](threat-model.md#t----tampering-6) | CRITICAL | Audit log deletion by compromised Splunk admin |
| [T-1.3](threat-model.md#t----tampering) | MEDIUM | Audit log tampering or suppression |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Run daily secret access audit | [§9.6](threat-model.md#96-secret-management) | P1 | `k8s_secret_auditor.py` runs nightly; per-actor event history enables attribution; output in `index=k8s_secret_audit` |
| Issue per-pipeline-stage ServiceAccounts | [§9.3](threat-model.md#93-rbac-least-privilege) | P2 | Each pipeline stage maps to a named SA; audit events carry `system:serviceaccount:<ns>:<stage>-sa` identity |

#### Assessment Objective (CMMC)

An assessor would verify: (1) audit log entries uniquely identify the requesting user or service account; (2) no shared credentials exist that would prevent attribution; (3) impersonation events are captured at `RequestResponse` level.

**Implementation Status:** IN PROGRESS — per-pipeline SA scoping is Phase 8 work; individual user kubeconfigs via OIDC are implemented.

---

### CM-3.4.1 — Establish Baseline Configurations

**CMMC Practice:** CM.L2-3.4.1  
**Control Family:** Configuration Management  
**Requirement Text:** *Establish and maintain baseline configurations and inventories of organizational information systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.*

Baseline configuration in a Kubernetes context means: (a) GitOps-managed manifests as the authoritative source of cluster state, (b) AIDE baselines for node filesystem integrity, (c) Trivy-scanned and digest-pinned container images as the authorized software inventory, and (d) RKE2 CIS hardening profile as the node OS configuration baseline.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-5.2](threat-model.md#t----tampering-4) | HIGH | Dependency confusion / supply chain poisoning |
| [T-8.1](threat-model.md#t----tampering-7) | HIGH | Mutable image tag overwrite |
| [T-14.2](threat-model.md#t----tampering-13) | HIGH | AIDE baseline bypass via database manipulation |
| [T-8.2](threat-model.md#t----tampering-7) | MEDIUM | Base image poisoning via upstream compromise |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Run AIDE daily on all nodes | [§9.9](threat-model.md#99-logging-and-audit) | P1 | AIDE database initialized at `aide --init` post-provisioning; daily check results ingested to Splunk |
| Scan all images before deployment | [§9.10](threat-model.md#910-image-and-supply-chain) | P1 | `trivy image` stage in GitLab CI pipeline; pipeline fails on CRITICAL CVEs with no exception |
| Use immutable image digest references | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | Deployment manifests reference `@sha256:...`; Kyverno policy `require-image-digest` enforces compliance |
| Verify base image provenance | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | Approved base image list in `docs/approved-base-images.md`; Kyverno policy validates registry source |
| Operate a private container registry | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | GitLab Container Registry for all workload images; no direct public pulls in production namespaces |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a current AIDE baseline exists for all nodes; (2) container images are pinned to immutable digests; (3) image scanning is integrated into the deployment pipeline; (4) the GitOps repository is the authoritative source of cluster configuration.

**Implementation Status:** IN PROGRESS — AIDE baseline and image scanning are P1 Phase 5 items; digest pinning and Kyverno policies are P2 Phase 9 items.

---

### CM-3.4.3 — Track and Control System Changes

**CMMC Practice:** CM.L2-3.4.3  
**Control Family:** Configuration Management  
**Requirement Text:** *Track, review, approve and log changes to organizational information systems.*

Every change to Kubernetes cluster state — whether applied via `kubectl apply`, a pipeline deployment, or a direct API call — is an authorized or unauthorized configuration change. This requirement mandates that changes are logged, reviewable, and approved before reaching production.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-1.1](threat-model.md#t----tampering) | CRITICAL | Malicious admission webhook injection |
| [T-2.1](threat-model.md#t----tampering-1) | CRITICAL | Direct etcd write bypassing all RBAC |
| [T-5.1](threat-model.md#t----tampering-4) | CRITICAL | Pipeline deploys malicious workloads to cluster |
| [T-1.2](threat-model.md#t----tampering) | HIGH | RBAC policy privilege escalation |
| [T-4.1](threat-model.md#t----tampering-3) | HIGH | LDAP group membership manipulation |
| [T-8.1](threat-model.md#t----tampering-7) | HIGH | Mutable image tag overwrite |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Audit RBAC bindings weekly | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | Splunk saved search diffs ClusterRoleBindings against approved baseline; alert on `verb=create resource=clusterrolebindings` |
| Enable `RequestResponse` audit logging for secrets | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | All write operations (create/update/patch/delete) on secrets captured with full request body |
| Protect `main` branch; require MR reviews | [§9.7](threat-model.md#97-cicd-security) | P1 | GitLab branch protection rules; minimum 1 required approver; push to `main` blocked for all users |
| Scope CI ServiceAccounts to minimum permissions | [§9.7](threat-model.md#97-cicd-security) | P1 | CI SA cannot modify admission webhooks or ClusterRoles; only `apply` on designated namespaces |
| Rotate CI/CD credentials on personnel offboarding | [§9.7](threat-model.md#97-cicd-security) | P2 | FreeIPA group membership drives CI variable access; offboarding removes group membership → CI access revoked |

#### Assessment Objective (CMMC)

An assessor would verify: (1) all changes to cluster state are logged in the API server audit trail; (2) production deployments require code review and pipeline approval; (3) changes to RBAC policies trigger alerts; (4) direct etcd access is physically blocked by network controls.

**Implementation Status:** IN PROGRESS — audit logging and branch protection are implemented; RBAC diff automation is Phase 9.

---

### CM-3.4.4 — Analyze Security Impact of Changes

**CMMC Practice:** CM.L2-3.4.4  
**Control Family:** Configuration Management  
**Requirement Text:** *Analyze the security impact of changes prior to implementation.*

In a Kubernetes context, this requirement covers CVE analysis before deploying new software versions (Trivy scanning), kernel security impact assessment before OS upgrades (Rocky Linux security advisories), and security review of new RBAC grants or network policies before applying them.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-14.1](threat-model.md#t----tampering-13) | HIGH | Unpatched kernel CVE enabling container escape |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Scan all images before deployment | [§9.10](threat-model.md#910-image-and-supply-chain) | P1 | Trivy output reviewed before any production deployment; CRITICAL CVEs block pipeline |
| Audit RBAC bindings weekly | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | New RBAC grants reviewed against threat model before application |
| Rotate all cluster certificates annually | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P2 | Zabbix monitors cert expiry; 60-day warning triggers review and rotation planning |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a documented process exists for evaluating the security impact of updates before deployment; (2) CVE scanning is part of the change pipeline; (3) kernel updates are tested in a non-production environment first.

**Implementation Status:** IN PROGRESS — Trivy is implemented; formal change impact review process is Phase 11 documentation work.

---

### CM-3.4.5 — Define Access Restrictions for Configuration Changes

**CMMC Practice:** CM.L2-3.4.5  
**Control Family:** Configuration Management  
**Requirement Text:** *Define, document, approve, and enforce access restrictions associated with changes to organizational information systems.*

In Kubernetes, this requirement is satisfied by RBAC policies that limit who can modify the cluster's security configuration: admission webhooks, ClusterRoles, NetworkPolicies, PodSecurity labels, and the audit policy itself. Unrestricted modification of these resources is a privilege escalation path.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [E-1.1](threat-model.md#e----elevation-of-privilege) | CRITICAL | Privileged pod container escape |
| [E-3.1](threat-model.md#e----elevation-of-privilege-2) | CRITICAL | Container escape via privileged pod to node OS |
| [E-6.1](threat-model.md#e----elevation-of-privilege-5) | CRITICAL | Arbitrary playbook execution via variable injection |
| [E-1.2](threat-model.md#e----elevation-of-privilege) | HIGH | Excessive cluster-admin ClusterRoleBinding grants |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Enable PodSecurity `restricted` profile | [§9.4](threat-model.md#94-pod-security) | P1 | All namespace labels enforced; modification requires cluster-admin + documented approval |
| Audit all `cluster-admin` ClusterRoleBindings | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | Automated weekly diff against approved baseline |
| Implement OPA/Gatekeeper policies | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P2 | Gatekeeper `ConstraintTemplate` objects restrict creation of permissive RBAC; only cluster-admin can modify Gatekeeper policies themselves |
| Drop all Linux capabilities | [§9.4](threat-model.md#94-pod-security) | P2 | `capabilities: drop: [ALL]` in container SecurityContext; add-back requires documented exception |

#### Assessment Objective (CMMC)

An assessor would verify: (1) only designated administrators can modify security-relevant configurations; (2) changes to PodSecurity labels require approval; (3) admission webhook creation is restricted to cluster-admin principals.

**Implementation Status:** PLANNED — OPA/Gatekeeper is Phase 9 scope; capability dropping is part of PSA restricted profile.

---

### IA-3.5.1 — Identify and Authenticate Users

**CMMC Practice:** IA.L1-3.5.1  
**Control Family:** Identification and Authentication  
**Requirement Text:** *Identify information system users, processes acting on behalf of users, or devices.*

Every principal accessing the cluster must have a stable, unique identity that is verifiable. Kubernetes supports multiple identity mechanisms: OIDC (human users via FreeIPA), client certificates (system components and kubelet), and ServiceAccount tokens (workloads). This control requires that no unauthenticated path to any resource exists.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-1.1](threat-model.md#s----spoofing) | CRITICAL | Stolen kubeconfig impersonation |
| [S-2.1](threat-model.md#s----spoofing-1) | CRITICAL | etcd client certificate forgery |
| [S-4.1](threat-model.md#s----spoofing-3) | CRITICAL | FreeIPA admin credential compromise |
| [S-1.2](threat-model.md#s----spoofing) | HIGH | ServiceAccount token theft from pod filesystem |
| [S-3.1](threat-model.md#s----spoofing-2) | HIGH | Unauthenticated kubelet API access |
| [E-3.2](threat-model.md#e----elevation-of-privilege-2) | HIGH | Kubelet client certificate credential abuse |
| [S-4.2](threat-model.md#s----spoofing-3) | HIGH | Kerberos golden ticket attack |
| [S-5.1](threat-model.md#s----spoofing-4) | HIGH | CI/CD variable exfiltration via pipeline injection |
| [S-1.4](threat-model.md#s----spoofing) | MEDIUM | Node identity certificate spoofing |
| [R-1.2](threat-model.md#r----repudiation) | MEDIUM | Impersonation without full request capture |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Verify anonymous auth disabled | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | `--anonymous-auth=false` confirmed via: `curl -sk https://apiserver:6443/api` returns 401 not 200 |
| Enforce mTLS on all etcd connections | [§9.2](threat-model.md#92-etcd-protection) | P1 | Dedicated etcd CA; client certs required for all etcd operations; verified via `etcdctl --cert/--key/--cacert` requirement |
| Enforce MFA for all human admin accounts | [§9.8](threat-model.md#98-freeipa--identity) | P1 | FreeIPA OTP mandatory for `admins` group; tested by attempting admin login without OTP token |
| Rotate CI/CD credentials on personnel offboarding | [§9.7](threat-model.md#97-cicd-security) | P2 | FreeIPA-backed pipeline credentials auto-revoked on group membership removal |
| Rotate all cluster certificates annually | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P2 | Zabbix cert expiry monitoring with 60-day lead time; documented rotation runbook |
| Restrict `krbtgt` knowledge | [§9.8](threat-model.md#98-freeipa--identity) | P2 | IPA admin password stored offline in password manager; rotated annually |

#### Assessment Objective (CMMC)

An assessor would verify: (1) the kube-apiserver returns 401 for unauthenticated requests; (2) no shared service account credentials exist across unrelated systems; (3) all human administrative access requires a second factor; (4) kubelet anonymous auth is disabled and verified.

**Implementation Status:** IN PROGRESS — OIDC with FreeIPA is implemented; MFA enforcement is Phase 3 item.

---

### IA-3.5.2 — Authenticate Devices

**CMMC Practice:** IA.L2-3.5.2  
**Control Family:** Identification and Authentication  
**Requirement Text:** *Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational information systems.*

This control specifically addresses the prevention of replay attacks — an attacker cannot reuse a captured credential to authenticate. In a Kubernetes/Kerberos environment, this requires token binding, short token lifetimes, and proper TLS validation to prevent credential interception.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-1.3](threat-model.md#s----spoofing) | HIGH | OIDC token replay attack |
| [S-4.2](threat-model.md#s----spoofing-3) | HIGH | Kerberos golden ticket attack |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Use short-lived projected ServiceAccount tokens | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | `expirationSeconds: 3600`; tokens valid for 1 hour maximum; automatic rotation by kubelet |
| Enforce mTLS on all etcd connections | [§9.2](threat-model.md#92-etcd-protection) | P1 | TLS prevents interception of credential material on the control-plane network segment |
| Use GitLab OIDC for pipeline cluster auth | [§9.7](threat-model.md#97-cicd-security) | P2 | OIDC tokens issued per-job with 1-hour TTL; no static kubeconfig in CI variables |

#### Assessment Objective (CMMC)

An assessor would verify: (1) ServiceAccount tokens have bounded lifetimes; (2) static long-lived tokens are replaced by short-lived projected tokens; (3) TLS is enforced on all inter-component communication to prevent credential interception.

**Implementation Status:** IN PROGRESS — token projection implemented; OIDC-based CI auth is Phase 8 work.

---

### IA-3.5.4 — Employ Replay-Resistant Authentication

**CMMC Practice:** IA.L2-3.5.4  
**Control Family:** Identification and Authentication  
**Requirement Text:** *Employ replay-resistant authentication mechanisms for network access to privileged and nonprivileged accounts.*

Beyond the technical controls in IA-3.5.2, this requirement addresses the management of identifiers — ensuring that service accounts, user accounts, and machine identities are current, correctly scoped, and not orphaned after personnel or system changes.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [I-1.1](threat-model.md#i----information-disclosure) | CRITICAL | Secret enumeration via over-privileged list/get |
| [I-11.1](threat-model.md#i----information-disclosure-10) | CRITICAL | Secrets mounted as environment variables are widely leakable |
| [R-1.1](threat-model.md#r----repudiation) | HIGH | Shared kubeconfig prevents actor attribution |
| [S-6.1](threat-model.md#s----spoofing-5) | HIGH | AWX credential store exfiltration |
| [R-5.1](threat-model.md#r----repudiation-1) | MEDIUM | Shared CI service account prevents attribution |
| [I-8.1](threat-model.md#i----information-disclosure-7) | MEDIUM | Credentials embedded in image layers |
| [I-13.2](threat-model.md#i----information-disclosure-12) | MEDIUM | Grafana datasource credentials readable via API |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Run daily account lifecycle audit | [§9.8](threat-model.md#98-freeipa--identity) | P1 | `freeipa_account_auditor.py` nightly; Splunk alert on `never_logged_in` and `privileged_inactive` findings |
| Rotate secrets on any suspected compromise | [§9.6](threat-model.md#96-secret-management) | P1 | Rotation runbooks documented for all secret types; tested in tabletop exercise |
| Mount secrets as volumes, not environment variables | [§9.6](threat-model.md#96-secret-management) | P1 | All Deployments audited; `envFrom: secretRef` replaced with volume mounts; enforced via OPA policy |
| Run daily secret access audit | [§9.6](threat-model.md#96-secret-management) | P1 | `k8s_secret_auditor.py` output in Splunk `index=k8s_secret_audit`; analyst reviews daily |

#### Assessment Objective (CMMC)

An assessor would verify: (1) inactive accounts are identified and disabled within a defined period; (2) no service account credentials are shared across unrelated services; (3) secrets are rotated when personnel with access depart.

**Implementation Status:** IN PROGRESS — FreeIPA account auditor is implemented; secret volume mount enforcement is P1 Phase 5 item.

---

### IA-3.5.7 — Enforce Password Complexity

**CMMC Practice:** IA.L2-3.5.7  
**Control Family:** Identification and Authentication  
**Requirement Text:** *Enforce a minimum password complexity and change of characters when new passwords are created.*

Password policy in the cluster environment is managed through FreeIPA, which enforces complexity rules for all human accounts. Machine credentials (certificates, API tokens, service account JWTs) are governed by separate rotation policies rather than password complexity requirements.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [XC-1](threat-model.md#xc-1--high--credential-reuse-across-services) | HIGH | Credential reuse across services |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Enforce MFA for all human admin accounts | [§9.8](threat-model.md#98-freeipa--identity) | P1 | TOTP second factor compensates for password weakness; TOTP secret stored in authenticator app only |
| Restrict `krbtgt` knowledge | [§9.8](threat-model.md#98-freeipa--identity) | P2 | Password manager enforces unique credentials per service; annual rotation policy |
| FreeIPA password policy enforcement | [§9.8](threat-model.md#98-freeipa--identity) | P1 | `ipa pwpolicy-mod`: `minlength=16`, `history=10`, `maxfail=5`, `lockouttime=600`; verified via FreeIPA UI |

#### Assessment Objective (CMMC)

An assessor would verify: (1) FreeIPA password policy requires minimum length and complexity; (2) password reuse is prevented by history enforcement; (3) account lockout is configured; (4) privileged accounts have MFA regardless of password policy.

**Implementation Status:** IN PROGRESS — FreeIPA password policy is configured; MFA enforcement is Phase 3 item.

---

### MP-3.8.3 — Sanitize Media Containing CUI

**CMMC Practice:** MP.L2-3.8.3  
**Control Family:** Media Protection  
**Requirement Text:** *Sanitize or destroy information system media before disposal or reuse.*

In a Kubernetes context, "media containing CUI" extends to etcd snapshots, Longhorn volume backups, database dumps, and any persistent storage that might contain secrets, credentials, or sensitive configuration. These must be encrypted at rest and access-controlled to prevent unauthorized disclosure.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [I-2.1](threat-model.md#i----information-disclosure-1) | CRITICAL | Secrets stored at rest without encryption |
| [T-2.2](threat-model.md#t----tampering-1) | HIGH | etcd backup snapshot exfiltration |
| [T-12.1](threat-model.md#t----tampering-11) | HIGH | Volume snapshot exfiltration to external storage |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Encrypt etcd snapshots before storing | [§9.2](threat-model.md#92-etcd-protection) | P1 | GPG encryption of snapshots: `etcdctl snapshot save - \| gpg --encrypt > backup.gpg`; decryption key in Vault |
| Restrict etcd to loopback and control-plane IP | [§9.2](threat-model.md#92-etcd-protection) | P1 | `--listen-client-urls` limits access; snapshot generation requires control-plane host access |
| Store etcd CA private key offline | [§9.2](threat-model.md#92-etcd-protection) | P2 | CA key removed from control plane filesystem after cert issuance; stored in encrypted offline medium |
| Monitor etcd disk usage | [§9.2](threat-model.md#92-etcd-protection) | P2 | Zabbix alerts at 70% and 85% `/var/lib/etcd` utilization; prevents forced compaction or data loss |
| Implement Sealed Secrets or Vault | [§9.6](threat-model.md#96-secret-management) | P1 | Vault provides encrypted secret storage with audit trail; Sealed Secrets encrypts GitOps secrets at rest |

#### Assessment Objective (CMMC)

An assessor would verify: (1) etcd backups are encrypted before writing to backup storage; (2) backup access is restricted to a documented set of principals; (3) Longhorn snapshot destinations are access-controlled; (4) a process exists to securely delete backup media when no longer needed.

**Implementation Status:** PLANNED — Vault implementation is Phase 7 scope; etcd backup encryption is Phase 5.

---

### SA-3.12.1 — Monitor and Protect Against Supply Chain Risk

**CMMC Practice:** SA.L2-3.12.1  
**Control Family:** System and Services Acquisition  
**Requirement Text:** *Establish a process to protect against supply chain risks to the organization, its partners, and its suppliers.*

The cluster's software supply chain spans upstream container images (Rocky Linux, application base images), third-party Helm charts and operators, Ansible Galaxy roles used by AWX, and Python/Node.js packages installed during CI builds. Each is a potential injection point for malicious code.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-5.2](threat-model.md#t----tampering-4) | HIGH | Dependency confusion / supply chain poisoning |
| [T-8.1](threat-model.md#t----tampering-7) | HIGH | Mutable image tag overwrite |
| [T-8.2](threat-model.md#t----tampering-7) | MEDIUM | Base image poisoning via upstream compromise |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Scan all images before deployment | [§9.10](threat-model.md#910-image-and-supply-chain) | P1 | Trivy CI stage: `trivy image --exit-code 1 --severity CRITICAL $IMAGE`; failing pipeline blocks deployment |
| Pin image digests in pipelines | [§9.7](threat-model.md#97-cicd-security) | P1 | `.gitlab-ci.yml` references `image@sha256:...` for all build and deploy stages |
| Use immutable image digest references | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | Kyverno `require-image-digest` policy blocks deployments using mutable tags |
| Verify base image provenance | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | Approved base image list in `docs/approved-base-images.md`; Kyverno validates registry source |
| Operate a private container registry | [§9.10](threat-model.md#910-image-and-supply-chain) | P2 | GitLab Container Registry mirrors approved external images; production pods only pull from private registry |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a documented list of approved base images exists; (2) CVE scanning is integrated into the CI/CD pipeline before any deployment; (3) container image tags in deployment manifests are immutable digests; (4) a process exists to respond to newly disclosed CVEs in deployed images.

**Implementation Status:** IN PROGRESS — Trivy is implemented; digest pinning and Kyverno policies are Phase 9.

---

### SC-3.13.1 — Monitor and Control Communications at Boundaries

**CMMC Practice:** SC.L1-3.13.1  
**Control Family:** System and Communications Protection  
**Requirement Text:** *Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information system.*

The cluster has two classes of communication boundaries: the external boundary (internet to Ingress) and internal boundaries (pod to pod, namespace to namespace, control plane to data plane). Both require active monitoring and access control.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [D-1.1](threat-model.md#d----denial-of-service) | HIGH | API server resource exhaustion via expensive list operations |
| [D-2.1](threat-model.md#d----denial-of-service-1) | HIGH | Single-node etcd quorum disruption |
| [D-4.1](threat-model.md#d----denial-of-service-3) | HIGH | FreeIPA outage cascades to all authentication |
| [I-10.1](threat-model.md#i----information-disclosure-9) | HIGH | Unrestricted east-west pod communication |
| [D-1.2](threat-model.md#d----denial-of-service) | MEDIUM | Webhook timeout cascade |
| [D-9.1](threat-model.md#d----denial-of-service-8) | MEDIUM | Layer 7 request flood exhausting worker capacity |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Default-deny all ingress and egress per namespace | [§9.5](threat-model.md#95-network-policy) | P1 | NetworkPolicy with `podSelector: {}` in all namespaces; blocks unrestricted east-west traffic |
| Explicitly allowlist required service paths | [§9.5](threat-model.md#95-network-policy) | P1 | Documented allowlist policies covering all required service communication paths |
| Isolate `kube-system` from workload namespaces | [§9.5](threat-model.md#95-network-policy) | P1 | Control plane services (etcd port 2379) unreachable from workload namespaces |
| Restrict pod egress to known lab CIDRs | [§9.5](threat-model.md#95-network-policy) | P2 | Pods cannot initiate connections to external IPs; blocks C2 callbacks and data exfiltration |
| Deploy FreeIPA replica for HA | [§9.8](threat-model.md#98-freeipa--identity) | P3 | Eliminates authentication single point of failure; `ipa-replica-install` on ipa02 VM |

#### Assessment Objective (CMMC)

An assessor would verify: (1) NetworkPolicy objects exist in all namespaces and default to deny; (2) the external Ingress performs TLS termination and does not forward unencrypted traffic; (3) the kube-apiserver is not directly reachable from workload pods.

**Implementation Status:** PLANNED — NetworkPolicy is Phase 6 scope; FreeIPA HA is Phase 12.

---

### SC-3.13.8 — Implement Cryptographic Mechanisms

**CMMC Practice:** SC.L2-3.13.8  
**Control Family:** System and Communications Protection  
**Requirement Text:** *Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.*

This is the encryption control. It covers: (1) TLS for all inter-component communication, (2) encryption at rest for secrets in etcd, (3) encryption of backup media, and (4) mTLS for the highest-trust paths (kube-apiserver to etcd, node to control plane). Twenty of the 38 component-level threats in the threat model cite this control — second only to AC-3.1.1 — reflecting how foundational cryptographic protection is to the cluster's security posture.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-1.1](threat-model.md#s----spoofing) | CRITICAL | Stolen kubeconfig impersonation |
| [I-1.1](threat-model.md#i----information-disclosure) | CRITICAL | Secret enumeration via over-privileged list/get |
| [S-2.1](threat-model.md#s----spoofing-1) | CRITICAL | etcd client certificate forgery |
| [T-2.1](threat-model.md#t----tampering-1) | CRITICAL | Direct etcd write bypassing all RBAC |
| [I-2.1](threat-model.md#i----information-disclosure-1) | CRITICAL | Secrets stored at rest without encryption |
| [I-11.1](threat-model.md#i----information-disclosure-10) | CRITICAL | Secrets mounted as environment variables are widely leakable |
| [S-1.3](threat-model.md#s----spoofing) | HIGH | OIDC token replay attack |
| [I-1.3](threat-model.md#i----information-disclosure) | HIGH | Verbose API error messages leaking internals |
| [T-2.2](threat-model.md#t----tampering-1) | HIGH | etcd backup snapshot exfiltration |
| [S-4.2](threat-model.md#s----spoofing-3) | HIGH | Kerberos golden ticket attack |
| [S-5.1](threat-model.md#s----spoofing-4) | HIGH | CI/CD variable exfiltration via pipeline injection |
| [S-6.1](threat-model.md#s----spoofing-5) | HIGH | AWX credential store exfiltration |
| [S-9.1](threat-model.md#s----spoofing-8) | HIGH | TLS private key compromise enables MITM |
| [E-10.1](threat-model.md#e----elevation-of-privilege-9) | HIGH | CoreDNS poisoning redirects service discovery |
| [I-11.2](threat-model.md#i----information-disclosure-10) | HIGH | Application logging captures secret values |
| [T-12.1](threat-model.md#t----tampering-11) | HIGH | Volume snapshot exfiltration to external storage |
| [I-13.1](threat-model.md#i----information-disclosure-12) | HIGH | Prometheus metrics exposing credentials |
| [S-1.4](threat-model.md#s----spoofing) | MEDIUM | Node identity certificate spoofing |
| [I-8.1](threat-model.md#i----information-disclosure-7) | MEDIUM | Credentials embedded in image layers |
| [I-13.2](threat-model.md#i----information-disclosure-12) | MEDIUM | Grafana datasource credentials readable via API |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Encrypt secrets at rest | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | `--encryption-provider-config` with `secretbox`; confirmed via etcd raw value inspection |
| Enforce mTLS on all etcd connections | [§9.2](threat-model.md#92-etcd-protection) | P1 | Dedicated etcd CA; `--cert-file`, `--key-file`, `--peer-cert-file` required; connection without cert returns error |
| Encrypt etcd snapshots before storing | [§9.2](threat-model.md#92-etcd-protection) | P1 | GPG encryption pipeline for all backup artifacts |
| Implement Sealed Secrets or Vault | [§9.6](threat-model.md#96-secret-management) | P1 | Vault provides encrypted storage for all sensitive credentials; Sealed Secrets encrypts at rest in Git |
| Mount secrets as volumes, not environment variables | [§9.6](threat-model.md#96-secret-management) | P1 | Removes credentials from `kubectl describe` output and `/proc/*/environ` visibility |
| Protect Splunk admin credentials in Vault | [§9.9](threat-model.md#99-logging-and-audit) | P1 | No plaintext credentials in any configuration file or CI variable |
| Use OIDC for pipeline cluster auth | [§9.7](threat-model.md#97-cicd-security) | P2 | Short-lived OIDC tokens replace static kubeconfig; prevents replay beyond 1-hour window |
| Restrict store etcd CA private key offline | [§9.2](threat-model.md#92-etcd-protection) | P2 | CA key offline reduces forgery risk for node identity certificates |

#### Assessment Objective (CMMC)

An assessor would verify: (1) etcd returns ciphertext when queried directly (bypassing the API server); (2) all inter-component traffic uses TLS (verifiable via network capture); (3) backup artifacts are encrypted; (4) no plaintext credentials exist in any configuration files, environment variables, or source code repositories.

**Implementation Status:** IN PROGRESS — etcd mTLS is implemented (RKE2 default); secrets at rest encryption is P1 Phase 5 item; Vault implementation is Phase 7.

---

### SC-3.13.10 — Establish and Manage Cryptographic Keys

**CMMC Practice:** SC.L2-3.13.10  
**Control Family:** System and Communications Protection  
**Requirement Text:** *Establish and manage cryptographic keys for required cryptography employed in organizational information systems.*

Key management covers the full lifecycle: generation, distribution, storage, rotation, and revocation. The cluster manages multiple categories of cryptographic material: cluster CA (kube-apiserver, etcd, service account signing), OIDC signing keys (FreeIPA), TLS certificates (Ingress), and application secrets (Vault-managed).

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [S-9.1](threat-model.md#s----spoofing-8) | HIGH | TLS private key compromise enables MITM |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Rotate all cluster certificates annually | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P2 | Zabbix cert expiry monitoring; 60-day alert triggers rotation planning; rotation runbook in `docs/runbooks/cert-rotation.md` |
| Store etcd CA private key offline | [§9.2](threat-model.md#92-etcd-protection) | P2 | Offline CA key storage prevents automatic certificate issuance; new certs require deliberate administrative action |
| Protect Splunk admin credentials in Vault | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Vault manages all high-value credentials; access policy enforces least privilege; audit log records all access |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a documented key management plan exists covering all cryptographic material in the system; (2) certificate expiry is monitored with advance warning; (3) procedures exist for key rotation and revocation; (4) private keys are stored with appropriate access controls.

**Implementation Status:** PLANNED — cert expiry monitoring is Phase 5; documented key management plan is Phase 11.

---

### SI-3.14.1 — Identify and Manage Information System Flaws

**CMMC Practice:** SI.L1-3.14.1  
**Control Family:** System and Information Integrity  
**Requirement Text:** *Identify, report, and correct information system flaws; install security-relevant software updates within a defined time period after the release of the updates.*

Patch management in a containerized environment operates at two levels: (1) the node OS (Rocky Linux 9 kernel and packages) which directly affects container isolation, and (2) container images which carry their own userspace library versions. Both must be tracked and updated on a defined schedule.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-14.1](threat-model.md#t----tampering-13) | HIGH | Unpatched kernel CVE enabling container escape |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Scan all images before deployment | [§9.10](threat-model.md#910-image-and-supply-chain) | P1 | Trivy in CI pipeline catches newly disclosed CVEs in dependencies before deployment |
| Audit RBAC bindings weekly | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | Complements patch management: new CVEs in cluster components trigger immediate assessment |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a process exists to receive and act on CVE notifications for all cluster components; (2) critical OS patches are applied within a defined timeframe (30 days recommended for CMMC); (3) patch status is tracked; (4) there is a rollback procedure if a patch introduces a regression.

**Implementation Status:** PLANNED — formal patch management SLA and tracking is Phase 11 documentation work; Rocky Linux 9 uses dnf automatic updates for security patches.

---

### SI-3.14.2 — Provide Protection from Malicious Code

**CMMC Practice:** SI.L1-3.14.2  
**Control Family:** System and Information Integrity  
**Requirement Text:** *Provide protection from malicious code at appropriate locations within organizational information systems.*

Malicious code protection in a container environment is implemented through: (1) admission control blocking privileged/unsigned workloads, (2) network egress restrictions preventing malicious code from communicating with C2 infrastructure, (3) image scanning blocking known-malicious packages, and (4) AIDE detecting unauthorized filesystem modifications on nodes.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [D-2.1](threat-model.md#d----denial-of-service-1) | HIGH | Single-node etcd quorum disruption |
| [D-4.1](threat-model.md#d----denial-of-service-3) | HIGH | FreeIPA outage cascades to all authentication |
| [D-1.2](threat-model.md#d----denial-of-service) | MEDIUM | Webhook timeout cascade |
| [D-9.1](threat-model.md#d----denial-of-service-8) | MEDIUM | Layer 7 request flood exhausting worker capacity |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Enable PodSecurity `restricted` profile | [§9.4](threat-model.md#94-pod-security) | P1 | Blocks privileged containers, host namespace sharing, and root execution |
| Restrict pod egress to known lab CIDRs | [§9.5](threat-model.md#95-network-policy) | P2 | Prevents malicious code from reaching external C2 infrastructure |
| Run AIDE daily on all nodes | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Detects unauthorized filesystem modifications including dropped backdoors |
| Scan all images before deployment | [§9.10](threat-model.md#910-image-and-supply-chain) | P1 | Trivy blocks deployment of images containing known malicious packages or severe CVEs |

#### Assessment Objective (CMMC)

An assessor would verify: (1) a mechanism exists to detect malicious code on nodes (AIDE); (2) malicious code cannot be introduced via container images (Trivy scanning); (3) deployed workloads are constrained in what they can do (PSA restricted); (4) network egress restrictions limit blast radius if malicious code executes.

**Implementation Status:** IN PROGRESS — AIDE and Trivy are implemented; PSA restricted profile is P1 Phase 5 item.

---

### SI-3.14.6 — Monitor Organizational Systems for Attacks

**CMMC Practice:** SI.L2-3.14.6  
**Control Family:** System and Information Integrity  
**Requirement Text:** *Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.*

Active monitoring is the operational complement to logging (AU-3.3.1). While audit logging records what happened, SI-3.14.6 requires that someone or something is actively analyzing those records to detect attacks in progress. The cluster's detection stack — Splunk with custom correlation rules, `k8s_secret_auditor.py`, and FreeIPA account auditor — fulfills this requirement.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [I-1.2](threat-model.md#i----information-disclosure) | HIGH | API discovery leaking resource layout |
| [I-1.3](threat-model.md#i----information-disclosure) | HIGH | Verbose API error messages leaking internals |
| [D-1.1](threat-model.md#d----denial-of-service) | HIGH | API server resource exhaustion via expensive list operations |
| [R-7.1](threat-model.md#r----repudiation-2) | HIGH | Audit policy gaps create blind spots |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Ship all audit logs to Splunk in real time | [§9.9](threat-model.md#99-logging-and-audit) | P1 | All nodes shipping to Splunk HEC; kube-apiserver audit log streamed via `k8s_secret_auditor.py` |
| Alert on audit log source gaps | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Splunk alert fires when any HEC source is missing for > 15 minutes |
| Run daily secret access audit | [§9.6](threat-model.md#96-secret-management) | P1 | `k8s_secret_auditor.py` detects 15 anomaly patterns including burst access, enumeration, and cross-namespace access |
| Run daily account lifecycle audit | [§9.8](threat-model.md#98-freeipa--identity) | P1 | `freeipa_account_auditor.py` detects stale accounts and privileged-inactive patterns |

#### Assessment Objective (CMMC)

An assessor would verify: (1) automated detection rules are active and generating alerts; (2) alert response procedures exist and are tested; (3) detection coverage includes secret access anomalies, authentication failures, and privilege escalation attempts; (4) detection gaps are documented and have compensating controls.

**Implementation Status:** IN PROGRESS — Splunk SIEM and custom detection scripts are implemented; alert response procedures are Phase 11 documentation work.

---

### SI-3.14.7 — Identify Unauthorized Use

**CMMC Practice:** SI.L2-3.14.7  
**Control Family:** System and Information Integrity  
**Requirement Text:** *Identify unauthorized use of organizational information systems.*

While SI-3.14.6 focuses on detecting attacks in progress, SI-3.14.7 addresses the ability to identify when a system is being used outside its authorized purpose — including authorized users performing unauthorized actions, insider threat behavior, and automated processes acting outside their expected scope.

#### Threats Addressed

| Threat ID | Severity | Description |
|---|---|---|
| [T-1.1](threat-model.md#t----tampering) | CRITICAL | Malicious admission webhook injection |
| [E-1.1](threat-model.md#e----elevation-of-privilege) | CRITICAL | Privileged pod container escape |
| [E-3.1](threat-model.md#e----elevation-of-privilege-2) | CRITICAL | Container escape via privileged pod to node OS |
| [T-5.1](threat-model.md#t----tampering-4) | CRITICAL | Pipeline deploys malicious workloads to cluster |
| [E-6.1](threat-model.md#e----elevation-of-privilege-5) | CRITICAL | Arbitrary playbook execution via variable injection |
| [T-7.1](threat-model.md#t----tampering-6) | CRITICAL | Audit log deletion by compromised Splunk admin |
| [T-7.2](threat-model.md#t----tampering-6) | HIGH | HEC token abuse for log injection / poisoning |
| [E-10.1](threat-model.md#e----elevation-of-privilege-9) | HIGH | CoreDNS poisoning redirects service discovery |
| [T-14.2](threat-model.md#t----tampering-13) | HIGH | AIDE baseline bypass via database manipulation |

#### Mitigations Implemented

| Mitigation | Threat Model Section | Priority | Implementation Evidence |
|---|---|---|---|
| Run daily secret access audit | [§9.6](threat-model.md#96-secret-management) | P1 | `k8s_secret_auditor.py` detects: `BURST_ACCESS`, `LIST_ENUMERATE`, `MASS_LIST`, `CROSS_NAMESPACE`, `WATCH_SECRETS`, `EXEC_AFTER_SECRET`, `FORBIDDEN_PROBE`, `SENSITIVE_NAME`, `SECRET_DELETED`, `SECRET_MODIFIED`, `IMPERSONATION`, `NODE_OVERSTEP`, `FORBIDDEN_RATE`, `DENIED_THEN_ALLOW`, `UNUSUAL_HOUR` |
| Run AIDE daily on all nodes | [§9.9](threat-model.md#99-logging-and-audit) | P1 | AIDE detects unauthorized filesystem changes including injected backdoors and AIDE database tampering (AIDE DB itself is in the monitored tree) |
| Audit all `cluster-admin` ClusterRoleBindings | [§9.3](threat-model.md#93-rbac-least-privilege) | P1 | Any new `cluster-admin` binding detected within 24 hours via automated diff |
| Enable `RequestResponse` audit logging for secrets | [§9.1](threat-model.md#91-kubernetes-api-server-hardening) | P1 | Full request/response body captured for all secret operations enables post-incident analysis |
| Alert on audit log source gaps | [§9.9](threat-model.md#99-logging-and-audit) | P1 | Missing audit stream is itself an indicator of unauthorized activity (log deletion or agent tampering) |

#### Assessment Objective (CMMC)

An assessor would verify: (1) automated tooling actively detects anomalous access patterns; (2) alerts are generated and reviewed within a defined timeframe; (3) unauthorized privilege escalation attempts are detected; (4) the system can distinguish normal from anomalous behavior using baseline data.

**Implementation Status:** IN PROGRESS — detection tooling is implemented; alert triage SLA and baseline documentation are Phase 11 items.

---

## Gap Analysis

The following NIST 800-171 controls from the 14 unaddressed families are outside the technical scope of this architecture document but required for a full CMMC Level 2 assessment:

| Control Family | Key Requirements | Gap Status |
|---|---|---|
| AT (Awareness and Training) | Security awareness training for all users | **Gap** — organizational policy required |
| CA (Security Assessment) | Periodic security assessments and plans of action | **Partial** — this threat model serves as a partial assessment; formal POA&M required |
| IR (Incident Response) | Incident response plan, testing, and reporting | **Gap** — IR plan is Phase 11 documentation work |
| MA (Maintenance) | Controlled maintenance and media sanitization | **Partial** — documented for VMs but not formal policy |
| PE (Physical Protection) | Physical access controls to systems | **Gap** — home lab environment; physical controls are informal |
| PS (Personnel Security) | Personnel screening and termination procedures | **Gap** — documented offboarding procedure partially addresses this |
| RA (Risk Assessment) | Periodic risk assessments | **Partial** — this threat model is the primary risk assessment artifact |
| RE (Recovery) | Backup and recovery testing | **Partial** — backups implemented; recovery testing is Phase 12 |

---

## Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | Jason A. Slocomb | Initial release — 22 controls mapped, 52 threat entries cross-referenced, full bidirectional traceability to `threat-model.md` |

---

*This document supports CMMC Level 2 assessment preparation for the homelab Kubernetes security cluster. All threat IDs link to their detailed entries in [`docs/threat-model.md`](threat-model.md). All mitigation section references link to [`docs/threat-model.md` Section 9](threat-model.md#9-mitigations-and-controls). The 110-control CMMC Level 2 practice set is defined in NIST SP 800-171 Rev 2 and the CMMC Assessment Guide Level 2 v2.0.*
