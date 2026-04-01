# System Security Plan (SSP) — Abbreviated
## homelab-k8s CMMC Level 2 Lab Environment

**Document ID:** SSP-HOMELAB-001  
**Version:** 1.0  
**Date:** April 2026  
**Author:** Jason A. Slocomb  
**Classification:** Unclassified / Lab Use  
**Status:** Draft  

---

## 1. System Identification

| Field | Value |
|-------|-------|
| System Name | homelab-k8s |
| System Owner | Jason A. Slocomb |
| System Type | Lab / Portfolio |
| Operating Environment | AWS us-west-2 |
| CMMC Level | Level 2 |
| FIPS 140-2 | Not applicable (lab environment) |
| Authorization Status | Self-authorized (lab) |

### 1.1 System Description

homelab-k8s is a security automation lab environment deployed on Amazon Web Services (AWS) that demonstrates enterprise-grade identity management, infrastructure automation, and compliance monitoring aligned to NIST SP 800-171 Revision 2 and CMMC Level 2. The system is designed to mirror the architecture of DoD contractor environments and is transferable to AWS GovCloud (IL2/IL4).

The system hosts no Controlled Unclassified Information (CUI). It exists solely as a portfolio demonstration of CMMC-aligned infrastructure competency.

### 1.2 System Boundary

The system boundary includes all AWS resources within the homelab-k8s VPC (10.0.0.0/16) in the us-west-2 region, including:

- Five EC2 instances (bastion, ipa01, k8s-cp01, k8s-w01, k8s-w02)
- VPC, subnets, security groups, NAT gateway, and internet gateway
- All software services deployed on the above instances
- All data at rest and in transit within the VPC boundary

### 1.3 System Components

| Component | Version | Function | Location |
|-----------|---------|----------|----------|
| Rocky Linux | 9.7 | Operating system | All nodes |
| RKE2 | v1.30.2 | Kubernetes orchestration | k8s-cp01, k8s-w01, k8s-w02 |
| FreeIPA | 4.12.2 | Identity, authentication, DNS | ipa01 |
| GitLab CE | 18.10.1 | Source control, change management | k8s-w01 |
| AWX | 24.6.1 | Automation orchestration | k8s-w02 |
| NetBox | v4.5.5 | Configuration management database | k8s-w02 |
| Splunk Enterprise | 10.2.1 | SIEM, log aggregation | k8s-w02 |
| Prometheus + Grafana | kube-prometheus-stack | Monitoring, observability | k8s-w02 |
| Falco | 0.43.0 | Runtime threat detection | All K8s nodes |
| AIDE | 0.16 | File integrity monitoring | All nodes |

---

## 2. System Environment

### 2.1 Network Architecture

```
Internet
    │
    ▼
[AWS Internet Gateway]
    │
    ▼
Public Subnet (10.0.1.0/24)
    │
    └── bastion (t3.micro) ── SSH jump host, no persistent data
    │
    ▼
[NAT Gateway]
    │
    ▼
Private Subnet (10.0.10.0/24)
    │
    ├── ipa01       (10.0.10.113) — FreeIPA identity services
    ├── k8s-cp01    (10.0.10.146) — RKE2 control plane
    ├── k8s-w01     (10.0.10.227) — RKE2 worker, GitLab, AWX
    └── k8s-w02     (10.0.10.117) — RKE2 worker, Splunk, NetBox, Prometheus
```

### 2.2 Security Boundaries

- All production nodes are in the private subnet with no direct internet access
- Inbound access to private nodes is exclusively through the bastion host via SSH
- AWS security groups enforce least-privilege network access between nodes
- Kubernetes Pod Security policies enforce restricted security contexts
- All inter-node communication uses private IP addresses within the VPC

---

## 3. Control Implementation Summary

This section summarizes the implementation of NIST SP 800-171 Rev 2 controls relevant to this system. Controls are organized by domain.

---

### 3.1 Access Control (AC)

#### 3.1.1 — Limit system access to authorized users

**Implementation:** FreeIPA 4.12.2 provides centralized identity management for all system components. User accounts are created and managed exclusively in FreeIPA. AWX integrates with FreeIPA via LDAP for authentication, ensuring only authorized users can execute automation. Kubernetes RBAC is synchronized with FreeIPA groups (k8s-admins, k8s-users, cluster-admins).

**Evidence:** `docs/screenshots/freeipa-users.png`, `docs/screenshots/awx-freeipa-ldap-auth.png`

**Status:** Implemented

#### 3.1.2 — Limit system access to authorized transactions and functions

**Implementation:** FreeIPA Host-Based Access Control (HBAC) rules restrict which users can access which systems. AWX roles restrict which users can execute which playbooks. Kubernetes RBAC restricts namespace-level operations by group membership.

**Evidence:** `freeipa/hbac/ipa-server.hbac`, `freeipa/hbac/k8s-nodes.hbac`, `docs/screenshots/freeipa-groups.png`

**Status:** Implemented

#### 3.1.3 — Control the flow of CUI

**Implementation:** No CUI is processed in this environment. Network flow controls are implemented via AWS security groups and Kubernetes network policies. The Canal CNI enforces pod-level network isolation.

**Status:** Not applicable (no CUI)

---

### 3.2 Audit and Accountability (AU)

#### 3.3.1 — Create and retain system audit logs

**Implementation:** Splunk Enterprise 10.2.1 aggregates audit logs from all five nodes via Universal Forwarders. Four indexes are maintained:

| Index | Source | Retention |
|-------|--------|-----------|
| linux_audit | /var/log/audit/audit.log | 90 days |
| linux_secure | /var/log/secure | 90 days |
| linux_syslog | /var/log/messages | 90 days |
| k8s_logs | Kubernetes API audit log | 90 days |

**Evidence:** `docs/screenshots/splunk-audit-logs.png`, `docs/screenshots/splunk-index-summary.png`

**Status:** Implemented

#### 3.3.2 — Ensure that the actions of individual users can be traced

**Implementation:** Splunk indexes include user identity fields from PAM authentication events, SSH logins, and sudo usage. AWX maintains a full audit trail of all automation jobs including the user who triggered each job, the playbook executed, and the hosts affected. GitLab tracks all code changes with user attribution.

**Evidence:** AWX job audit trail, Splunk `linux_secure` index

**Status:** Implemented

---

### 3.3 Configuration Management (CM)

#### 3.4.1 — Establish and maintain baseline configurations

**Implementation:** AIDE (Advanced Intrusion Detection Environment) 0.16 is deployed on all five nodes. Initial baselines were generated post-deployment and stored at `/var/lib/aide/aide.db`. Daily integrity checks run at 02:00 UTC via cron and results are forwarded to Splunk. Deviations from baseline generate alerts.

**Evidence:** `docs/aide-falco.md`, `docs/screenshots/falco-detections.png`

**Status:** Implemented

#### 3.4.2 — Establish and maintain configurations for information technology products

**Implementation:** All node configurations are managed via Ansible playbooks stored in GitLab CE. Infrastructure is provisioned via Terraform. No manual configuration changes are made outside of source-controlled automation.

**Evidence:** `ansible/` directory, `terraform-aws/` directory

**Status:** Implemented

#### 3.4.3 — Track, review, approve and log changes to systems

**Implementation:** All configuration changes are committed to GitLab CE with user attribution and commit messages. AWX enforces change execution through approved playbooks. The `.gitlab-ci.yml` pipeline validates playbook syntax before merge.

**Evidence:** `docs/screenshots/gitlab-ce.png`

**Status:** Implemented

#### 3.4.5 — Define, document, approve and enforce physical and logical access restrictions

**Implementation:** Kubernetes Pod Security admission policies enforce `restricted` security contexts across all namespaces. RKE2 ships with CIS benchmark hardening applied by default. Node-level access is restricted via FreeIPA HBAC rules.

**Evidence:** `docs/screenshots/rke2-nodes-ready.png`

**Status:** Implemented

---

### 3.4 Identification and Authentication (IA)

#### 3.5.1 — Identify system users, processes, and devices

**Implementation:** FreeIPA provides a central identity store for all human users. Each node has a unique hostname registered in FreeIPA DNS. Service accounts for AWX, NetBox, and GitLab are defined in FreeIPA LDAP schemas.

**Evidence:** `freeipa/ldap-schema/`, `docs/screenshots/freeipa-users.png`

**Status:** Implemented

#### 3.5.2 — Authenticate the identities of users, processes, and devices

**Implementation:** FreeIPA Kerberos provides strong authentication for all node access. SSH key-based authentication is enforced on all nodes with password authentication disabled. AWX authenticates users against FreeIPA LDAP.

**Evidence:** `docs/screenshots/awx-freeipa-ldap-auth.png`

**Status:** Implemented

#### 3.5.3 — Use multifactor authentication for local and network access

**Implementation:** FreeIPA OTP infrastructure is deployed and ready. MFA enforcement is not activated in this lab environment but the infrastructure supports it. In a production environment, FreeIPA OTP would be enabled for all administrative accounts.

**Status:** Partially implemented (infrastructure ready, not enforced in lab)

---

### 3.5 System and Communications Protection (SC)

#### 3.13.1 — Monitor, control, and protect communications at external boundaries

**Implementation:** AWS security groups enforce boundary protection at the VPC level. The bastion host is the sole entry point for administrative access. All service ports are restricted to specific source security groups — no ports are open to 0.0.0.0/0 except SSH on the bastion.

**Evidence:** AWS security group rules (sg-0efcbaa8023bceafd, sg-0cbc6f0e499d9804d)

**Status:** Implemented

---

### 3.6 System and Information Integrity (SI)

#### 3.14.1 — Identify, report, and correct system flaws

**Implementation:** All system packages are managed via dnf with automatic security updates enabled. Splunk Universal Forwarders monitor package installation events. AIDE detects unauthorized file modifications.

**Status:** Implemented

#### 3.14.6 — Monitor systems to detect attacks and indicators of potential attacks

**Implementation:** Falco 0.43.0 runs as a DaemonSet on all Kubernetes nodes using the legacy eBPF driver. Falco monitors syscalls in real time and generates alerts for suspicious activity including privilege escalation attempts, unexpected network connections, and container escape patterns. Alerts are forwarded to Splunk.

**Evidence:** `docs/screenshots/falco-detections.png`, `docs/aide-falco.md`

**Status:** Implemented

#### 3.14.7 — Identify unauthorized use of organizational systems

**Implementation:** AIDE daily integrity checks detect unauthorized file modifications. Falco runtime detection identifies unexpected process execution, file access, and network activity. Splunk correlates events across all nodes to identify anomalous patterns.

**Evidence:** `docs/screenshots/splunk-audit-logs.png`, `docs/screenshots/falco-detections.png`

**Status:** Implemented

---

## 4. Roles and Responsibilities

| Role | Responsibilities | Implemented By |
|------|-----------------|----------------|
| System Owner | Overall accountability for system security | Jason A. Slocomb |
| System Administrator | Node configuration, patch management | Ansible AWX automation |
| Identity Administrator | User account management, HBAC rules | FreeIPA admin console |
| Security Operations | Log review, alert triage, incident response | Splunk dashboards |
| Change Manager | Review and approve configuration changes | GitLab MR process |

---

## 5. Continuous Monitoring

| Activity | Frequency | Tool | Output |
|----------|-----------|------|--------|
| File integrity check | Daily (02:00 UTC) | AIDE | Splunk alert on deviation |
| Runtime threat detection | Continuous | Falco | Splunk alert on detection |
| Log aggregation | Real-time | Splunk UF | Splunk indexes |
| K8s cluster health | Real-time | Prometheus | Grafana dashboard |
| Vulnerability scanning | On-demand | dnf check-update | Manual review |

---

## 6. Plan of Action and Milestones (POA&M)

| ID | Finding | Severity | Mitigation | Target Date |
|----|---------|----------|------------|-------------|
| POA-001 | MFA not enforced for admin accounts | Medium | Enable FreeIPA OTP for all admin accounts | Future sprint |
| POA-002 | No automated vulnerability scanning | Low | Integrate OpenSCAP or Trivy into CI pipeline | Future sprint |
| POA-003 | Splunk retention not enforced via policy | Low | Configure index retention policies in indexes.conf | Future sprint |
| POA-004 | No backup/recovery tested | Low | Implement and test backup procedures | Future sprint |

---

## 7. Interconnections

| System | Type | Data Exchanged | Authorization |
|--------|------|----------------|---------------|
| AWS VPC | Network boundary | All system traffic | AWS account owner |
| FreeIPA → AWX | LDAP/S | User authentication | Configured via AWX LDAP settings |
| NetBox → AWX | HTTP API | Inventory data | AWX inventory source credential |
| Splunk UF → Splunk | Syslog/TCP | Audit and system logs | Universal Forwarder configuration |
| GitLab → AWX | HTTP/Git | Playbook source | AWX project credential |

---

## 8. References

- NIST SP 800-171 Rev 2 — Protecting Controlled Unclassified Information in Nonfederal Systems
- CMMC Model v2.0 — Level 2 Practice Guide
- DISA RKE2 STIG — Rancher Government Solutions RKE2 Security Technical Implementation Guide
- CIS Rocky Linux 9 Benchmark
- AWS GovCloud (US) Authorization to Operate documentation
