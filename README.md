# homelab-k8s — CMMC Level 2 Security Automation Portfolio

![AWS](https://img.shields.io/badge/AWS-us--west--2-FF9900?style=flat&logo=amazon-aws&logoColor=white)
![Kubernetes](https://img.shields.io/badge/RKE2-v1.30.2-326CE5?style=flat&logo=kubernetes&logoColor=white)
![Rocky Linux](https://img.shields.io/badge/Rocky_Linux-9.7-10B981?style=flat&logo=rockylinux&logoColor=white)
![CMMC](https://img.shields.io/badge/CMMC-Level_2-003087?style=flat)
![NIST](https://img.shields.io/badge/NIST_800--171-12_Controls-003087?style=flat)
![License](https://img.shields.io/badge/License-MIT-6B7280?style=flat)

A production-grade security automation lab built on AWS, demonstrating enterprise identity management, infrastructure automation, and compliance monitoring aligned to NIST SP 800-171 / CMMC Level 2 controls.

**Author:** Jason A. Slocomb  
**Platform:** AWS us-west-2 | Rocky Linux 9.7 | RKE2 Kubernetes  
**Target Roles:** DoD Contractor IT/Security Engineer, DevSecOps, AWS GovCloud (IL2/IL4)

---

## Architecture Overview

<a href="https://curious-wisp-e95465.netlify.app" target="_blank" rel="noopener noreferrer">🔗 View Architecture Diagram (opens in new tab)</a>


## Stack

| Component | Version | Role | Node |
|-----------|---------|------|------|
| RKE2 | v1.30.2 | Kubernetes distribution | k8s-cp01, k8s-w01, k8s-w02 |
| FreeIPA | 4.12.2 | Identity provider (LDAP, Kerberos, DNS, CA) | ipa01 |
| GitLab CE | 18.10.1 | Source control, CI/CD | k8s-w01 (native) |
| AWX | 24.6.1 | Ansible automation with RBAC | k8s-w02 (K8s) |
| NetBox | v4.5.5 | CMDB, dynamic inventory source | k8s-w02 (K8s) |
| Splunk | 10.2.1 | SIEM, log aggregation | k8s-w02 (native) |
| Prometheus + Grafana | kube-prometheus-stack | K8s observability | k8s-w02 (K8s) |
| Falco | 0.43.0 | Runtime threat detection | All K8s nodes (DaemonSet) |
| AIDE | 0.16 | File integrity monitoring | All nodes |

---

## Identity & Automation Pipeline

```
FreeIPA (LDAP/Kerberos)
    │
    ├── AWX LDAP Auth ──► Role-Based Playbook Access
    │
    └── K8s RBAC ──────► Namespace-level permissions

NetBox (CMDB/Source of Truth)
    │
    └── AWX Dynamic Inventory ──► Ansible targets all lab nodes automatically
```

This pipeline demonstrates enterprise-grade automation governance:
- **Who** can run automation is controlled by FreeIPA identity
- **What** gets automated is driven by NetBox CMDB inventory
- **All actions** are logged with user attribution in AWX audit trail

---

## CMMC Level 2 Control Mapping

| NIST 800-171 Control | Description | Implementation |
|----------------------|-------------|----------------|
| AC-3.1.1 | Limit system access to authorized users | FreeIPA LDAP → AWX RBAC |
| AC-3.1.2 | Limit system access to authorized functions | FreeIPA HBAC rules |
| AU-3.3.1 | Create and retain audit records | Splunk indexes: linux_audit, linux_secure |
| AU-3.3.2 | Ensure actions traceable to users | AWX job audit trail + Splunk user tracking |
| CM-3.4.1 | Baseline configurations | AIDE file integrity baselines on all nodes |
| CM-3.4.3 | Track and control changes | GitLab source control + AWX change automation |
| CM-3.4.5 | Define and manage configurations | RKE2 K8s with Pod Security policies |
| IA-3.5.1 | Identify and authenticate users | FreeIPA Kerberos + LDAP |
| IA-3.5.3 | Use multifactor authentication | FreeIPA OTP-ready infrastructure |
| SC-3.13.1 | Monitor communications at boundaries | Canal CNI network policies |
| SI-3.14.6 | Monitor systems for attacks | Falco runtime detection DaemonSet |
| SI-3.14.7 | Identify unauthorized use | AIDE integrity checks + Falco syscall monitoring |

---

## Key Technical Decisions

### Why Rocky Linux 9?
Rocky Linux 9.7 is binary-compatible with RHEL 9, which is the standard OS in DoD contractor environments and is approved for AWS GovCloud (IL2/IL4). All configurations in this lab transfer directly to classified environments.

### Why RKE2?
RKE2 is DISA STIG-compliant by default and is the recommended K8s distribution for DoD environments. It ships with CIS benchmark hardening, Pod Security admission, and uses containerd instead of Docker.

### Why FreeIPA + AWX + NetBox?
This combination mirrors the identity/automation/CMDB pipeline used in enterprise DoD contractor environments:
- FreeIPA provides centralized identity (replaces AD in Linux-heavy shops)
- AWX provides auditable automation with user attribution
- NetBox provides the source-of-truth inventory that drives automation at scale

### AWX Deployment Notes
AWX 18+ is Kubernetes-native. The AWX operator has a circular initialization dependency where both the web and task pods wait for database migrations that neither can run without the other completing init. The fix is to pre-run migrations via a standalone `kubectl run` pod against the postgres service immediately after postgres starts. Pod CIDR routes (10.42.0.0/16, 10.43.0.0/16) must also be added to firewalld trusted zones on all K8s nodes.

---

## Infrastructure

### AWS Resources
- **VPC:** 10.0.0.0/16
- **Public subnet:** 10.0.1.0/24 (bastion)
- **Private subnet:** 10.0.10.0/24 (all lab nodes)
- **Region:** us-west-2

### Node Layout

| Hostname | Private IP | Instance | Services |
|----------|-----------|---------|---------|
| bastion | 35.90.33.175 (public) | t3.micro | SSH jump host |
| ipa01 | 10.0.10.113 | t3.large | FreeIPA |
| k8s-cp01 | 10.0.10.146 | t3.medium | RKE2 control plane, etcd |
| k8s-w01 | 10.0.10.227 | t3.large | RKE2 worker, GitLab CE |
| k8s-w02 | 10.0.10.117 | t3.large | RKE2 worker, Splunk, AWX, NetBox, Prometheus |

---

## Deployment

### Prerequisites
- AWS CLI configured with appropriate credentials
- Terraform >= 1.0
- Ansible >= 2.14
- SSH key pair named `homelab-k8s` in AWS us-west-2

### Deploy Infrastructure
```bash
cd terraform-aws/
terraform init
terraform apply
```

### Configure Nodes
```bash
cd ansible/
ansible-playbook playbooks/provision_vms.yml
ansible-playbook playbooks/install_freeipa.yml
ansible-playbook playbooks/install_rke2.yml
```

### Post-Deployment DNS Fix
After any node reboot, run:
```bash
ansible all -b -m shell -a "
  nmcli con mod 'System eth0' ipv4.dns '10.0.10.113' ipv4.ignore-auto-dns yes
  nmcli con up 'System eth0'"
```

---

## Evidence

Screenshots of all running services are in `docs/screenshots/`:

| Screenshot | Description |
|-----------|-------------|
| `rke2-nodes-ready.png` | All 3 K8s nodes in Ready state |
| `freeipa-users.png` | FreeIPA user management |
| `freeipa-groups.png` | RBAC groups (k8s-admins, k8s-users) |
| `freeipa-dns.png` | DNS zone management |
| `gitlab-ce.png` | GitLab CE with homelab-k8s repo |
| `awx-dashboard.png` | AWX automation dashboard |
| `awx-freeipa-ldap-auth.png` | FreeIPA LDAP auth in AWX |
| `splunk-audit-logs.png` | Audit logs flowing from all nodes |
| `splunk-index-summary.png` | All 4 indexes receiving data |
| `grafana.png` | K8s cluster dashboards |
| `falco-detections.png` | Runtime security detections |
| `netbox-awx-dynamic-inventory.png` | NetBox → AWX dynamic inventory |

---

## AWS GovCloud Transferability

This lab is designed to transfer directly to AWS GovCloud:
- Rocky Linux 9 → RHEL 9 (binary compatible, GovCloud approved)
- RKE2 → DISA STIG compliant, GovCloud supported
- FreeIPA → Approved for IL2/IL4 identity management
- All Terraform/Ansible code requires only region and AMI updates

---

## Repository Structure

```
homelab-k8s/
├── terraform-aws/          # AWS infrastructure as code
├── ansible/
│   ├── inventory/          # Host inventory and group vars
│   └── playbooks/          # Provisioning playbooks
├── inventory/
│   └── netbox_inventory.py # NetBox dynamic inventory script
├── scripts/
│   └── netbox-populate.sh  # NetBox API population script
├── docs/
│   ├── phase8-aide-falco.md
│   └── screenshots/        # Evidence screenshots
└── prometheus-values.yaml  # Grafana/Prometheus Helm values
```

