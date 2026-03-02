# Homelab K8s Infrastructure — Documentation Index

**Enterprise-grade Kubernetes homelab** built on Proxmox/Rocky Linux 9, demonstrating CMMC Level 2 / NIST 800-171 security controls for a defense contractor portfolio.

---

## Deliverables

| File | Description |
|------|-------------|
| `homelab-k8s-files.zip` | Complete infrastructure codebase — 127 files across Terraform, Ansible, Kubernetes manifests, FreeIPA configs, docs, and scripts |
| `homelab-k8s-structure.md` | Architecture design document and directory structure specification |
| `homelab-k8s-cluster.md` | Detailed cluster reference — stack decisions, resource allocations, CMMC control mapping |
| `homelab-network-diagrams.html` | Interactive network diagrams (7 tabs) |
| `homelab-workflow-diagrams.html` | Interactive workflow diagrams (7 tabs) |

---

## Stack

| Layer | Technology |
|-------|-----------|
| Hypervisor | Proxmox VE 8.x |
| OS | Rocky Linux 9 (CIS hardened) |
| Kubernetes | RKE2 (CIS profile, audit logging) |
| Identity | FreeIPA (LDAP, Kerberos, DNS, CA) |
| Automation | AWX + Ansible |
| Source Control | GitLab CE |
| Storage | Longhorn (distributed, 2-replica) |
| Monitoring | Prometheus + Grafana + Zabbix |
| SIEM | Splunk Enterprise |
| CMDB | NetBox |
| Ingress | ingress-nginx + MetalLB (L2) |
| TLS | cert-manager + FreeIPA internal CA |
| Secrets | Sealed Secrets + Ansible Vault |

---

## Network Diagrams (`homelab-network-diagrams.html`)

Open in any browser. Seven interactive tabs:

1. **Physical** — Proxmox host with all 5 VMs rendered inside the hypervisor boundary; vmbr0/vmbr1 bridges; per-VM specs, services, and OS badges
2. **Network** — Full L3 topology from client browser through DNS resolution, MetalLB ingress routing, all application pods, LDAP auth back-channels to FreeIPA, pod/service CIDRs, and Longhorn storage fabric
3. **K8s Cluster** — Control plane components (apiserver, etcd, scheduler, CoreDNS, Canal CNI, CIS audit) with all 3 workers showing namespace workloads, DaemonSet pods, kubelet, containerd, and Longhorn replicas
4. **Data Flow** — Two-layer diagram: GitOps pipeline (commit → GitLab CI → AWX webhook → execution) and observability pipeline (node telemetry → Splunk UF / Prometheus / Zabbix → Grafana)
5. **Auth Flow** — FreeIPA at center with all 6 consuming services; each shows bind DN, group mappings, and auth mechanism
6. **Services** — Color-coded namespace cards (devops / monitoring / logging / netops / infra) with URLs and port callouts
7. **Port Reference** — Complete port table organized by layer (RKE2, FreeIPA, Apps, Monitoring, Longhorn, Management)

---

## Workflow Diagrams (`homelab-workflow-diagrams.html`)

Open in any browser. Seven interactive tabs:

1. **GitOps Pipeline** — 6-step animated flow (write → CI lint → MR review → AWX sync → execute → audit), CI failure branch, and RBAC swimlane (infra-admin / dev-ops / read-only / service accounts)
2. **Provisioning** — Dual-column timeline: Proxmox template + Terraform + base OS + CIS hardening (left); FreeIPA install + RKE2 control plane + worker agents + cluster services (right). VM config matrix at bottom.
3. **Auth Workflows** — Side-by-side: LDAP login flow (bind → search → re-bind → group check → session) and Kerberos + HBAC SSH login flow. Full bind account table for all 5 apps.
4. **Incident Response** — Detection sources (Splunk/Prometheus/Zabbix/K8s audit/auditd) → triage with live SPL queries + severity classification → containment and recovery timelines
5. **Service Deploy** — 6-gate pipeline (prerequisites → secrets → Helm → ingress+TLS → LDAP → health check) with per-service deploy notes for AWX, GitLab, Splunk, and Prometheus stack
6. **Backup & DR** — 4-tier backup strategy swimlane (config/volumes/identity/secrets) + DR scenario timeline (FreeIPA lost / worker lost / control plane lost / full rebuild) with RPO/RTO targets
7. **CMMC Audit** — Evidence pipeline flow, 9-row control coverage matrix mapping NIST 800-171 practices to implementations, and 4 ready-to-use Splunk SPL evidence queries per domain

---

## Infrastructure at a Glance

### VM Layout

| Hostname | IP | vCPU | RAM | Disk | Role |
|----------|----|------|-----|------|------|
| ipa01 | 192.168.10.5 | 2 | 4 GB | 40 GB | FreeIPA · DNS · CA · LDAP |
| k8s-cp01 | 192.168.10.10 | 4 | 8 GB | 80 GB | RKE2 server · etcd · API |
| k8s-w01 | 192.168.10.11 | 6 | 16 GB | 200 GB | AWX · GitLab CE |
| k8s-w02 | 192.168.10.12 | 6 | 16 GB | 200 GB | Splunk · Prometheus · Grafana |
| k8s-w03 | 192.168.10.13 | 4 | 8 GB | 100 GB | NetBox · Zabbix |
| **Total** | | **22** | **52 GB** | **620 GB** | |

### Networking

- **vmbr1 lab bridge:** `192.168.10.0/24` — all cluster traffic
- **MetalLB L2 pool:** `192.168.10.200–220`
- **Ingress VIP:** `192.168.10.200` (ingress-nginx)
- **Pod CIDR:** `10.42.0.0/16` (Canal/Flannel VXLAN)
- **Service CIDR:** `10.43.0.0/16`
- **DNS zone:** `lab.internal` (served by FreeIPA)

### Application URLs

| Service | URL |
|---------|-----|
| AWX | `https://awx.lab.internal` |
| GitLab CE | `https://gitlab.lab.internal` |
| Grafana | `https://grafana.lab.internal` |
| Prometheus | `https://prometheus.lab.internal` |
| Splunk | `https://splunk.lab.internal` |
| Zabbix | `https://zabbix.lab.internal` |
| NetBox | `https://netbox.lab.internal` |
| Longhorn | `https://longhorn.lab.internal` |

---

## CMMC Level 2 Control Coverage

| Domain | Controls Addressed | Implementation |
|--------|-------------------|----------------|
| AC — Access Control | 3.1.1, 3.1.5 | FreeIPA LDAP auth · K8s RBAC · HBAC rules |
| AU — Audit & Accountability | 3.3.1, 3.3.2 | auditd + Splunk (90d) · K8s audit log |
| CM — Config Management | 3.4.1, 3.4.3 | CIS Ansible role · AIDE · GitLab change history |
| IA — Identification & Auth | 3.5.1, 3.5.7 | FreeIPA central identity · password policy (14 char, 4 class) |
| SC — System & Comms | 3.13.8 | TLS everywhere via cert-manager + FreeIPA CA |
| SI — System Integrity | 3.14.7 | AIDE file integrity · Splunk correlation rules · Zabbix |

---

## Quick Start

```bash
# 1. Provision VMs
cd terraform/
terraform init && terraform apply

# 2. Configure base OS + CIS hardening
ansible-playbook ansible/playbooks/provision_vms.yml
ansible-playbook ansible/playbooks/harden_os.yml

# 3. Install FreeIPA (manual step on ipa01)
bash freeipa/install-freeipa.sh

# 4. Deploy RKE2 cluster
ansible-playbook ansible/playbooks/install_rke2_server.yml
ansible-playbook ansible/playbooks/install_rke2_agent.yml

# 5. Deploy all cluster services
ansible-playbook ansible/playbooks/site.yml

# 6. Verify
bash scripts/verify-cluster-health.sh
```

See `docs/deployment-order.md` for the full 18-step sequence with verification commands at each stage.

---

## Repository Structure (homelab-k8s-files.zip)

```
.
├── terraform/              # Proxmox VM provisioning (5 VMs)
│   └── modules/proxmox-vm/ # Reusable VM module
├── ansible/
│   ├── playbooks/          # 15 playbooks (provision → deploy)
│   ├── roles/              # common, cis_hardening, firewalld, rke2_server, rke2_agent
│   └── inventory/          # hosts.yml + group_vars (with Vault)
├── kubernetes/
│   ├── namespaces/         # auth, devops, monitoring, netops, logging
│   ├── metallb/            # IPAddressPool + L2Advertisement
│   ├── cert-manager/       # ClusterIssuers (FreeIPA CA + selfsigned)
│   ├── longhorn/           # Helm values
│   ├── gitlab/             # Helm values + LDAP config + ingress
│   ├── awx/                # Operator kustomization + AWX CR + LDAP
│   ├── prometheus/         # kube-prometheus-stack values + ServiceMonitors
│   ├── grafana/            # values + LDAP toml + dashboards
│   ├── zabbix/             # Helm values + agent DaemonSet
│   ├── netbox/             # Helm values + LDAP config
│   └── splunk/             # Operator + StandaloneInstance + UF DaemonSet
├── freeipa/                # Install script, LDIF schemas, HBAC rules, DNS records
├── docs/                   # Architecture, deployment order, runbooks, CMMC mapping
└── scripts/                # bootstrap-proxmox, verify-cluster-health, kubeconfig-merge
```

---

*Built to demonstrate enterprise security engineering capabilities aligned with CMMC Level 2 / NIST 800-171 for defense contractor environments.*
