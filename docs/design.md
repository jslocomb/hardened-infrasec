# Homelab Kubernetes Cluster — Design Document

A production-mirroring homelab stack built on Kubernetes, integrating centralized identity, source-controlled automation, SIEM, CMDB, and full-stack observability. Designed to demonstrate CMMC/NIST-aligned infrastructure competency.

---

## Stack Overview

| Service | Role |
|---|---|
| **FreeIPA** | Centralized identity & internal CA |
| **GitLab CE** | Source control & Ansible playbook management |
| **Ansible AWX** | Automation orchestration (authenticates via FreeIPA) |
| **Prometheus** | Metrics collection |
| **Grafana** | Unified observability dashboards |
| **Zabbix** | Infrastructure-level monitoring |
| **NetBox** | CMDB / network source of truth |
| **Splunk** | SIEM & log aggregation |

---

## Architecture

### Hypervisor

Run **Proxmox** on the physical host with a Kubernetes cluster on top via VMs. Use **K3s** or **RKE2** (preferred for security-focused labs) as the K8s distribution.

### Node Layout

| Node | vCPU | RAM | Disk | Workloads |
|---|---|---|---|---|
| Control Plane | 4 | 8 GB | 100 GB | K8s control plane + etcd (no user workloads) |
| Worker 1 | 6 | 16 GB | 200 GB | AWX, FreeIPA, GitLab CE |
| Worker 2 | 6 | 16 GB | 200 GB | Splunk, Zabbix, Grafana, NetBox, Prometheus |

### Persistent Storage

Use **Longhorn** for persistent volumes across nodes — integrates cleanly with K3s/RKE2.

Recommended PVC sizing:
- Splunk indexes: **50 GB+**
- GitLab repos: **20 GB+**

---

## Deployment Stack

### Ingress & TLS

- **ingress-nginx** for ingress
- **cert-manager** for certificate lifecycle
- FreeIPA acts as the internal CA; cert-manager consumes it via the CA issuer
- Each service gets a dedicated FQDN: `awx.lab.internal`, `gitlab.lab.internal`, etc.

### Secrets Management

Use **Sealed Secrets** (simpler for GitLab-integrated workflows) or **HashiCorp Vault**. Avoid storing plaintext credentials in Git under any circumstances.

### Namespace Strategy

Isolate services into namespaces for clean RBAC boundaries:

```
auth        → FreeIPA
devops      → AWX, GitLab
monitoring  → Prometheus, Grafana, Zabbix
netops      → NetBox, Splunk
```

---

## Service Deployment Order

Order matters — deploy in dependency sequence.

### 1. FreeIPA

Deploy **first**; everything else authenticates against it.

> **Note:** Running FreeIPA inside Kubernetes is non-trivial due to its requirement for a stable hostname/IP and its desire to own DNS. The recommended approach is to run FreeIPA as a **VM outside the cluster** with a static IP, then reference it as an external service. This avoids DNS recursion conflicts.

Use the `freeipa/freeipa-server` container image.

### 2. GitLab CE

Deploy via the official `gitlab/gitlab-ce` Helm chart. Configure LDAP in `gitlab.rb` to point at FreeIPA's LDAP interface. GitLab becomes the **source of truth** for all Ansible playbooks.

### 3. Ansible AWX

Deploy via the **AWX Operator** (the supported K8s-native method).

Post-install configuration:
- LDAP authentication → FreeIPA (see [AWX ↔ FreeIPA](#awx--freeipa-authentication))
- GitLab credential using a deploy token or SSH key
- Project sync configured to pull from GitLab CE
- Webhook on AWX project + GitLab push webhook for GitOps-style auto-sync

### 4. Prometheus + Grafana

Deploy via the **`kube-prometheus-stack`** Helm chart. Bundles Prometheus, Grafana, node-exporter, and Alertmanager in a single install.

### 5. Zabbix

Deploy via Helm or manifests. Install Zabbix agents on all nodes and VMs. Grafana has a Zabbix datasource plugin for unified dashboards.

### 6. NetBox

Use the `netboxcommunity/netbox` Helm chart. Configure LDAP auth against FreeIPA via `django-auth-ldap` (natively supported).

### 7. Splunk

Use the **Splunk Operator for Kubernetes** (official). Deploy a `StandaloneInstance` CRD to start. Deploy universal forwarders on nodes to ship logs to the Splunk indexer.

Recommended detection rules:
- Failed SSH attempts
- Sudo escalations
- Kubernetes audit log ingestion

---

## AWX ↔ FreeIPA Authentication

In AWX under **Settings → Authentication → LDAP**:

```
LDAP URI:         ldap://freeipa.lab.internal
Bind DN:          uid=awx-bind,cn=users,cn=accounts,dc=lab,dc=internal
User Search:      cn=users,cn=accounts,dc=lab,dc=internal
User DN Template: uid=%(user)s,cn=users,cn=accounts,dc=lab,dc=internal
Group Search:     cn=groups,cn=accounts,dc=lab,dc=internal
Require Group:    cn=awx-users,cn=groups,cn=accounts,dc=lab,dc=internal
```

- Create a dedicated `awx-bind` service account in FreeIPA with **read-only HBAC**
- Map FreeIPA groups to AWX organizations and roles via **LDAP Organization Map** and **LDAP Team Map** in AWX settings

---

## AWX ↔ GitLab CE Integration

In AWX:

1. Create a **Source Control credential** using a GitLab deploy token or SSH key scoped to the playbook repo
2. Create a **Project** pointing at:
   ```
   git@gitlab.lab.internal:infrateam/ansible-playbooks.git
   ```
3. Enable the **AWX project webhook** and configure a matching GitLab push webhook for automatic project sync on push

For secrets in playbooks, use AWX's **Vault credential type** (backed by HashiCorp Vault) or AWX's built-in **credential injection** — plaintext secrets must never live in GitLab repos.

---

## Monitoring Integration

Wire all data sources into Grafana:

| Datasource | Data |
|---|---|
| Prometheus | K8s metrics, node metrics, app `/metrics` endpoints |
| Zabbix plugin | Infrastructure-level checks |
| Splunk plugin | Log-based panels |

Create **ServiceMonitor CRDs** for AWX, GitLab, and NetBox so Prometheus scrapes them automatically.

---

## Security & Compliance Posture

This stack maps directly to CMMC/NIST control families:

| Control Area | Implementation |
|---|---|
| Centralized Identity | FreeIPA (LDAP/Kerberos) |
| Source-Controlled Automation | GitLab CE + AWX |
| SIEM & Log Integrity | Splunk with audit log ingestion |
| CMDB | NetBox |
| Observability | Prometheus + Grafana + Zabbix |
| Secrets Management | Sealed Secrets / HashiCorp Vault |
| TLS / PKI | FreeIPA CA + cert-manager |

---

## Further Reading

- [AWX Operator](https://github.com/ansible/awx-operator)
- [kube-prometheus-stack Helm chart](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
- [Splunk Operator for Kubernetes](https://github.com/splunk/splunk-operator)
- [NetBox Helm chart](https://github.com/netbox-community/netbox-chart)
- [Longhorn](https://longhorn.io/)
- [cert-manager](https://cert-manager.io/)
- [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
