# Architecture Overview

## Design Principles

This homelab is built to mirror an enterprise CMMC Level 2 / NIST 800-171 environment. Every architectural decision is made with the following goals:

- **Defense-in-depth**: Multiple security layers at every tier
- **Centralized identity**: All services authenticate through FreeIPA — no local user databases
- **Infrastructure-as-Code**: Every resource is provisioned via Terraform or Ansible — nothing configured by hand
- **GitOps**: All automation flows from GitLab CE through AWX — the repo is the source of truth
- **Observability**: Full-stack visibility across logs (Splunk), metrics (Prometheus/Grafana), and infrastructure checks (Zabbix)

## Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  PHYSICAL LAYER                                                 │
│  Proxmox VE 8.x — Single host hypervisor                       │
│  Rocky Linux 9 VMs with q35/UEFI, VirtIO, CPU passthrough      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  IDENTITY LAYER                                                 │
│  FreeIPA (ipa01.lab.internal)                                   │
│  LDAP · Kerberos · DNS · Internal CA                            │
│  All cluster services authenticate here                         │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  KUBERNETES LAYER (RKE2 — CIS profile)                         │
│  1 Control Plane + 3 Worker Nodes                               │
│  Canal CNI · Longhorn Storage · MetalLB · ingress-nginx         │
│  cert-manager (FreeIPA CA) · Sealed Secrets                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  APPLICATION LAYER                                              │
│  devops/    → AWX, GitLab CE                                    │
│  monitoring/ → Prometheus, Grafana, Zabbix, Alertmanager        │
│  logging/   → Splunk Enterprise                                 │
│  netops/    → NetBox CMDB                                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  AUTOMATION FLOW                                                │
│  GitLab (playbook SCM) → AWX (executor) → Nodes (targets)      │
│  All changes tracked in Git · All executions logged in AWX      │
└─────────────────────────────────────────────────────────────────┘
```

## Network Topology

All VMs reside on `vmbr1` (lab bridge), `192.168.10.0/24`. The Proxmox host's management interface is on `vmbr0`.

MetalLB allocates LoadBalancer IPs from `192.168.10.200-220`. The ingress controller takes `.200`.

## Security Controls

| Control Domain | Implementation |
|---|---|
| Access Control | FreeIPA LDAP/Kerberos, HBAC rules |
| Audit & Accountability | auditd, K8s audit logs, Splunk SIEM |
| Configuration Management | Ansible + GitLab version control |
| Identification & Authentication | FreeIPA, SSH key-only access |
| System & Communications Protection | TLS everywhere (FreeIPA CA), firewalld |
| System & Info Integrity | AIDE file integrity, Zabbix monitoring |
