# 🏠 Homelab K8s Infrastructure

> **Proxmox → Rocky Linux 9 VMs → RKE2 → AWX · FreeIPA · GitLab CE · Splunk · Zabbix · Grafana · NetBox · Prometheus**

## Overview

This repository contains all Infrastructure-as-Code for a fully automated, security-hardened homelab Kubernetes environment. The stack is designed to mirror enterprise CMMC Level 2 / NIST 800-171 compliant infrastructure.

## Stack Summary

| Layer | Technology |
|---|---|
| Hypervisor | Proxmox VE |
| OS | Rocky Linux 9 (CIS hardened) |
| Kubernetes | RKE2 (CIS profile) |
| Identity | FreeIPA (LDAP/Kerberos) |
| Automation | Ansible AWX + GitLab CE |
| Monitoring | Prometheus + Grafana + Zabbix |
| SIEM | Splunk Enterprise |
| CMDB | NetBox |
| Storage | Longhorn |
| Ingress | ingress-nginx + cert-manager |
| LB | MetalLB (L2 mode) |

## Quick Start

```bash
# 1. Provision VMs
cd terraform && terraform init && terraform apply

# 2. Harden and configure nodes
cd ../ansible
ansible-playbook playbooks/provision_vms.yml
ansible-playbook playbooks/harden_os.yml

# 3. Deploy RKE2
ansible-playbook playbooks/install_rke2_server.yml
ansible-playbook playbooks/install_rke2_agent.yml

# 4. Deploy cluster services (in order)
ansible-playbook playbooks/site.yml
```

See `docs/deployment-order.md` for the full step-by-step sequence.

## Repository Structure

```
homelab-k8s/
├── terraform/        # Proxmox VM provisioning
├── ansible/          # OS hardening, RKE2 install, app deployment
├── kubernetes/       # Helm values & K8s manifests per service
├── freeipa/          # FreeIPA VM config, LDAP schema, HBAC
├── docs/             # Architecture docs, runbooks
└── scripts/          # Utility & bootstrap helpers
```

## Prerequisites

- Proxmox VE 8.x host with sufficient resources (see `docs/vm-specifications.md`)
- Terraform >= 1.6
- Ansible >= 2.15
- kubectl >= 1.28
- Helm >= 3.12
- `kubeseal` for Sealed Secrets management

## Documentation

- [Architecture Overview](docs/architecture-overview.md)
- [VM Specifications](docs/vm-specifications.md)
- [Deployment Order](docs/deployment-order.md)
- [LDAP Integration Guide](docs/ldap-integration-guide.md)
- [AWX + GitLab Workflow](docs/awx-gitlab-workflow.md)
- [CMMC Control Mapping](docs/cmmc-control-mapping.md)

## License

MIT — For homelab/educational use.
