# Runbook: RKE2 Cluster Upgrade

## Overview
Upgrade RKE2 one node at a time. Always upgrade the control plane first.

## Pre-Upgrade Checklist
- [ ] Check release notes: https://github.com/rancher/rke2/releases
- [ ] Verify Longhorn volume health: all volumes green
- [ ] Take Longhorn backups of critical PVCs
- [ ] Confirm kubectl access works

## Upgrade Control Plane

```bash
# 1. Cordon the control plane (optional for single-node CP)
kubectl cordon k8s-cp01.lab.internal

# 2. Update the version in group_vars
vim ansible/inventory/group_vars/control_plane.yml
# Change rke2_version to new version

# 3. Run upgrade via Ansible
ansible-playbook playbooks/install_rke2_server.yml --tags upgrade

# 4. Verify
kubectl get nodes
kubectl version
```

## Upgrade Worker Nodes (one at a time)

```bash
for worker in k8s-w01 k8s-w02 k8s-w03; do
  echo "=== Upgrading $worker ==="
  kubectl drain ${worker}.lab.internal --ignore-daemonsets --delete-emptydir-data
  ansible-playbook playbooks/install_rke2_agent.yml \
    --limit="${worker}.lab.internal" --tags upgrade
  kubectl uncordon ${worker}.lab.internal
  kubectl wait --for=condition=Ready node/${worker}.lab.internal --timeout=300s
  echo "=== $worker upgraded ==="
done
```
