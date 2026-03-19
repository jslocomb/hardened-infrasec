#!/bin/bash
# kubeconfig-merge.sh
# Fetch kubeconfig from RKE2 control plane and merge into local ~/.kube/config
set -euo pipefail

CP_HOST=${1:-k8s-cp01.lab.internal}
CONTEXT_NAME=${2:-homelab}

echo "Fetching kubeconfig from $CP_HOST..."

# Copy kubeconfig from control plane
scp ansible@${CP_HOST}:/etc/rancher/rke2/server/creds/admin.kubeconfig /tmp/rke2-kubeconfig

# Replace the default server URL with the actual hostname
sed -i "s|127.0.0.1|${CP_HOST}|g" /tmp/rke2-kubeconfig
sed -i "s|default|${CONTEXT_NAME}|g" /tmp/rke2-kubeconfig

# Merge into local config
if [[ -f ~/.kube/config ]]; then
  KUBECONFIG=~/.kube/config:/tmp/rke2-kubeconfig \
    kubectl config view --flatten > /tmp/merged-kubeconfig
  mv /tmp/merged-kubeconfig ~/.kube/config
else
  mkdir -p ~/.kube
  cp /tmp/rke2-kubeconfig ~/.kube/config
fi

chmod 600 ~/.kube/config
rm -f /tmp/rke2-kubeconfig

echo "Done. Switch context with: kubectl config use-context ${CONTEXT_NAME}"
kubectl config use-context "${CONTEXT_NAME}"
kubectl get nodes
