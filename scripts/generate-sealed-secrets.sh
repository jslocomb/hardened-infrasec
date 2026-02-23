#!/bin/bash
# generate-sealed-secrets.sh
# Helper script to seal Kubernetes secrets with kubeseal.
# Requires: kubeseal, kubectl (with cluster access)
set -euo pipefail

NAMESPACE=${1:-default}
SECRET_FILE=${2:-}

if [[ -z "$SECRET_FILE" ]]; then
  echo "Usage: $0 <namespace> <secret-file.yaml>"
  echo "Example: $0 devops kubernetes/awx/ldap-secret.yaml"
  exit 1
fi

OUTPUT_FILE="${SECRET_FILE%.yaml}-sealed.yaml"

echo "Sealing: $SECRET_FILE → $OUTPUT_FILE"

# Fetch the public cert from the cluster (or use --cert flag)
kubeseal \
  --namespace "$NAMESPACE" \
  --format yaml \
  < "$SECRET_FILE" \
  > "$OUTPUT_FILE"

echo "Sealed secret written to: $OUTPUT_FILE"
echo "Safe to commit: $OUTPUT_FILE"
echo "DO NOT commit: $SECRET_FILE"
