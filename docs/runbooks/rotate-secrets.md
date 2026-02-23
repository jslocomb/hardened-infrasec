# Runbook: Rotate Secrets

## LDAP Bind Account Passwords

```bash
# 1. Generate new password
NEW_PASS=$(openssl rand -base64 24)

# 2. Update in FreeIPA
kinit admin
ipa user-mod awx-bind --password <<< "$NEW_PASS"

# 3. Update in Kubernetes secret
kubectl create secret generic awx-ldap-bind-secret \
  --from-literal=ldap_bind_password="$NEW_PASS" \
  --namespace devops \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Restart AWX to pick up new credentials
kubectl rollout restart deployment awx-web -n devops
```

## Sealed Secrets Rotation

```bash
# Re-seal a secret with current cluster key
kubectl get secret awx-ldap-bind-secret -n devops -o yaml \
  | kubeseal --format yaml > kubernetes/awx/ldap-secret-sealed.yaml
git add kubernetes/awx/ldap-secret-sealed.yaml
git commit -m "chore: rotate awx ldap bind secret"
```

## TLS Certificate Rotation

cert-manager handles rotation automatically before expiry. Force immediate renewal:
```bash
kubectl annotate certificate awx-tls -n devops \
  cert-manager.io/issuer-kind="ClusterIssuer" \
  --overwrite
```
