# Lessons Learned — homelab-k8s

**Author:** Jason A. Slocomb  
**Project:** CMMC Level 2 Security Automation Lab  
**Platform:** AWS us-west-2 | Rocky Linux 9.7 | RKE2 Kubernetes

This document captures the key technical challenges, dead ends, and breakthroughs encountered during the build. It is intended as a reference for future deployments and as a demonstration of systematic problem-solving and root cause analysis.

---

## 1. AWX is Kubernetes-native — there is no standalone path

**The problem:** AWX 18+ cannot be run outside of Kubernetes. This is not clearly documented. The official docs mention Docker as an option, but the container image (`quay.io/ansible/awx:24.6.1`) is built assuming Kubernetes init containers will configure nginx before the main container starts. The nginx config that proxies to the AWX uwsgi backend simply does not exist in the base image — it is injected at runtime by the operator's init containers.

**What we tried:** Over 19 deployment attempts across three strategies:
- K8s operator on RKE2 (correct approach, but blocked by a circular dependency)
- AWX source install (no installer exists for 18+)
- Podman/Docker Compose on a standalone node (failed at nginx config layer)

**The breakthrough:** After getting the Docker Compose approach to serve HTTP 200, we discovered it was returning the Rocky Linux default nginx test page — not AWX. Investigation revealed the nginx config was never written. This confirmed AWX is exclusively K8s-native and we returned to the operator approach with a clear understanding of the actual problem.

**Lesson:** When official documentation says "Docker or Kubernetes," verify whether Docker support was removed in a recent major version. AWX's Docker support was quietly deprecated around version 18.

---

## 2. AWX operator circular initialization dependency

**The problem:** The AWX operator has a deadlock in its initialization sequence. The `init-database` container runs `wait-for-migrations`, which checks `awx-manage showmigrations` to verify all migrations are applied. But migrations only run inside the task pod — and the task pod cannot complete its init until migrations are verified. Both pods wait indefinitely for each other.

**Why it's hard to diagnose:** The pods show `Init:0/2` with no error messages. The deadlock is silent. Without understanding the AWX codebase, it looks like the operator is simply slow to start.

**The fix:** Pre-run Django migrations from a standalone `kubectl run` pod immediately after the postgres pod reaches Running state, before the task pod's init container exhausts its attempts. The pod needs:
- The `awx-awx-configmap` ConfigMap mounted at `/etc/tower/settings.py` (key: `settings`, not `settings.py`)
- The `awx-secret-key` secret mounted at `/etc/tower/SECRET_KEY` (key: `secret_key`, not `SECRET_KEY`)
- The `awx-app-credentials` secret mounted at `/etc/tower/conf.d/credentials.py`
- `dnsPolicy: ClusterFirst` to resolve the postgres service hostname
- Pod CIDR firewalld rules on all K8s nodes (see lesson 4)

**Key insight:** The secret and configmap key names do not match the mount paths. The configmap key is `settings` (not `settings.py`) and the secret key is `secret_key` (not `SECRET_KEY`). Getting these wrong causes `MountVolume.SetUp failed` errors that look unrelated to the migration issue.

---

## 3. RKE2 ingress nginx uses reuseport on port 80

**The problem:** GitLab CE needs to listen on port 80, but RKE2's bundled ingress-nginx controller binds port 80 with the `reuseport` socket option on all nodes. Any native service attempting to bind port 80 fails silently — nginx starts but returns the RKE2 default backend instead of the application.

**Symptom:** GitLab installed and appeared healthy, but all web requests returned a 404 from the RKE2 ingress default backend.

**The fix:** Configure GitLab CE to use an alternate port (8929). The nginx config must be updated to match: `listen 8929` in the GitLab nginx configuration, and the GitLab external URL updated to include the port.

**Lesson:** Any native (non-Kubernetes) service on a RKE2 worker node must avoid ports 80 and 443. RKE2 owns those ports on all nodes in the cluster.

---

## 4. Pod CIDR routes must be trusted in firewalld

**The problem:** Cross-node pod communication failed silently. A pod on k8s-w01 could not reach a pod on k8s-w02 even though Canal CNI was running on all nodes. The connection timed out with "No route to host."

**Root cause:** Rocky Linux 9 ships with firewalld enabled by default. firewalld was blocking traffic from the pod CIDR ranges (10.42.0.0/16 and 10.43.0.0/16) because they are not in any trusted zone. The Canal CNI overlay tunnels the traffic, but firewalld drops it before Canal can process it.

**The fix:**
```bash
firewall-cmd --add-source=10.42.0.0/16 --zone=trusted --permanent
firewall-cmd --add-source=10.43.0.0/16 --zone=trusted --permanent
firewall-cmd --reload
```

This must be run on every K8s node. It is not applied automatically by the RKE2 installer.

**Lesson:** RKE2 documentation does not mention firewalld configuration for Rocky Linux. Always verify pod-to-pod connectivity across nodes immediately after cluster setup.

---

## 5. kubectl port-forward only accepts localhost connections

**The problem:** `kubectl port-forward --address 0.0.0.0` appears to bind to all interfaces, but connections from external hosts (including the bastion) return HTTP 400 "Bad Request." The port-forward only accepts connections that originate from localhost on the node running kubectl.

**Root cause:** kubectl port-forward uses the Kubernetes API server as a proxy. The `--address` flag controls which interface kubectl listens on, but the Kubernetes API's `portforward` subresource validates that connections come from the local pod network. External connections fail at the API level, not the network level.

**The fix:** Use SSH jump tunnels instead of direct port-forward tunnels:
```bash
# Wrong — doesn't work through bastion
ssh -L 8080:10.0.10.146:8080 bastion -N -f

# Correct — tunnels directly to localhost on k8s-cp01
ssh -L 8080:localhost:8080 -J bastion k8s-cp01 -N -f
```

---

## 6. Splunk index creation via CLI can fail silently

**The problem:** Running `splunk add index linux_audit` appeared to succeed (exit code 0, no error output), but the index did not appear in the Splunk UI and forwarder data was not indexed.

**Root cause:** The `splunk add index` CLI command writes to a user-specific config layer that can be overridden by the system layer. In some configurations the command succeeds from the CLI perspective but the index is not actually created in the active configuration.

**The fix:** Write the index configuration directly to the system local config:
```bash
cat >> /opt/splunk/etc/system/local/indexes.conf << EOF
[linux_audit]
homePath = $SPLUNK_DB/linux_audit/db
coldPath = $SPLUNK_DB/linux_audit/colddb
thawedPath = $SPLUNK_DB/linux_audit/thaweddb
EOF
/opt/splunk/bin/splunk restart
```

---

## 7. Falco modern_ebpf driver conflicts with the container plugin on Rocky Linux 9

**The problem:** Falco deployed successfully with the `modern_ebpf` driver but immediately logged errors about duplicate container plugin registration and failed to start properly.

**Root cause:** The `modern_ebpf` driver in Falco 0.43.0 has a known conflict with the container metadata plugin on Rocky Linux 9 / kernel 5.14. The plugin registers twice, causing a fatal initialization error.

**The fix:** Use the legacy eBPF driver instead:
```yaml
driver:
  kind: ebpf
```

The legacy eBPF driver requires `kernel-devel` and `kernel-headers` packages on all K8s nodes matching the running kernel version.

**Lesson:** Always check Falco's GitHub issues for driver compatibility before deployment. `modern_ebpf` is not universally supported despite being the recommended driver.

---

## 8. NetBox v4.5.5 requires API_TOKEN_PEPPERS for token creation

**The problem:** After deploying NetBox v4.5.5 via the netbox-community Helm chart, the UI displayed "Unable to save v2 tokens: API_TOKEN_PEPPERS is not defined" when attempting to create API tokens through either the UI or the `/api/users/tokens/provision/` endpoint.

**Root cause:** NetBox v4.x introduced a required `API_TOKEN_PEPPERS` configuration variable for enhanced token security. The Helm chart does not configure this by default.

**The fix:** Create a Kubernetes secret with a Python configuration snippet and mount it as an extra config file:
```bash
kubectl -n netbox create secret generic netbox-token-pepper \
  --from-literal='netbox.py=API_TOKEN_PEPPERS = {"1": "your-pepper-key-here"}'
```

**Workaround:** Use v1 tokens instead of v2 tokens. v1 tokens do not require the pepper configuration and work for all API operations.

---

## 9. Resource sizing — always provision larger than you think

Several services required larger instance types than initially planned:

| Service | Initial | Required | Reason |
|---------|---------|----------|--------|
| GitLab CE | t3.medium | t3.large | GitLab requires ~3GB RAM minimum |
| Splunk | t3.medium | t3.large | Splunk indexing requires ~4GB RAM |
| AWX web pod | 1Gi limit | 2Gi limit | OOMKilled repeatedly at 1Gi |
| AWX task pod | t3.medium node | t3.large node | OOM during migration |

**Lesson:** For a CMMC lab stack, assume every service needs a t3.large node. t3.medium is only appropriate for the control plane.

---

## 10. FreeIPA DNS must be explicitly set after node reboot

**The problem:** After rebooting any lab node, DNS resolution for `lab.internal` hostnames failed. Nodes would fall back to the AWS VPC DNS resolver which does not know about FreeIPA's internal zone.

**Root cause:** NetworkManager on Rocky Linux 9 resets DNS configuration on interface restart. The FreeIPA DNS setting is not persisted across reboots by default.

**The fix:**
```bash
nmcli con mod 'System eth0' ipv4.dns '10.0.10.113' ipv4.ignore-auto-dns yes
nmcli con up 'System eth0'
```

This must be run on every node after any reboot, or baked into an Ansible playbook that runs at node startup.

---

## Summary

The most significant insight from this build is that **modern enterprise automation tools are designed for Kubernetes and assume Kubernetes**. AWX, NetBox, and Grafana all have Kubernetes-native deployment paths that are vastly better supported than their standalone equivalents. The attempt to run AWX outside of Kubernetes cost the most time and generated the most valuable learning — it forced a deep understanding of how the operator initialization sequence works, what init containers do, and how Django migrations relate to application startup.

The second most significant insight is that **Rocky Linux 9's default security posture requires explicit configuration for Kubernetes networking**. firewalld, SELinux, and NetworkManager all need attention that RKE2 documentation does not fully cover for RHEL-family operating systems. These are exactly the kinds of issues that appear in production DoD contractor environments where hardened OS baselines are required.
