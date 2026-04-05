# Falco → Splunk Integration: Detection Engineering on RKE2

> **Location in repo:** `docs/falco-splunk-integration.md`  
> **CMMC controls:** SI.L2-3.14.2, SI.L2-3.14.6, SI.L2-3.14.7, AU.L2-3.3.1, AU.L2-3.3.2  
> **Stack:** Falco 0.43.0 · Falcosidekick 2.32.0 · Splunk Enterprise 10.2.1 · RKE2 · Rocky Linux 9.7 · AWS us-west-2

---

## Why This Integration Matters

Falco catches what auditd and AIDE miss: **runtime behavior inside running containers**. A container can have a clean image SHA and a clean filesystem, and still spawn a reverse shell at 2am. Auditd sees the syscall. AIDE sees nothing until its next scheduled run. Falco fires immediately.

But a Falco alert that stays in a pod log is not a security control — it's noise you'll never act on. The value comes from getting those alerts into Splunk, correlated with auth events, audit logs, and AIDE findings, in a structured format you can query and alert on.

This document covers the full implementation: what was already in place, what was missing, and exactly how the wiring works — including the specific failure modes encountered during build.

---

## What Was Already Built

When Falco was deployed in Phase 8 of this lab build, it was intentionally kept minimal:

```bash
helm upgrade --install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=false \
  --set tty=true \
  --set falcoctl.artifact.install.enabled=false \
  --set falcoctl.artifact.follow.enabled=false
```

**Why `falcosidekick.enabled=false`?** At the time, the goal was getting Falco running and detecting events — validating the eBPF driver worked on Rocky Linux 9.7 before adding routing complexity. Falco was confirmed working: it immediately detected Splunk's Universal Forwarder spawning shell processes during startup, which is exactly the kind of signal it's designed to surface.

What was missing was the pipeline from Falco's JSON output to Splunk's HTTP Event Collector (HEC), with Kubernetes context enriched into every alert.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster (RKE2)                                          │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │  k8s-cp01   │    │  k8s-w01    │    │  k8s-w02    │             │
│  │             │    │             │    │             │             │
│  │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │             │
│  │ │  Falco  │ │    │ │  Falco  │ │    │ │  Falco  │ │             │
│  │ │  (eBPF) │ │    │ │  (eBPF) │ │    │ │  (eBPF) │ │             │
│  │ └────┬────┘ │    │ └────┬────┘ │    │ └────┬────┘ │             │
│  └──────┼──────┘    └──────┼──────┘    └──────┼──────┘             │
│         │                  │                  │                     │
│         └──────────────────┼──────────────────┘                     │
│                            │ JSON via http_output (:2801)           │
│                     ┌──────▼───────┐                                │
│                     │ falcosidekick│                                │
│                     │  2 replicas  │                                │
│                     └──────┬───────┘                                │
│                            │ HTTPS POST to HEC                      │
└────────────────────────────┼───────────────────────────────────────┘
                             │
                    ┌────────▼────────────────────────────┐
                    │  Splunk 10.2.1 (k8s-w02)            │
                    │  https://10.0.10.117:8088/          │
                    │    services/collector/event         │
                    │                                     │
                    │  index=falco_alerts                 │
                    └─────────────────────────────────────┘
```

Each Falco DaemonSet pod sends JSON output via `http_output` to the falcosidekick service on port 2801. Falcosidekick forwards to Splunk HEC with enriched Kubernetes metadata.

---

## Step 1 — Enable Splunk HEC and Create Index

```bash
ssh k8s-w02 "
  sudo /opt/splunk/bin/splunk add index falco_alerts \
    -maxTotalDataSizeMB 5120 \
    --run-as-root

  sudo /opt/splunk/bin/splunk http-event-collector enable \
    -uri https://localhost:8089 \
    -auth admin:'<SPLUNK_ADMIN_PASSWORD>' \
    --run-as-root

  sudo /opt/splunk/bin/splunk http-event-collector create falco-token \
    -uri https://localhost:8089 \
    -auth admin:'<SPLUNK_ADMIN_PASSWORD>' \
    -index falco_alerts \
    -sourcetype falco \
    --run-as-root
"
```

Capture the token from the output. Store it in your password manager:

```
pass Lab/falco/falco-token
```

Verify HEC is healthy:

```bash
curl -sk https://10.0.10.117:8088/services/collector/health
# Expected: {"text":"HEC is healthy","code":17}
```

Open port 8088 on the Splunk node firewall — required for pod CIDR traffic from other nodes:

```bash
ssh k8s-w02 "
  sudo firewall-cmd --permanent --add-port=8088/tcp
  sudo firewall-cmd --reload
"
```

---

## Step 2 — Deploy Falco with Falcosidekick

The full Helm upgrade command that produced the working REVISION 6 deployment:

```bash
scp k8s/falco/falcosidekick-values.yaml k8s-cp01:/tmp/falcosidekick-values.yaml

ssh k8s-cp01 "sudo /usr/local/bin/helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url=http://falco-falcosidekick:2801 \
  --set falco.json_output=true \
  --set falcoctl.artifact.install.enabled=false \
  --set falcoctl.artifact.follow.enabled=false \
  --set tty=true \
  --values /tmp/falcosidekick-values.yaml \
  --timeout 10m"
```

Key flags:
- `falco.http_output.enabled=true` — enables Falco's HTTP output driver
- `falco.http_output.url=http://falco-falcosidekick:2801` — points Falco at the falcosidekick ClusterIP service
- `falco.json_output=true` — required for falcosidekick to parse events
- `falcosidekick.enabled=true` — deploys the falcosidekick sidecar Deployment

Verify all pods are running:

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco get pods"
```

Expected:
```
NAME                                   READY   STATUS    RESTARTS   AGE
falco-c4lql                            1/1     Running   0          ...
falco-falcosidekick-xxxxx-xxxxx        1/1     Running   0          ...
falco-falcosidekick-xxxxx-xxxxx        1/1     Running   0          ...
falco-nq78p                            1/1     Running   0          ...
falco-r6rbw                            1/1     Running   0          ...
```

---

## Step 3 — Configure Falcosidekick Splunk Output

The Helm chart renders falcosidekick config into a Kubernetes secret named `falco-falcosidekick`. The secret uses environment variable names directly — the `SPLUNK_HOST` value must be the **full HEC endpoint URL including path**:

```bash
# Patch the secret directly after each Helm upgrade
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco patch secret falco-falcosidekick \
  --type=json \
  -p='[
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_HOST\",\"value\":\"aHR0cHM6Ly8xMC4wLjEwLjExNzo4MDg4L3NlcnZpY2VzL2NvbGxlY3Rvci9ldmVudA==\"},
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_TOKEN\",\"value\":\"<BASE64_ENCODED_TOKEN>\"},
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_CHECKCERT\",\"value\":\"ZmFsc2U=\"},
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_MINIMUMPRIORITY\",\"value\":\"bm90aWNl\"},
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_INDEX\",\"value\":\"ZmFsY29fYWxlcnRz\"},
    {\"op\":\"replace\",\"path\":\"/data/SPLUNK_SOURCETYPE\",\"value\":\"ZmFsY28=\"},
    {\"op\":\"replace\",\"path\":\"/data/DEBUG\",\"value\":\"dHJ1ZQ==\"}
  ]' && \
  sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco delete pods -l app.kubernetes.io/name=falcosidekick"
```

Base64 reference:
| Value | Base64 |
|---|---|
| `https://10.0.10.117:8088/services/collector/event` | `aHR0cHM6Ly8xMC4wLjEwLjExNzo4MDg4L3NlcnZpY2VzL2NvbGxlY3Rvci9ldmVudA==` |
| `false` | `ZmFsc2U=` |
| `notice` | `bm90aWNl` |
| `falco_alerts` | `ZmFsY29fYWxlcnRz` |
| `falco` | `ZmFsY28=` |
| `true` | `dHJ1ZQ==` |

Verify the secret is set correctly:

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco get secret falco-falcosidekick \
  -o jsonpath='{.data.SPLUNK_HOST}' | base64 -d && echo"
```

---

## Step 4 — Verify the Pipeline

Check falcosidekick logs for successful POSTs:

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco logs deployment/falco-falcosidekick --tail=20"
```

Expected output:
```
2026/04/05 00:10:29 [INFO]  : Falcosidekick version: 2.32.0
2026/04/05 00:10:29 [INFO]  : Enabled Outputs: [Splunk]
2026/04/05 00:10:29 [INFO]  : Falcosidekick is up and listening on :2801
2026/04/05 00:10:43 [INFO]  : Splunk - POST OK (200)
```

Verify events in Splunk:

```bash
ssh k8s-w02 "sudo /opt/splunk/bin/splunk search \
  'index=falco_alerts earliest=-15m | stats count by rule' \
  -auth admin:'<PASSWORD>' \
  --run-as-root"
```

---

## Step 5 — Splunk Searches

### All Falco Events by Rule

```spl
index=falco_alerts earliest=-24h
| stats count by rule, priority
| sort - count
```

### Shell Spawned in Container

```spl
index=falco_alerts earliest=-24h
  rule="Terminal shell in container"
  k8s_namespace!=falco
  k8s_namespace!=kube-system
| table _time, k8s_namespace, k8s_pod_name, container_image, user_name, proc_cmdline
```

### Cross-Index Correlation: Falco + SSH Auth

```spl
| union
    [search index=falco_alerts earliest=-1h
     | eval event_source="falco", summary=rule
     | table _time, host, summary, event_source]
    [search index=linux_secure earliest=-1h "Failed password" OR "Accepted publickey"
     | rex field=_raw "for (?<ssh_user>\S+) from (?<src_ip>\S+)"
     | eval event_source="ssh", summary="SSH: ".ssh_user." from ".src_ip
     | table _time, host, summary, event_source]
| sort _time
| transaction host maxspan=10m keepeventsourceorder=true
| where eventcount > 1 AND mvcount(event_source) > 1
| table _time, host, eventcount, mvjoin(summary, " | ")
```

---

## CMMC Control Evidence

| Control | Requirement | Evidence |
|---|---|---|
| SI.L2-3.14.2 | Malicious code protection | Falco DaemonSet running on all 3 nodes — `kubectl get ds -n falco` |
| SI.L2-3.14.6 | Monitor for attacks | Real-time detection confirmed — `index=falco_alerts \| stats count by rule` |
| SI.L2-3.14.7 | Identify unauthorized use | Falco + Splunk correlation searches operational |
| AU.L2-3.3.1 | Create and retain audit logs | `index=falco_alerts` with 90-day retention |
| AU.L2-3.3.2 | Trace actions to users | `k8s_pod_name`, `user_name`, `proc_cmdline` fields in every event |

---

## Lessons Learned

**`SPLUNK_HOST` requires the full endpoint path.** The falcosidekick source code passes `SPLUNK_HOST` directly to `http.NewRequest()` with no path appended. The value must be the complete URL: `https://host:port/services/collector/event`. Using just `host:port` or `https://host:port` results in 404 errors because Splunk's web UI intercepts the request at `/`.

**The Helm chart does not honor `config.splunk.hostport` or `config.splunk.host` from a values file reliably in this version.** The rendered secret uses environment variable names (`SPLUNK_HOST`, `SPLUNK_TOKEN`, etc.). After each Helm upgrade, patch the secret directly and delete the falcosidekick pods to pick up the new values.

**Port 8088 must be opened in firewalld on the Splunk node.** Pod CIDR traffic (`10.42.0.0/16`) originates from worker nodes and is subject to host firewall rules. Opening port 8088 only in the security group is insufficient — firewalld on k8s-w02 must also allow it.

**`modern_ebpf` fails on Rocky Linux 9.7 with RKE2.** Use `driver.kind=ebpf` (legacy eBPF). The deprecation warning is safe to ignore.

**Falco detects its own environment.** Two high-volume rules fire continuously in this lab:
- `Run shell untrusted` — Splunk spawning Python subshells every 60 seconds
- `Contact K8S API Server From Container` — AWX task pod polling the K8s API every 60 seconds

Both are expected behavior. Suppress them in `custom_rules.yaml` to reduce noise in `falco_alerts`.

**`http_output` in Falco must be explicitly enabled via Helm `--set` flags.** Setting it in a values file is not sufficient — use `--set falco.http_output.enabled=true` and `--set falco.http_output.url=http://falco-falcosidekick:2801` on every upgrade.

---

## Known Issues / Future Work

- HEC token is stored in plaintext in `falcosidekick-values.yaml` — should be moved to a Sealed Secret
- Custom suppression rules in `custom_rules.yaml` need to be deployed to the cluster
- No Splunk saved searches or scheduled alerts configured yet
- `image_digest` field is empty — containers pulled by tag, not digest

---

## Repository Layout

```
homelab-k8s/
├── k8s/
│   └── falco/
│       ├── falcosidekick-values.yaml     # Helm values for falcosidekick
│       └── custom_rules.yaml             # Lab-specific rule suppressions
├── ansible/
│   └── roles/
│       └── splunk_config/
│           └── tasks/
│               └── hec.yaml              # Idempotent HEC + index setup
└── docs/
    └── falco-splunk-integration.md       # This file
```

---

## References

- [Falco 0.43.0 Release Notes](https://falco.org/blog/falco-0-43-0/)
- [Falcosidekick 2.32.0 Source — splunk.go](https://github.com/falcosecurity/falcosidekick/blob/2.32.0/outputs/splunk.go)
- [Falcosidekick 2.32.0 Source — main.go](https://github.com/falcosecurity/falcosidekick/blob/2.32.0/main.go)
- [Splunk HEC Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [NIST SP 800-171 Rev 2 — SI Family](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
