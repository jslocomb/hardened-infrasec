# Falco → Splunk Integration: Detection Engineering on RKE2

> **Location in repo:** `docs/falco-splunk-integration.md`  
> **CMMC controls:** SI.L2-3.14.2, SI.L2-3.14.6, SI.L2-3.14.7, AU.L2-3.3.1, AU.L2-3.3.2  
> **Stack:** Falco 0.43.0 · Splunk Enterprise 10.2.1 · RKE2 · Rocky Linux 9.7 · AWS us-west-2

---

## Why This Integration Matters

Falco catches what auditd and AIDE miss: **runtime behavior inside running containers**. A container can have a clean image SHA and a clean filesystem, and still spawn a reverse shell at 2am. Auditd sees the syscall. AIDE sees nothing until its next scheduled run. Falco fires immediately.

But a Falco alert that stays in a pod log is not a security control — it's noise you'll never act on. The value comes from getting those alerts into Splunk, correlated with auth events, audit logs, and AIDE findings, in a structured format you can query and alert on.

This document covers the full implementation: what was already in place, what was missing, and exactly how the wiring works.

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

What was missing was the pipeline from Falco's JSON output to Splunk's HTTP Event Collector (HEC), with Kubernetes context (pod name, namespace, image SHA) enriched into every alert.

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
│                            │ JSON over stdout                        │
│                     ┌──────▼───────┐                                │
│                     │  falcosidekick│                               │
│                     │  (sidecar)   │                                │
│                     └──────┬───────┘                                │
│                            │ HTTP POST (HEC)                        │
└────────────────────────────┼───────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Splunk 10.2.1  │
                    │  k8s-w02:8088   │
                    │                 │
                    │  index=         │
                    │  falco_alerts   │
                    └─────────────────┘
```

Each Falco DaemonSet pod outputs structured JSON. Falcosidekick (deployed as a sidecar Deployment) reads those events and forwards them to Splunk HEC on port 8088. Every event is enriched with Kubernetes metadata before it leaves the cluster.

---

## Why Not Log-File Forwarding?

The alternative to falcosidekick is having the Splunk Universal Forwarder watch Falco's log output. This is simpler to configure but has two meaningful problems in a CMMC context:

**Field parsing is fragile.** Falco's text output format can change across versions. The Splunk UF would ingest it as a raw string, requiring a custom sourcetype extraction regex that breaks on format changes. Falcosidekick sends structured JSON with a stable schema — every field is queryable immediately.

**No enrichment hook.** The UF reads what Falco writes. Falcosidekick has a templating layer that lets you add arbitrary fields before the event leaves the cluster — you can inject the image SHA, the Kubernetes node name, a CMMC control tag, or a severity normalization at the pipeline level rather than at query time.

---

## Step 1 — Enable Splunk HEC

If HEC is not yet enabled on your Splunk instance, enable it via CLI on `k8s-w02`:

```bash
ssh k8s-w02 "
  sudo /opt/splunk/bin/splunk http-event-collector enable \
    -uri https://localhost:8089 \
    -auth admin:'Splunk_Admin2026!' \
    --run-as-root

  sudo /opt/splunk/bin/splunk http-event-collector create falco-token \
    -uri https://localhost:8089 \
    -auth admin:'Splunk_Admin2026!' \
    -index falco_alerts \
    -sourcetype falco \
    --run-as-root
"
```

Capture the token that comes back — you'll need it in the next step. Then create the index if it doesn't exist:

```bash
ssh k8s-w02 "
  sudo /opt/splunk/bin/splunk add index falco_alerts \
    -maxTotalDataSizeMB 5120 \
    --run-as-root
"
```

Verify HEC is listening:

```bash
curl -sk https://k8s-w02.lab.internal:8088/services/collector/health
# Expected: {"text":"HEC is healthy","code":200}
```

---

## Step 2 — Create the Falcosidekick Values File

Falcosidekick is configured entirely through Helm values. Create this file at `k8s/falco/falcosidekick-values.yaml` in the repo:

```yaml
# k8s/falco/falcosidekick-values.yaml
# Falcosidekick configuration — Falco alert routing to Splunk HEC
# Ref: https://github.com/falcosecurity/charts/tree/master/charts/falcosidekick

replicaCount: 2   # HA — one per worker node is fine at this scale

config:
  splunk:
    hostport: "https://k8s-w02.lab.internal:8088"
    token: ""          # Injected from Kubernetes Secret — do not hardcode
    index: "falco_alerts"
    sourcetype: "falco"
    minimumpriority: "notice"   # notice | warning | error | critical | alert | emergency
    checkcert: false            # Self-signed cert on lab Splunk instance

  customfields:
    # These fields are appended to every alert Falcosidekick forwards.
    # Visible as indexed fields in Splunk: falco.environment, falco.cmmc_control, etc.
    environment: "homelab-k8s"
    cluster: "rke2-us-west-2"
    compliance_framework: "CMMC_L2"
    # CMMC controls demonstrated by runtime detection:
    cmmc_si_3_14_2: "malicious_code_protection"
    cmmc_si_3_14_6: "monitor_for_attacks"
    cmmc_si_3_14_7: "identify_unauthorized_use"

  templatedfields:
    # Dynamic fields pulled from the Falco event itself.
    # {{ .Output }} = full Falco alert string
    # {{ .OutputFields }} = map of all k8s.* fields Falco extracted
    k8s_pod_name:    "{{ index .OutputFields \"k8s.pod.name\" }}"
    k8s_namespace:   "{{ index .OutputFields \"k8s.ns.name\" }}"
    k8s_node_name:   "{{ index .OutputFields \"k8s.node.name\" }}"
    container_image: "{{ index .OutputFields \"container.image.repository\" }}"
    image_tag:       "{{ index .OutputFields \"container.image.tag\" }}"
    image_digest:    "{{ index .OutputFields \"container.image.digest\" }}"
    proc_name:       "{{ index .OutputFields \"proc.name\" }}"
    proc_cmdline:    "{{ index .OutputFields \"proc.cmdline\" }}"
    user_name:       "{{ index .OutputFields \"user.name\" }}"

  # Output to stdout as well — visible in `kubectl logs` for debugging
  stdout:
    enabled: true
    minimumpriority: "debug"

resources:
  requests:
    cpu: "50m"
    memory: "64Mi"
  limits:
    cpu: "200m"
    memory: "128Mi"
```

The `customfields` and `templatedfields` blocks are where the enrichment happens. Every alert that reaches Splunk will carry the pod name, namespace, image repository, image tag, and image digest as discrete indexed fields — not buried inside a message string you'd have to regex out at search time.

---

## Step 3 — Create the HEC Token Secret

Never put the HEC token in the values file or in source control. Create a Kubernetes secret:

```bash
ssh k8s-cp01 "
  sudo /var/lib/rancher/rke2/bin/kubectl \
    --kubeconfig /etc/rancher/rke2/rke2.yaml \
    create secret generic falcosidekick-splunk-token \
    --namespace falco \
    --from-literal=token='<YOUR-HEC-TOKEN-HERE>'
"
```

Then reference it in the values file by adding this under `config.splunk`:

```yaml
  splunk:
    # ... existing config ...
    # Token is mounted from secret — do not set 'token' field directly
    existingSecret: "falcosidekick-splunk-token"
    existingSecretKey: "token"
```

---

## Step 4 — Upgrade the Falco Helm Release

Redeploy Falco with falcosidekick enabled. The existing DaemonSet pods will roll:

```bash
ssh k8s-cp01 "
  sudo /usr/local/bin/helm upgrade falco falcosecurity/falco \
    --namespace falco \
    --kubeconfig /etc/rancher/rke2/rke2.yaml \
    --set driver.kind=ebpf \
    --set falcosidekick.enabled=true \
    --set falcoctl.artifact.install.enabled=false \
    --set falcoctl.artifact.follow.enabled=false \
    --set tty=true \
    --values /tmp/falcosidekick-values.yaml \
    --timeout 10m
"
```

Verify everything came up:

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco get pods"
```

Expected output:

```
NAME                                    READY   STATUS    RESTARTS   AGE
falco-cpl7k                             1/1     Running   0          3m
falco-n9qhf                             1/1     Running   0          3m
falco-phjbk                             1/1     Running   0          3m
falco-falcosidekick-7d9b8c4f6d-xkq9r   1/1     Running   0          3m
falco-falcosidekick-7d9b8c4f6d-z2p4t   1/1     Running   0          3m
```

---

## Step 5 — Trigger a Test Alert

Generate a deliberate Falco detection to confirm the pipeline is working end to end:

```bash
# Spawn a shell inside a running container — triggers "Terminal shell in container" rule
ssh k8s-cp01 "
  POD=\$(sudo /var/lib/rancher/rke2/bin/kubectl \
    --kubeconfig /etc/rancher/rke2/rke2.yaml \
    -n awx get pods -l app.kubernetes.io/name=awx \
    -o jsonpath='{.items[0].metadata.name}')

  sudo /var/lib/rancher/rke2/bin/kubectl \
    --kubeconfig /etc/rancher/rke2/rke2.yaml \
    exec -it \$POD -n awx -- /bin/bash -c 'id && exit' 2>&1 | head -5
"
```

Then check falcosidekick logs for the forwarded event:

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n falco logs deployment/falco-falcosidekick --tail=20 2>&1 | grep -i 'splunk\|sent\|error'"
```

And verify it landed in Splunk:

```spl
index=falco_alerts earliest=-5m
| table _time, rule, priority, k8s_namespace, k8s_pod_name, container_image, image_digest, proc_cmdline
```

---

## Step 6 — The Event Schema in Splunk

A fully enriched Falco alert in Splunk looks like this:

```json
{
  "_time": "2026-04-04T01:23:45.000Z",
  "index": "falco_alerts",
  "sourcetype": "falco",
  "host": "k8s-w01",

  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output": "Notice A shell was spawned in a container with an attached terminal (user=root k8s.ns=awx k8s.pod=awx-web-5c9d8f7b4-x2k9r container=awx-web shell=bash parent=runc cmdline=bash)",

  "k8s_pod_name": "awx-web-5c9d8f7b4-x2k9r",
  "k8s_namespace": "awx",
  "k8s_node_name": "k8s-w01",

  "container_image": "quay.io/ansible/awx",
  "image_tag": "24.6.1",
  "image_digest": "sha256:a3f8c2d1e4b7...",

  "proc_name": "bash",
  "proc_cmdline": "bash",
  "user_name": "root",

  "environment": "homelab-k8s",
  "cluster": "rke2-us-west-2",
  "compliance_framework": "CMMC_L2",
  "cmmc_si_3_14_2": "malicious_code_protection",
  "cmmc_si_3_14_6": "monitor_for_attacks",
  "cmmc_si_3_14_7": "identify_unauthorized_use"
}
```

The `image_digest` field is the one that matters most for forensics. An image tag like `awx:24.6.1` is mutable — someone can push a different image to the same tag. The SHA digest is immutable. If an alert fires and you need to determine whether the container was running a trusted build, the digest is what you correlate against your image build pipeline.

---

## Step 7 — Splunk Searches and Saved Alerts

### Baseline: All Falco Events by Priority and Rule

```spl
index=falco_alerts earliest=-24h
| stats count by priority, rule
| sort - count
```

### Container Escapes and Privilege Escalation

```spl
index=falco_alerts earliest=-24h
  (rule="*privilege*" OR rule="*escape*" OR rule="*sensitive*" OR priority=Critical OR priority=Alert)
| table _time, rule, priority, k8s_namespace, k8s_pod_name, user_name, proc_cmdline
| sort - _time
```

### Unexpected Shell Spawned in Production Namespace

```spl
index=falco_alerts earliest=-24h
  rule="Terminal shell in container"
  k8s_namespace!=falco
  k8s_namespace!=kube-system
| table _time, k8s_namespace, k8s_pod_name, container_image, image_digest, user_name, proc_cmdline
```

### Correlate with Auth Events: Same Host, Same Window

This is the query type that demonstrates real detection engineering — correlating a Falco runtime alert with a suspicious SSH login on the same node within the same time window:

```spl
| union
    [search index=falco_alerts earliest=-1h
     | eval event_source="falco", summary=rule
     | table _time, host, k8s_node_name, summary, event_source]
    [search index=linux_secure earliest=-1h "Failed password" OR "Accepted publickey"
     | rex field=_raw "for (?<ssh_user>\S+) from (?<src_ip>\S+)"
     | eval event_source="ssh", summary="SSH: ".ssh_user." from ".src_ip, k8s_node_name=host
     | table _time, host, k8s_node_name, summary, event_source]
| sort _time
| transaction k8s_node_name maxspan=10m keepeventsourceorder=true
| where eventcount > 1 AND mvcount(event_source) > 1
| table _time, k8s_node_name, eventcount, mvjoin(summary, " | ")
```

A Falco alert followed by an SSH auth event on the same node within 10 minutes is worth investigating. This query surfaces exactly that pattern.

### Save as Scheduled Alert

In Splunk: **Settings → Searches, Reports, and Alerts → New Alert**

| Field | Value |
|---|---|
| Search | The "Container Escapes" SPL above |
| Schedule | Every 15 minutes |
| Trigger condition | Number of results > 0 |
| Alert action | Log to index (initially) |
| Index | `falco_alerts` |
| Sourcetype | `falco:alert_fired` |

Start with log-to-index rather than email until you've confirmed the search has acceptable false-positive rate.

---

## Step 8 — Ansible Playbook for Repeatable Deployment

The HEC token creation and index setup should be idempotent and Ansible-managed, not run by hand. Add this to the Splunk hardening playbook:

```yaml
# ansible/roles/splunk_config/tasks/hec.yaml
---
- name: Enable Splunk HEC
  ansible.builtin.command: >
    /opt/splunk/bin/splunk http-event-collector enable
    -uri https://localhost:8089
    -auth {{ splunk_admin_user }}:{{ splunk_admin_password }}
    --run-as-root
  become: true
  register: hec_enable
  changed_when: "'already enabled' not in hec_enable.stdout"

- name: Create falco_alerts index
  ansible.builtin.command: >
    /opt/splunk/bin/splunk add index falco_alerts
    -maxTotalDataSizeMB 5120
    --run-as-root
  become: true
  register: index_create
  changed_when: "'already exists' not in index_create.stderr"
  failed_when: index_create.rc != 0 and 'already exists' not in index_create.stderr

- name: Create Falco HEC token
  ansible.builtin.command: >
    /opt/splunk/bin/splunk http-event-collector create falco-token
    -uri https://localhost:8089
    -auth {{ splunk_admin_user }}:{{ splunk_admin_password }}
    -index falco_alerts
    -sourcetype falco
    --run-as-root
  become: true
  register: hec_token
  changed_when: "'already exists' not in hec_token.stderr"
  failed_when: hec_token.rc != 0 and 'already exists' not in hec_token.stderr

- name: Store HEC token as Kubernetes secret
  kubernetes.core.k8s:
    kubeconfig: /etc/rancher/rke2/rke2.yaml
    state: present
    definition:
      apiVersion: v1
      kind: Secret
      metadata:
        name: falcosidekick-splunk-token
        namespace: falco
      stringData:
        token: "{{ hec_token.stdout | regex_search('token=([\\w-]+)', '\\1') | first }}"
  when: hec_token.changed
```

---

## CMMC Control Evidence

This integration directly demonstrates five NIST 800-171 Rev 2 controls:

| Control | Requirement | How This Integration Satisfies It |
|---|---|---|
| SI.L2-3.14.2 | Provide protection from malicious code | Falco DaemonSet continuously monitors all container syscalls for malicious behavior patterns |
| SI.L2-3.14.6 | Monitor systems to detect attacks | Real-time detection of privilege escalation, unexpected shells, sensitive file access across all 3 nodes |
| SI.L2-3.14.7 | Identify unauthorized use | Falco alerts correlated with auth events in Splunk identify anomalous user behavior across the cluster |
| AU.L2-3.3.1 | Create and retain audit logs | All Falco alerts persisted in `index=falco_alerts` with configurable retention |
| AU.L2-3.3.2 | Trace actions to individual users | `user_name`, `proc_cmdline`, `k8s_pod_name`, and `image_digest` fields provide attribution chain |

Evidence artifacts to capture for an assessment package:

- `kubectl get ds -n falco` — confirm DaemonSet running on all nodes
- `kubectl get deployment falco-falcosidekick -n falco` — confirm sidekick HA deployment
- Splunk search: `index=falco_alerts | stats count by rule, priority` — confirm events flowing
- Falcosidekick logs showing successful Splunk HEC POSTs
- Splunk `falco_alerts` index settings showing retention configuration

---

## Lessons Learned

**`modern_ebpf` on Rocky Linux 9.7 with RKE2.** The Falco Helm chart will warn you that `driver.kind=ebpf` (legacy eBPF) is deprecated and suggest `modern_ebpf`. On this cluster, `modern_ebpf` failed with a container plugin initialization error. Legacy eBPF works correctly. This is a known compatibility issue with certain kernel versions under RKE2 — the deprecation warning is safe to ignore until upstream resolves it.

**Falco detects its own deployment.** When Falco first comes up, it will fire alerts against the Splunk Universal Forwarder spawning subshells during startup. This is expected — it means Falco is working. Add a tuned rule to suppress known-good processes after you've confirmed detection is functioning:

```yaml
# Add to custom_rules.yaml
- rule: Suppress known Splunk UF startup shells
  condition: >
    spawned_process and
    container.name = "splunk-forwarder" and
    proc.name in (bash, sh) and
    proc.pname = splunkd
  output: "Suppressed: Splunk UF startup shell (pod=%container.name)"
  priority: DEBUG
  tags: [suppressed, splunk]
```

**Image digest availability.** The `container.image.digest` field is only populated if the container was pulled by digest (not by tag) or if the runtime has cached the manifest. On a fresh pull by tag, the field may be empty. This is a kubelet/containerd behavior, not a Falco limitation. Pull images by digest in production for consistent forensic attribution.

---

## Repository Layout

```
homelab-k8s/
├── k8s/
│   └── falco/
│       ├── falcosidekick-values.yaml     # Helm values (token ref only, no plaintext)
│       └── custom_rules.yaml             # Lab-specific rule overrides and suppressions
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
- [Falcosidekick Configuration Reference](https://github.com/falcosecurity/falcosidekick#configuration)
- [Falcosidekick Helm Chart Values](https://github.com/falcosecurity/charts/tree/master/charts/falcosidekick)
- [Splunk HEC Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [Falco Rules Reference](https://falco.org/docs/reference/rules/)
- [NIST SP 800-171 Rev 2 — SI Family](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
