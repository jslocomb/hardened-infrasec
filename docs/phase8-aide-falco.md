# Phase 8 — AIDE + Falco

## AIDE (Advanced Intrusion Detection Environment)
- Version: 0.16-105.el9
- Installed on: ipa01, k8s-cp01, k8s-w01, k8s-w02
- Baseline initialized: 2026-03-28
- Daily check: 02:00 UTC via /etc/cron.d/aide-check
- Logs: /var/log/aide/aide-check.log → Splunk index=linux_audit
- CMMC: CM-3.4.1, SI-3.14.7

## Falco
- Version: 0.43.0
- Driver: eBPF
- Deployed: DaemonSet in falco namespace (RKE2 cluster)
- Nodes monitored: k8s-cp01, k8s-w01, k8s-w02
- Rules: /etc/falco/falco_rules.yaml (default ruleset)
- CMMC: SI-3.14.6

## Sample Falco Detection
Falco detected Splunk spawning shell processes from untrusted binary
immediately after deployment — demonstrating active runtime monitoring.
