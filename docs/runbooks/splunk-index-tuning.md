# Runbook: Splunk Index Tuning

## Index Layout

| Index | Data Source | Retention |
|---|---|---|
| `os_logs` | /var/log/messages, /var/log/secure | 90 days |
| `k8s_audit` | K8s API audit log | 90 days |
| `main` | Default catchall | 30 days |

## Create Indexes via Splunk CLI

```bash
# SSH into Splunk pod
kubectl exec -it splunk-standalone-standalone-0 -n logging -- /bin/bash

# Create index
/opt/splunk/bin/splunk add index os_logs -maxTotalDataSizeMB 5000
/opt/splunk/bin/splunk add index k8s_audit -maxTotalDataSizeMB 10000
```

## Key Searches for CMMC Evidence

```spl
# Failed SSH logins (NIST 3.14.6)
index=os_logs sourcetype=linux_secure "Failed password"
| stats count by host, src_ip, user
| sort -count

# Privilege escalation (NIST 3.1.6)
index=os_logs sourcetype=linux_secure "sudo"
| stats count by host, user, command

# K8s API changes (NIST 3.4.3)
index=k8s_audit verb IN (create,update,delete,patch)
| stats count by user.username, objectRef.resource, verb
```

## Storage Monitoring

Alert when index storage exceeds 80%:
- Splunk UI → Settings → Monitoring Console → Indexing → Index Detail
