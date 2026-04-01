# Python Security Automation Suite

A collection of Python security automation tools built for CMMC Level 2 / NIST 800-171 compliance environments. All tools use Python standard library only — no external dependencies.

**Author:** Jason A. Slocomb  
**Python:** 3.9+  
**Dependencies:** None (stdlib only)

---

## Tools

### `aide_to_splunk.py` — AIDE File Integrity → Splunk

Parses AIDE (Advanced Intrusion Detection Environment) report output and ships structured events to a Splunk HTTP Event Collector (HEC) endpoint.

**NIST 800-171 controls:** SI-3.14.7, AU-3.3.1, CM-3.4.1, CM-3.4.3

**Key features:**
- Parses all AIDE change types: added, removed, changed
- Assigns severity (critical/high/medium/low) based on path sensitivity
- Maps each finding to specific NIST 800-171 control identifiers
- Generates one summary event + one event per file change
- Sends to Splunk HEC in configurable batch sizes
- Zero external dependencies — stdlib urllib only
- Supports reading from stdin (pipe directly from AIDE)

**Quick start:**
```bash
# Dry run — parse and print JSON
python3 aide_to_splunk.py --report /var/log/aide/aide.log --dry-run

# Send to Splunk
python3 aide_to_splunk.py \
    --report /var/log/aide/aide.log \
    --hec-url https://splunk.lab.internal:8088 \
    --hec-token <token>

# Pipe directly from AIDE
aide --check 2>&1 | \
    SPLUNK_HEC_URL=https://splunk.lab.internal:8088 \
    SPLUNK_HEC_TOKEN=<token> \
    python3 aide_to_splunk.py --report -
```

**Cron integration (recommended):**
```bash
# /etc/cron.d/aide-to-splunk
0 4 * * * root aide --check 2>&1 | \
    SPLUNK_HEC_URL=https://splunk.lab.internal:8088 \
    SPLUNK_HEC_TOKEN=<token> \
    python3 /usr/local/bin/aide_to_splunk.py --report - --no-ssl-verify
```

**Splunk sourcetype:** `aide:report`  
**Splunk index:** `linux_audit` (configurable)

**Event fields:**
| Field | Description |
|-------|-------------|
| `event_type` | `aide_run_summary` or `aide_file_change` |
| `path` | Filesystem path |
| `change_type` | `added`, `removed`, or `changed` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `attributes_changed` | List of changed attributes (permissions, checksum, etc.) |
| `nist_controls` | NIST 800-171 control identifiers |
| `requires_review` | `true` for critical/high severity findings |

---

### `freeipa_account_auditor.py` — FreeIPA Stale Account Detection

Connects to FreeIPA via its JSON-RPC API, audits all user accounts for stale or risky conditions, and generates reports in JSON, CSV, and HTML formats.

**NIST 800-171 controls:** AC-3.1.1, AC-3.1.2, IA-3.5.4, IA-3.5.7, AC-3.1.14

**Key features:**
- Detects 10 risk conditions: never logged in, inactive, locked, expired password/principal, stale password, no groups, no email, privileged+inactive, high failed logins
- Severity rating per account: critical, high, medium, low, clean
- Produces JSON, CSV, and self-contained HTML reports
- Built-in dry-run mode with synthetic test data (no IPA connection needed)
- Configurable thresholds for all time-based checks
- NIST 800-171 control mapping per finding type

**Quick start:**
```bash
# Dry run with synthetic data (no IPA needed)
python3 freeipa_account_auditor.py --dry-run

# Live audit
python3 freeipa_account_auditor.py \
    --server ipa01.lab.internal \
    --binduser admin \
    --no-ssl-verify

# Full report output
IPA_PASSWORD=<password> python3 freeipa_account_auditor.py \
    --server ipa01.lab.internal \
    --binduser admin \
    --inactive-days 60 \
    --output-json /var/log/ipa_audit.json \
    --output-csv  /var/log/ipa_audit.csv \
    --output-html /var/log/ipa_audit.html \
    --no-ssl-verify
```

**Risk conditions detected:**

| Condition | Severity | NIST Controls |
|-----------|----------|---------------|
| Privileged account inactive/never logged in | Critical | AC-3.1.1, AC-3.1.2 |
| Kerberos principal expired | Critical | AC-3.1.1, IA-3.5.4 |
| Account locked | High | AC-3.1.1, IA-3.5.4 |
| Password expired | High | IA-3.5.7, IA-3.5.4 |
| Never logged in (30+ days) | High | AC-3.1.1, IA-3.5.4 |
| Inactive (90+ days) | High | AC-3.1.2, IA-3.5.4 |
| Stale password (no policy) | Medium | IA-3.5.7 |
| High failed login count | Medium | AC-3.1.1 |
| No group memberships | Low | AC-3.1.1, IA-3.5.4 |
| No email address | Low | IA-3.5.4 |

**Exit codes:**
- `0` — No critical or high findings
- `1` — High findings present
- `2` — Critical findings present (useful for alerting)

---

### `k8s_secret_auditor.py` — Kubernetes Secret Access Anomaly Detector

Parses Kubernetes API server audit logs and flags anomalous secret access patterns. Detects credential harvesting, privilege escalation, lateral movement, and exfiltration patterns using behavioral analysis across the event stream.

**NIST 800-171 controls:** AC-3.1.1, AC-3.1.3, SI-3.14.6, SI-3.14.7, SC-3.13.8, CM-3.4.3, IA-3.5.1, AU-3.3.1

**Key features:**
- 15 detection rules covering burst access, enumeration, impersonation, unusual hours, exec-after-secret, and more
- Streaming event processing — handles large audit logs without loading everything into memory
- Per-actor behavioral state tracking with configurable thresholds
- Built-in synthetic test data generator for offline testing
- HTML, JSON, and CSV report output
- Zero external dependencies — stdlib only

**Quick start:**
```bash
# Dry run with built-in synthetic test data
python3 k8s_secret_auditor.py --dry-run

# Analyze a real audit log
python3 k8s_secret_auditor.py --log /var/log/kubernetes/audit.log

# Generate test log then analyze it
python3 k8s_secret_auditor.py --generate-test-log /tmp/test_audit.log
python3 k8s_secret_auditor.py --log /tmp/test_audit.log --output-html /tmp/report.html

# Pipe from kubectl
kubectl logs -n kube-system kube-apiserver-node01 | \
    python3 k8s_secret_auditor.py --log -
```

**Detection rules:**

| Rule | Severity | Description |
|------|----------|-------------|
| EXEC_AFTER_SECRET | Critical | Pod exec within 5m of secret read (lateral movement) |
| BURST_ACCESS | Critical/High | N+ secret reads in sliding time window |
| IMPERSONATION | Critical | Impersonation headers on secret access |
| FORBIDDEN_PROBE | High | Repeated 403/401 on secrets (permission probing) |
| SENSITIVE_NAME | High | Access to high-value secret names (aws-creds, kubeconfig) |
| SECRET_DELETED | High | Secret deletion (post-exfil cleanup) |
| SECRET_MODIFIED | High | Secret patch/update (credential manipulation) |
| MASS_LIST | High | Namespace or cluster-wide secret listing |
| WATCH_SECRETS | High | Persistent watch on secrets resource |
| FORBIDDEN_RATE | High | High ratio of forbidden responses |
| DENIED_THEN_ALLOW | High | Denied then later allowed (privilege escalation) |
| NODE_OVERSTEP | High | Kubelet reading excessive distinct secrets |
| LIST_ENUMERATE | Medium | List + targeted get pattern (enumeration) |
| UNUSUAL_HOUR | Medium | Human user access outside business hours |
| CROSS_NAMESPACE | Medium | Actor reading from atypical namespace |

**Exit codes:**
- `0` — No critical or high findings
- `1` — High findings present
- `2` — Critical findings present

---

### `netbox-populate.sh` — NetBox API Population

Populates a NetBox CMDB instance with lab infrastructure devices and IP addresses via the NetBox REST API. Used to seed the CMDB as the source of truth for AWX dynamic inventory.

```bash
# Set token and run
TOKEN=<netbox-api-token> ./netbox-populate.sh
```

---

### `verify-cluster-health.sh` — RKE2 Cluster Health Check

Quick health check script for the RKE2 cluster. Verifies all nodes are Ready, all system pods are Running, and key services are reachable.

```bash
./verify-cluster-health.sh
```

---

## Architecture — How the tools fit together

```
AIDE (daily cron)
    │
    └── aide_to_splunk.py ──► Splunk HEC ──► linux_audit index
                                              ├── Alerts on critical/high findings
                                              └── Evidence for CM-3.4.1, SI-3.14.7

FreeIPA (weekly cron recommended)
    │
    └── freeipa_account_auditor.py ──► HTML report ──► Security review
                                    └► JSON/CSV    ──► Ticketing system
                                                       Evidence for AC-3.1.1, IA-3.5.4

Kubernetes (on-demand)
    │
    └── k8s_secret_auditor.py ──► JSON report ──► Evidence for IA-3.5.1, CM-3.4.1

NetBox CMDB
    │
    └── netbox-populate.sh ──► Seeds devices ──► AWX dynamic inventory
```

---

## Testing

Unit tests are in the `tests/` directory:

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test file
python3 -m pytest tests/test_aide_to_splunk.py -v
python3 -m pytest tests/test_freeipa_account_auditor.py -v
```

---

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `SPLUNK_HEC_URL` | aide_to_splunk | Splunk HEC base URL |
| `SPLUNK_HEC_TOKEN` | aide_to_splunk | HEC authentication token |
| `SPLUNK_INDEX` | aide_to_splunk | Target index (default: os_logs) |
| `SPLUNK_SOURCETYPE` | aide_to_splunk | Sourcetype (default: aide:report) |
| `AIDE_HOSTNAME` | aide_to_splunk | Override reported hostname |
| `IPA_SERVER` | freeipa_account_auditor | FreeIPA server hostname |
| `IPA_BINDUSER` | freeipa_account_auditor | Bind username |
| `IPA_PASSWORD` | freeipa_account_auditor | Bind password |

---

## Security Notes

- Never hardcode credentials. Use environment variables or a secrets manager.
- The `--no-ssl-verify` flag disables SSL certificate verification. Only use in lab environments with self-signed certificates.
- The FreeIPA auditor requires read access to all user attributes. Use a dedicated read-only service account in production.
- AIDE HEC tokens should be scoped to the `linux_audit` index only.
