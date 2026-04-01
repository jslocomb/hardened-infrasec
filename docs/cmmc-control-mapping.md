# CMMC Level 2 / NIST 800-171 Control Mapping

This document maps homelab services to NIST 800-171 practice domains.
Useful for demonstrating CMMC-awareness in interviews and portfolio reviews.

## Domain Mapping

### AC — Access Control (3.1.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.1.1 | Limit system access to authorized users | FreeIPA LDAP authentication on all services |
| 3.1.2 | Limit access to types of transactions | AWX RBAC, GitLab project permissions, K8s RBAC |
| 3.1.3 | Control CUI flow | Namespace isolation (auth/devops/monitoring/netops/logging) |
| 3.1.5 | Employ least privilege | FreeIPA HBAC, read-only bind accounts, K8s NetworkPolicy |
| 3.1.6 | Use non-privileged accounts for non-privileged activities | Separate admin vs. user accounts in FreeIPA |
| 3.1.12 | Monitor remote access sessions | Splunk SSH login monitoring, auditd |
| 3.1.13 | Employ cryptographic mechanisms | SSH key-only auth, TLS everywhere (FreeIPA CA) |

### AU — Audit & Accountability (3.3.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.3.1 | Create system audit logs | auditd on all nodes, K8s audit log enabled on API server |
| 3.3.2 | Ensure audit logs cannot be deleted | Splunk indexes, rsyslog to centralized SIEM |
| 3.3.4 | Alert on audit log failures | Splunk + Prometheus Alertmanager |
| 3.3.5 | Correlate audit logs | Splunk correlation searches across OS, K8s, and application logs |

### CM — Configuration Management (3.4.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.4.1 | Establish baselines | Ansible CIS hardening role, RKE2 CIS profile |
| 3.4.2 | Establish settings for high-security | CIS Rocky Linux 9 Benchmark (sysctl, SSH, auditd) |
| 3.4.3 | Track changes to systems | GitLab version control, AWX execution history |
| 3.4.4 | Analyze security impact before changes | GitLab merge request review process |
| 3.4.6 | Employ principle of least functionality | Disabled unnecessary services (Section 2 CIS hardening) |

### IA — Identification & Authentication (3.5.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.5.1 | Identify all users | FreeIPA centralized identity |
| 3.5.2 | Authenticate users before access | LDAP authentication required for all services |
| 3.5.3 | Employ multifactor authentication | FreeIPA OTP (TOTP) support — can be enabled per user |
| 3.5.4 | Employ replay-resistant auth | Kerberos via FreeIPA |
| 3.5.7 | Enforce minimum password complexity | FreeIPA password policy (14 char min, complexity) |

### SC — System & Communications Protection (3.13.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.13.1 | Monitor, control, and protect communications | firewalld, ingress-nginx, TLS enforcement |
| 3.13.2 | Employ architectural designs | Network segmentation via namespaces + NetworkPolicy |
| 3.13.8 | Implement cryptographic mechanisms | TLS via cert-manager + FreeIPA CA |
| 3.13.10 | Establish and manage cryptographic keys | FreeIPA CA, cert-manager key rotation |

### SI — System & Info Integrity (3.14.x)

| Practice | Control | Implementation |
|---|---|---|
| 3.14.1 | Identify and manage vulnerabilities | Falco runtime detection, dnf-automatic |
| 3.14.2 | Provide protection from malicious code | CIS-hardened OS baseline, SELinux enforcing |
| 3.14.3 | Monitor system security alerts | Splunk SIEM correlation, Prometheus alerting |
| 3.14.6 | Monitor systems to detect attacks | Splunk detection rules (failed SSH, privilege escalation) |
| 3.14.7 | Identify unauthorized use | AIDE file integrity monitoring, auditd rules |
