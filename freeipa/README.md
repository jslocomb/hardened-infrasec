# FreeIPA Setup Guide

FreeIPA runs as a standalone VM (`ipa01.lab.internal`, `10.0.10.113`) outside the K8s cluster.
It provides LDAP, Kerberos, DNS, and CA services for the entire homelab.

## Initial Install

```bash
# On ipa01 (Rocky Linux 9)
dnf install -y freeipa-server freeipa-server-dns
bash /home/ansible/freeipa/install-freeipa.sh
```

## Post-Install Checklist

1. Verify DNS zone `lab.internal` is created
2. Add A records for all K8s node FQDNs
3. Create service accounts (see `ldap-schema/service-accounts.ldif`)
4. Create groups for each application (see `ldap-schema/awx-groups.ldif`, etc.)
5. Set HBAC rules (see `hbac/`)
6. Retrieve CA cert: `cat /etc/ipa/ca.crt` — this is needed by cert-manager

## Service Accounts Summary

| Account | Application | Permissions |
|---|---|---|
| `awx-bind` | AWX | LDAP read-only |
| `gitlab-bind` | GitLab CE | LDAP read-only |
| `grafana-bind` | Grafana | LDAP read-only |
| `netbox-bind` | NetBox | LDAP read-only |

## Application Groups

| Group | Members |
|---|---|
| `awx-users` | Lab users who can log into AWX |
| `awx-admins` | AWX superusers |
| `gitlab-users` | GitLab CE users |
| `grafana-admins` | Grafana admin users |
| `netbox-users` | NetBox read/write |
| `netbox-admins` | NetBox admin |
