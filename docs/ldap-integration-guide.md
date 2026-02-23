# LDAP Integration Guide

All applications authenticate users through FreeIPA's LDAP interface. This guide documents the configuration pattern for each service.

## Common Pattern

Every application uses a dedicated read-only service account (bind DN) to query the directory. Users are organized into application-specific groups. The bind account must:

- Have `userPassword` set
- Have read access to `cn=users` and `cn=groups`
- NOT be a member of any application group (it's a technical account, not a user)

## FreeIPA Base DN

```
dc=lab,dc=internal
Users:  cn=users,cn=accounts,dc=lab,dc=internal
Groups: cn=groups,cn=accounts,dc=lab,dc=internal
```

## AWX

**Settings path:** AWX UI → Settings → Authentication → LDAP

| Setting | Value |
|---|---|
| LDAP SERVER URI | `ldaps://ipa01.lab.internal:636` |
| LDAP BIND DN | `uid=awx-bind,cn=users,cn=accounts,dc=lab,dc=internal` |
| LDAP USER SEARCH | `cn=users,cn=accounts,dc=lab,dc=internal` |
| LDAP USER DN TEMPLATE | `uid=%(user)s,cn=users,cn=accounts,dc=lab,dc=internal` |
| LDAP REQUIRE GROUP | `cn=awx-users,cn=groups,cn=accounts,dc=lab,dc=internal` |
| Superuser group | `cn=awx-admins,cn=groups,cn=accounts,dc=lab,dc=internal` |

## GitLab CE

Configured in `kubernetes/gitlab/values.yaml` under `global.ldap`. See that file for the full config.

Key group: `cn=gitlab-users,cn=groups,cn=accounts,dc=lab,dc=internal`

## Grafana

Configured via `ldap.toml` injected as a secret (see `kubernetes/prometheus/values.yaml`).

| Group | Grafana Role |
|---|---|
| `cn=grafana-admins` | Admin |
| All others | Viewer |

## Zabbix

Configure in Zabbix UI: Administration → Authentication → LDAP Settings.
LDAP auth is separate from Zabbix's internal DB auth — enable LDAP as the default.

## NetBox

Uses `django-auth-ldap`. Config injected as `ldap_config.py` secret (see `kubernetes/netbox/ldap-config.yaml` for the full Python config).

| Group | NetBox Permission |
|---|---|
| `cn=netbox-admins` | `is_superuser = True` |
| `cn=netbox-users` | `is_active = True` |

## Troubleshooting LDAP

```bash
# Test LDAP bind from a cluster node
ldapsearch -x -H ldaps://ipa01.lab.internal:636 \
  -D "uid=awx-bind,cn=users,cn=accounts,dc=lab,dc=internal" \
  -w "YOUR_BIND_PASSWORD" \
  -b "cn=users,cn=accounts,dc=lab,dc=internal" \
  "(uid=testuser)"

# Verify group membership
ldapsearch -x -H ldaps://ipa01.lab.internal:636 \
  -D "uid=awx-bind,cn=users,cn=accounts,dc=lab,dc=internal" \
  -w "YOUR_BIND_PASSWORD" \
  -b "cn=groups,cn=accounts,dc=lab,dc=internal" \
  "(cn=awx-users)"
```
