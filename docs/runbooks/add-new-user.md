# Runbook: Add New User

## Overview
All users are provisioned in FreeIPA. Group membership controls access to each application.

## Steps

### 1. Create user in FreeIPA
```bash
kinit admin
ipa user-add jsmith \
  --first="John" \
  --last="Smith" \
  --email="jsmith@lab.internal" \
  --password
```

### 2. Add to appropriate groups
```bash
# Grant AWX access
ipa group-add-member awx-users --users=jsmith

# Grant GitLab access
ipa group-add-member gitlab-users --users=jsmith

# Grant Grafana access (read-only by default)
ipa group-add-member grafana-users --users=jsmith

# Grant NetBox access
ipa group-add-member netbox-users --users=jsmith
```

### 3. Verify login

Have the user log into each application to verify LDAP auth is working. First login may require the user to change their password via the FreeIPA web UI (`https://ipa01.lab.internal/ipa/ui`).

### 4. Document in NetBox

Add the user's workstation/laptop to NetBox CMDB for inventory tracking.
