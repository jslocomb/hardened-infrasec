# AWX + GitLab GitOps Workflow

## Overview

GitLab CE is the single source of truth for all Ansible playbooks. AWX pulls from GitLab and executes against inventory targets. Changes to playbooks go through GitLab's merge request process, and AWX auto-syncs on push via webhooks.

## Setup Steps

### 1. Create GitLab Project

In GitLab at `https://gitlab.lab.internal`:
- Create group: `infra`
- Create project: `infra/ansible-playbooks`
- Push the contents of `ansible/` to this repo

### 2. Create GitLab Deploy Key

```bash
# Generate deploy key
ssh-keygen -t ed25519 -f ~/.ssh/awx_deploy_key -C "awx@lab.internal" -N ""

# Add public key to GitLab:
# Settings > Repository > Deploy Keys > Add deploy key
# Title: awx-readonly
# Key: (contents of awx_deploy_key.pub)
# Access: Read-only
```

### 3. Create AWX SCM Credential

In AWX at `https://awx.lab.internal`:
- Credentials → Add
- Type: Source Control
- Name: `gitlab-scm`
- Username: `git`
- SSH Private Key: (paste contents of `awx_deploy_key`)

### 4. Create AWX Project

- Projects → Add
- Name: `Homelab Playbooks`
- SCM Type: Git
- SCM URL: `git@gitlab.lab.internal:infra/ansible-playbooks.git`
- SCM Credential: `gitlab-scm`
- SCM Branch: `main`
- ✅ Update Revision on Launch
- ✅ Allow Branch Override

### 5. Configure GitLab → AWX Webhook

Get the AWX webhook URL:
- AWX → Projects → Homelab Playbooks → Edit → Webhooks tab
- Copy the webhook URL and secret token

In GitLab:
- Project → Settings → Webhooks → Add webhook
- URL: `https://awx.lab.internal/api/v2/projects/<id>/update/`
- Secret token: (from AWX)
- Trigger: Push events

### 6. Create AWX Job Template

- Templates → Add → Job Template
- Name: `Deploy Infrastructure`
- Inventory: (your lab inventory)
- Project: `Homelab Playbooks`
- Playbook: `playbooks/site.yml`
- Credentials: (Machine credential for SSH access)
- Variables: (inject vault vars here)

## Workflow

```
Developer commits playbook change
        │
        ▼
GitLab CE (merge request review)
        │
        ▼ (merge to main)
GitLab webhook fires
        │
        ▼
AWX Project sync (pulls latest playbook from GitLab)
        │
        ▼
AWX Job Template launches
        │
        ▼
Ansible executes against Rocky Linux 9 targets
        │
        ▼
Results logged in AWX activity stream
        │
        ▼
Splunk collects AWX logs via Universal Forwarder
```

## RBAC in AWX

Map FreeIPA groups to AWX roles:

| FreeIPA Group | AWX Role |
|---|---|
| `awx-admins` | System Administrator |
| `awx-users` | Normal User |

Use AWX Team Mapping to automatically assign roles based on LDAP group membership.
