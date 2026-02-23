# Deployment Order

Complete step-by-step deployment sequence. Do not skip steps — each has dependencies on the previous.

## Phase 1: Infrastructure

### Step 1 — Proxmox Template
```bash
# On Proxmox host — create Rocky Linux 9 cloud-init template
# See docs/vm-specifications.md for full commands
```

### Step 2 — Provision VMs with Terraform
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

### Step 3 — Base OS Setup
```bash
cd ansible
ansible-playbook playbooks/provision_vms.yml
```

### Step 4 — CIS Hardening
```bash
ansible-playbook playbooks/harden_os.yml
```

## Phase 2: Identity

### Step 5 — Install FreeIPA (manual)
```bash
# SSH to ipa01
ssh ansible@192.168.10.5
sudo bash /home/ansible/freeipa/install-freeipa.sh

# After install — create groups and service accounts
kinit admin
ldapmodify -x -H ldap://localhost -D "cn=Directory Manager" -W \
  -f /home/ansible/freeipa/ldap-schema/service-accounts.ldif
ldapmodify -x -H ldap://localhost -D "cn=Directory Manager" -W \
  -f /home/ansible/freeipa/ldap-schema/awx-groups.ldif
ldapmodify -x -H ldap://localhost -D "cn=Directory Manager" -W \
  -f /home/ansible/freeipa/ldap-schema/gitlab-groups.ldif
ldapmodify -x -H ldap://localhost -D "cn=Directory Manager" -W \
  -f /home/ansible/freeipa/ldap-schema/netbox-groups.ldif

# Add DNS records (see freeipa/dns/lab-zone-records.txt)
```

## Phase 3: Kubernetes

### Step 6 — Install RKE2 Control Plane
```bash
ansible-playbook playbooks/install_rke2_server.yml
```

### Step 7 — Join Worker Nodes
```bash
ansible-playbook playbooks/install_rke2_agent.yml
```

### Step 8 — Verify Cluster
```bash
bash scripts/verify-cluster-health.sh
```

## Phase 4: Cluster Services

### Step 9 — MetalLB
```bash
ansible-playbook playbooks/deploy_metallb.yml
```

### Step 10 — ingress-nginx
```bash
ansible-playbook playbooks/deploy_ingress.yml
# Note the LoadBalancer IP assigned — update FreeIPA DNS
```

### Step 11 — cert-manager
```bash
ansible-playbook playbooks/deploy_certmanager.yml
```

### Step 12 — Longhorn Storage
```bash
ansible-playbook playbooks/deploy_longhorn.yml
# Verify: kubectl get storageclass
```

## Phase 5: Applications

### Step 13 — GitLab CE
```bash
ansible-playbook playbooks/deploy_gitlab.yml
# Access: https://gitlab.lab.internal
# Initial root password: kubectl get secret gitlab-gitlab-initial-root-password -n devops
```

### Step 14 — AWX
```bash
ansible-playbook playbooks/deploy_awx.yml
# Access: https://awx.lab.internal
# Configure GitLab SCM credential and project after deploy
```

### Step 15 — Prometheus + Grafana
```bash
ansible-playbook playbooks/deploy_monitoring.yml
# Access: https://grafana.lab.internal
```

### Step 16 — Zabbix
```bash
ansible-playbook playbooks/deploy_zabbix.yml
# Access: https://zabbix.lab.internal
```

### Step 17 — NetBox
```bash
ansible-playbook playbooks/deploy_netbox.yml
# Access: https://netbox.lab.internal
```

### Step 18 — Splunk
```bash
ansible-playbook playbooks/deploy_splunk.yml
# Access: https://splunk.lab.internal
# Splunk takes 10-15 min to fully initialize
```

## Verification
```bash
bash scripts/verify-cluster-health.sh
```
