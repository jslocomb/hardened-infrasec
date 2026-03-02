# Homelab K8s Infrastructure — Build Checklist

**11 Phases · 117 Steps · Start to Finish**

> Proxmox · Rocky Linux 9 · RKE2 · FreeIPA · GitLab CE · AWX · Splunk · CMMC Level 2
>
> Work through phases in order — each phase depends on the previous. Phase 11 items are portfolio enhancements and can be tackled after core deployment is stable.

---

## Phase 0 — Planning & Design

### Architecture Decisions

- [ ] **0.1** — Define VM layout, vCPU, RAM, and disk allocations for all 5 VMs `→ See VM matrix in README`
- [ ] **0.2** — Choose networking: vmbr0 (mgmt) + vmbr1 (lab), static IPs 192.168.10.x `→ Subnet: .0/24`
- [ ] **0.3** — Select RKE2 as Kubernetes distribution (CIS profile, air-gap friendly) `→ vs k3s / kubeadm`
- [ ] **0.4** — Choose FreeIPA as central identity provider (LDAP + Kerberos + DNS + CA) `→ dc=lab,dc=internal`
- [ ] **0.5** — Confirm storage: Longhorn distributed block storage (2 replicas across workers) `→ iSCSI :9500-9502`
- [ ] **0.6** — Confirm ingress: MetalLB L2 + ingress-nginx, VIP 192.168.10.200 `→ Pool: .200-.220`
- [ ] **0.7** — Map NIST 800-171 / CMMC Level 2 controls to stack components `→ docs/cmmc-mapping.md`
- [ ] **0.8** — Document deployment order (dependency chain for all services) `→ docs/deployment-order.md`
- [ ] **0.9** — Create Git repository structure and directory layout `→ homelab-k8s-files.zip`

---

## Phase 1 — Proxmox Host Setup

### Host Configuration

- [ ] **1.1** — Install Proxmox VE 8.x on bare metal host `→ ISO install`
- [ ] **1.2** — Update Proxmox to latest packages `→ apt update && apt dist-upgrade`
- [ ] **1.3** — Create vmbr0 bridge (management, NAT to internet, 192.168.1.0/24) `→ /etc/network/interfaces`
- [ ] **1.4** — Create vmbr1 bridge (lab network, no external routing, 192.168.10.0/24) `→ /etc/network/interfaces`
- [ ] **1.5** — Enable IP forwarding on Proxmox host `→ sysctl net.ipv4.ip_forward=1`
- [ ] **1.6** — Configure iptables NAT masquerade on vmbr0 for lab internet access `→ postup script`
- [ ] **1.7** — Download Rocky Linux 9 Generic Cloud qcow2 image `→ wget alma/rocky mirror`
- [ ] **1.8** — Create Proxmox VM 9000 as Rocky Linux 9 template `→ qm create 9000`
- [ ] **1.9** — Import disk image to local-lvm storage `→ qm importdisk 9000 ...`
- [ ] **1.10** — Configure template: q35 machine, OVMF UEFI, VirtIO SCSI, cloud-init `→ qm set 9000 ...`
- [ ] **1.11** — Add cloud-init drive (ide2) `→ qm set 9000 --ide2 ...`
- [ ] **1.12** — Convert VM to template `→ qm template 9000`

### Terraform Provisioning

- [ ] **1.13** — Write `terraform/main.tf` with Proxmox telmate provider configuration `→ provider = bpg/proxmox`
- [ ] **1.14** — Write `terraform/variables.tf` for all configurable inputs `→ vm_count, cpu, mem...`
- [ ] **1.15** — Write `terraform/modules/proxmox-vm/main.tf` reusable VM clone module `→ clone = 9000`
- [ ] **1.16** — Write `terraform/vm_configs.tf` with per-VM specs (ipa01, cp01, w01-w03) `→ 5 VM definitions`
- [ ] **1.17** — Write `terraform/terraform.tfvars` with secrets (gitignored) `→ proxmox_password`
- [ ] **1.18** — `terraform init` — download provider plugins
- [ ] **1.19** — `terraform plan` — review all 5 VM creation actions
- [ ] **1.20** — `terraform apply` — provision all 5 VMs
- [ ] **1.21** — Verify all 5 VMs appear in Proxmox UI with correct specs and IPs `→ Proxmox web console`

---

## Phase 2 — Base OS Configuration

### Ansible Inventory & Connectivity

- [ ] **2.1** — Write `ansible/inventory/hosts.yml` with all 5 VMs grouped by role `→ groups: ipa, k8s_cp, k8s_workers`
- [ ] **2.2** — Write `ansible/inventory/group_vars/all.yml` with common variables `→ domain, DNS server, NTP`
- [ ] **2.3** — Write `ansible/inventory/group_vars/k8s_workers.yml` with worker vars `→ node labels, disk paths`
- [ ] **2.4** — Test SSH connectivity to all VMs with ansible ping `→ ansible all -m ping`

### Provision VMs Playbook

- [ ] **2.5** — Write `roles/common/tasks/main.yml`: hostname, /etc/hosts, base packages
- [ ] **2.6** — Write `roles/common/tasks/main.yml`: configure chrony NTP `→ chrony.conf template`
- [ ] **2.7** — Write `roles/common/tasks/main.yml`: point resolv.conf to ipa01 DNS `→ 192.168.10.5`
- [ ] **2.8** — Write `ansible/playbooks/provision_vms.yml` orchestrating common role `→ hosts: all`
- [ ] **2.9** — Run provision_vms.yml against all VMs `→ ansible-playbook provision_vms.yml`
- [ ] **2.10** — Verify hostnames set and NTP synchronized on all nodes `→ timedatectl status`

### CIS Hardening Playbook

- [ ] **2.11** — Write `roles/cis_hardening/tasks` — disable unused filesystems `→ cramfs, usb-storage...`
- [ ] **2.12** — Write `roles/cis_hardening/tasks` — sysctl hardening params `→ syncookies, rp_filter...`
- [ ] **2.13** — Write `roles/cis_hardening/tasks` — SSH hardening config `→ PermitRootLogin no, keys only`
- [ ] **2.14** — Write `roles/cis_hardening/tasks` — auditd rules (NIST 800-171 aligned) `→ audit.rules file`
- [ ] **2.15** — Write `roles/cis_hardening/tasks` — AIDE initialization `→ aide --init`
- [ ] **2.16** — Write `roles/cis_hardening/tasks` — disable unnecessary services `→ cups, avahi, postfix`
- [ ] **2.17** — Write `roles/cis_hardening/tasks` — configure firewalld per-node rules `→ firewall-cmd --permanent`
- [ ] **2.18** — Write `ansible/playbooks/harden_os.yml` orchestrating cis_hardening role `→ hosts: all`
- [ ] **2.19** — Run harden_os.yml against all VMs `→ ansible-playbook harden_os.yml`
- [ ] **2.20** — Verify AIDE database created and no hardening failures `→ aide --check`

---

## Phase 3 — FreeIPA Identity & DNS

### FreeIPA Server Install

- [ ] **3.1** — Write `freeipa/install-freeipa.sh` with full ipa-server-install command `→ --setup-dns --no-forwarders`
- [ ] **3.2** — Configure FreeIPA realm: LAB.INTERNAL, domain: lab.internal `→ kerberos realm`
- [ ] **3.3** — Run install-freeipa.sh on ipa01 `→ bash install-freeipa.sh`
- [ ] **3.4** — Verify FreeIPA web UI accessible at https://ipa01.lab.internal `→ browser test`
- [ ] **3.5** — Verify kinit admin succeeds (Kerberos working) `→ kinit admin`

### DNS Records

- [ ] **3.6** — Write `freeipa/dns-records.sh` to add all A records `→ ipa dnsrecord-add`
- [ ] **3.7** — Add A record: k8s-cp01 → 192.168.10.10 `→ ipa dnsrecord-add lab.internal k8s-cp01`
- [ ] **3.8** — Add A records: k8s-w01/w02/w03 → .11/.12/.13 `→ 3x ipa dnsrecord-add`
- [ ] **3.9** — Add A records for all service ingress URLs (awx, gitlab, grafana...) `→ wildcard or per-service`
- [ ] **3.10** — Verify DNS resolution from all VMs for *.lab.internal `→ dig awx.lab.internal`

### LDAP Schema — Groups & Users

- [ ] **3.11** — Write `freeipa/ldap-groups.ldif` — create all application groups `→ awx-users, gitlab-users...`
- [ ] **3.12** — Create groups: awx-users, awx-admins, gitlab-users, gitlab-admins `→ ipa group-add`
- [ ] **3.13** — Create groups: grafana-admins, netbox-users, netbox-admins, zabbix-admins `→ ipa group-add`
- [ ] **3.14** — Create group: infra-admins (for SSH HBAC) `→ ipa group-add infra-admins`
- [ ] **3.15** — Write `freeipa/service-accounts.sh` — create all LDAP bind accounts `→ uid=awx-bind...`
- [ ] **3.16** — Create bind accounts: awx-bind, gitlab-bind, grafana-bind, netbox-bind, zabbix-bind `→ ipa user-add (no shell)`
- [ ] **3.17** — Create at least one admin user account, add to infra-admins and app groups `→ ipa user-add jsmith`

### HBAC Rules & Password Policy

- [ ] **3.18** — Write `freeipa/hbac-rules.sh` — disable allow_all, create scoped rules `→ ipa hbacrule-add`
- [ ] **3.19** — Disable default allow_all HBAC rule `→ ipa hbacrule-disable allow_all`
- [ ] **3.20** — Create k8s-ssh-access HBAC rule: infra-admins → k8s nodes → sshd `→ ipa hbacrule-add`
- [ ] **3.21** — Write `freeipa/password-policy.sh` — 14 char min, 4 class, history 12 `→ ipa pwpolicy-mod`
- [ ] **3.22** — Apply password policy to global and all app groups `→ ipa pwpolicy-mod`

### Certificate Authority

- [ ] **3.23** — Export FreeIPA CA certificate for use by cert-manager `→ ipa-cacert-manage list`
- [ ] **3.24** — Write `freeipa/ca-cert-secret.yaml` — K8s Secret with CA bundle `→ kubectl apply`
- [ ] **3.25** — Verify CA cert signs test certificate (openssl verify) `→ openssl verify -CAfile ipa-ca.crt`

---

## Phase 4 — RKE2 Kubernetes Cluster

### Control Plane

- [ ] **4.1** — Write `roles/rke2_server/templates/config.yaml.j2` with CIS profile settings `→ profile: cis-1.23`
- [ ] **4.2** — Include K8s audit policy file (NIST-aligned audit rules) `→ audit-policy.yaml`
- [ ] **4.3** — Write `ansible/playbooks/install_rke2_server.yml` for k8s-cp01 `→ hosts: k8s_cp`
- [ ] **4.4** — Deploy rke2 config, audit policy, and install script `→ curl -sfL get.rke2.io | sh`
- [ ] **4.5** — Enable and start rke2-server.service `→ systemctl enable --now`
- [ ] **4.6** — Wait for kube-apiserver to be ready on :6443 `→ wait_for port:6443`
- [ ] **4.7** — Retrieve node-token and kubeconfig from control plane `→ /var/lib/rancher/rke2/server/`
- [ ] **4.8** — Run install_rke2_server.yml playbook `→ ansible-playbook install_rke2_server.yml`
- [ ] **4.9** — Verify kubectl get nodes shows cp01 in Ready state `→ kubectl get nodes`

### Worker Agents *(serial — one at a time)*

- [ ] **4.10** — Write `roles/rke2_agent/templates/config.yaml.j2` with server URL + token `→ server: https://cp01:9345`
- [ ] **4.11** — Write `ansible/playbooks/install_rke2_agent.yml` with serial: 1 `→ hosts: k8s_workers`
- [ ] **4.12** — Pre-requisite: enable and start iscsid on all workers (Longhorn requirement) `→ systemctl enable iscsid`
- [ ] **4.13** — Run install_rke2_agent.yml — workers join one at a time `→ ansible-playbook install_rke2_agent.yml`
- [ ] **4.14** — Verify all 3 workers appear as Ready in kubectl get nodes `→ kubectl get nodes -o wide`
- [ ] **4.15** — Apply node labels to each worker (node-role=devops/monitoring/netops) `→ kubectl label node k8s-w01 ...`

### Cluster Infrastructure Services

- [ ] **4.16** — Write `kubernetes/namespaces/` — create all namespaces (devops, monitoring, logging, netops) `→ kubectl apply -f namespaces/`
- [ ] **4.17** — Deploy MetalLB via Helm, configure IPAddressPool (.200-.220) + L2Advertisement `→ helm install metallb`
- [ ] **4.18** — Deploy ingress-nginx via Helm, verify LoadBalancer gets 192.168.10.200 `→ helm install ingress-nginx`
- [ ] **4.19** — Create cert-manager namespace and deploy via Helm `→ helm install cert-manager`
- [ ] **4.20** — Create ClusterIssuer using FreeIPA CA secret (for *.lab.internal TLS) `→ kubernetes/cert-manager/`
- [ ] **4.21** — Deploy Sealed Secrets controller `→ helm install sealed-secrets`
- [ ] **4.22** — Download kubeseal CLI and export public key for encrypting secrets `→ kubeseal --fetch-cert`
- [ ] **4.23** — Deploy Longhorn via Helm with 2 replicas, verify all nodes have replica managers `→ helm install longhorn`
- [ ] **4.24** — Verify Longhorn UI accessible at longhorn.lab.internal `→ kubectl get svc -n longhorn-system`
- [ ] **4.25** — Create StorageClass longhorn as cluster default `→ kubectl get sc`

---

## Phase 5 — GitOps: GitLab CE & AWX

### GitLab CE

- [ ] **5.1** — Write `kubernetes/gitlab/values.yaml` — disable bundled nginx, certmanager, prometheus `→ global.ingress.class`
- [ ] **5.2** — Configure GitLab LDAP in values.yaml (gitlab-bind, ldaps://ipa01:636) `→ global.ldap.servers`
- [ ] **5.3** — Create GitLab Helm namespace secret (sealed) `→ kubeseal < gitlab-secrets.yaml`
- [ ] **5.4** — Write `kubernetes/gitlab/ingress.yaml` with TLS cert from cert-manager `→ gitlab.lab.internal`
- [ ] **5.5** — Write `ansible/playbooks/deploy_gitlab.yml` using helm_release module `→ helm install gitlab`
- [ ] **5.6** — Run deploy_gitlab.yml — wait for all pods to be ready `→ ansible-playbook deploy_gitlab.yml`
- [ ] **5.7** — Retrieve initial root password from GitLab secret `→ kubectl get secret gitlab-gitlab-initial-root-password`
- [ ] **5.8** — Log in to GitLab, verify LDAP login works with FreeIPA credentials `→ https://gitlab.lab.internal`
- [ ] **5.9** — Create homelab-k8s repository in GitLab `→ New project`
- [ ] **5.10** — Push all infrastructure code to GitLab repo `→ git remote add + push`
- [ ] **5.11** — Create SSH deploy key for AWX SCM integration `→ Settings > Repository > Deploy Keys`

### AWX

- [ ] **5.12** — Write `kubernetes/awx/kustomization.yaml` for AWX Operator install `→ kustomize build | kubectl apply`
- [ ] **5.13** — Deploy AWX Operator and wait for webhook to be ready (30s pause) `→ kubectl apply -k`
- [ ] **5.14** — Write `kubernetes/awx/awx-instance.yaml` — AWX CR with LDAP extra_settings `→ kind: AWX`
- [ ] **5.15** — Apply AWX CR and wait for operator to provision all pods (5-10 min) `→ kubectl wait --for=condition=Ready`
- [ ] **5.16** — Retrieve AWX admin password from secret `→ kubectl get secret awx-admin-password`
- [ ] **5.17** — Write `kubernetes/awx/ingress.yaml` — AWX ingress with TLS `→ awx.lab.internal`
- [ ] **5.18** — Log in to AWX, verify LDAP login works with FreeIPA credentials `→ https://awx.lab.internal`
- [ ] **5.19** — Add GitLab SCM credential to AWX (SSH key from deploy key) `→ AWX > Credentials`
- [ ] **5.20** — Create AWX Project pointing to GitLab homelab-k8s repo `→ AWX > Projects`
- [ ] **5.21** — Create AWX Inventory from project (inventory/hosts.yml) `→ AWX > Inventories`
- [ ] **5.22** — Create AWX Job Templates for each major playbook `→ AWX > Templates`
- [ ] **5.23** — Configure GitLab webhook to notify AWX on push to main branch `→ GitLab > Webhooks`
- [ ] **5.24** — Test GitOps loop: push change to GitLab, verify AWX job auto-triggers `→ end-to-end test`

---

## Phase 6 — Observability Stack

### Prometheus + Grafana

- [ ] **6.1** — Write `kubernetes/prometheus/values.yaml` — kube-prometheus-stack Helm values `→ 30GB PVC, 30d retention`
- [ ] **6.2** — Configure Grafana LDAP in values (grafana-bind, ldap.toml as secret) `→ global.ldap`
- [ ] **6.3** — Create Grafana LDAP toml as sealed secret `→ kubeseal`
- [ ] **6.4** — Write `kubernetes/prometheus/alertmanager-config.yaml` — Splunk HEC webhook `→ receivers: splunk-hec`
- [ ] **6.5** — Write `kubernetes/prometheus/ingress.yaml` for Prometheus, Grafana, Alertmanager `→ 3 ingress resources`
- [ ] **6.6** — Write `ansible/playbooks/deploy_prometheus.yml` `→ helm install kube-prometheus-stack`
- [ ] **6.7** — Run deploy_prometheus.yml `→ ansible-playbook deploy_prometheus.yml`
- [ ] **6.8** — Verify Grafana accessible and LDAP login works `→ https://grafana.lab.internal`
- [ ] **6.9** — Verify node-exporter DaemonSet running on all nodes (port 9100) `→ kubectl get daemonset`
- [ ] **6.10** — Install Zabbix datasource plugin in Grafana `→ grafana-cli plugins install`
- [ ] **6.11** — Write ServiceMonitors for AWX, GitLab, NetBox `→ kubernetes/prometheus/servicemonitors/`

### Zabbix

- [ ] **6.12** — Write `kubernetes/zabbix/values.yaml` — Zabbix Helm values with LDAP auth `→ zabbix-server + web`
- [ ] **6.13** — Configure Zabbix LDAP (zabbix-bind) in values `→ ldap_config`
- [ ] **6.14** — Write `kubernetes/zabbix/agent-daemonset.yaml` — Zabbix agent on all nodes `→ DaemonSet :10050`
- [ ] **6.15** — Write `ansible/playbooks/deploy_zabbix.yml` `→ helm install zabbix`
- [ ] **6.16** — Run deploy_zabbix.yml `→ ansible-playbook deploy_zabbix.yml`
- [ ] **6.17** — Log in to Zabbix, add all 5 VMs as monitored hosts `→ https://zabbix.lab.internal`
- [ ] **6.18** — Verify Zabbix agent auto-discovered on all nodes `→ Zabbix > Discovery`
- [ ] **6.19** — Add Zabbix as Grafana datasource using Zabbix plugin `→ Grafana > Datasources`

---

## Phase 7 — Splunk SIEM

### Splunk Enterprise

- [ ] **7.1** — Write `kubernetes/splunk/splunk-operator.yaml` — deploy Splunk Operator `→ kubectl apply`
- [ ] **7.2** — Write `kubernetes/splunk/standalone.yaml` — StandaloneInstance CR (50GB PVC) `→ kind: Standalone`
- [ ] **7.3** — Write `kubernetes/splunk/ingress.yaml` for Splunk web UI + HEC `→ splunk.lab.internal`
- [ ] **7.4** — Write `ansible/playbooks/deploy_splunk.yml` — operator then instance (15 min wait) `→ --wait 900s`
- [ ] **7.5** — Run deploy_splunk.yml `→ ansible-playbook deploy_splunk.yml`
- [ ] **7.6** — Retrieve Splunk admin password from secret `→ kubectl get secret splunk-s1-standalone-secret-v1`
- [ ] **7.7** — Log in to Splunk web UI at https://splunk.lab.internal `→ port :8000 via ingress`
- [ ] **7.8** — Create indexes: os_logs (90d retention), k8s_audit (90d retention) `→ Settings > Indexes`
- [ ] **7.9** — Create HEC token for log ingest (disable indexer acknowledgment) `→ Settings > Data Inputs > HEC`
- [ ] **7.10** — Write `kubernetes/splunk/uf-daemonset.yaml` — Universal Forwarder on all nodes `→ DaemonSet`
- [ ] **7.11** — Configure UF outputs.conf → Splunk :9997, inputs.conf for auditd + syslog `→ ConfigMap`
- [ ] **7.12** — Deploy UF DaemonSet, verify all nodes forwarding logs `→ kubectl get daemonset`
- [ ] **7.13** — Verify os_logs index receiving data in Splunk `→ index=os_logs | stats count by host`
- [ ] **7.14** — Write K8s audit log forwarder (ship kube-apiserver audit.log to Splunk HEC) `→ fluent-bit or sidecar`
- [ ] **7.15** — Verify k8s_audit index receiving K8s API audit events `→ index=k8s_audit | stats count`
- [ ] **7.16** — Configure Alertmanager webhook to Splunk HEC (from Phase 6.4) `→ test alert fire`
- [ ] **7.17** — Build Splunk dashboard: OS login events, sudo activity, failed auth `→ Dashboard Studio`
- [ ] **7.18** — Build Splunk correlation search: >5 failed SSH logins from same IP in 5 min `→ saved search + alert`

---

## Phase 8 — NetOps: NetBox CMDB

### NetBox

- [ ] **8.1** — Write `kubernetes/netbox/values.yaml` — NetBox Helm values with LDAP config `→ django-auth-ldap`
- [ ] **8.2** — Configure netbox-bind in values, is_staff for cn=netbox-admins `→ ldap_config.py`
- [ ] **8.3** — Write `kubernetes/netbox/ingress.yaml` `→ netbox.lab.internal`
- [ ] **8.4** — Write `ansible/playbooks/deploy_netbox.yml` `→ helm install netbox`
- [ ] **8.5** — Run deploy_netbox.yml `→ ansible-playbook deploy_netbox.yml`
- [ ] **8.6** — Log in to NetBox at https://netbox.lab.internal, verify LDAP login `→ browser test`
- [ ] **8.7** — Populate NetBox: add site, rack, all 5 VMs as virtual machines `→ NetBox UI or API`
- [ ] **8.8** — Add IP addresses and prefixes (192.168.10.0/24, all host IPs) `→ NetBox IPAM`
- [ ] **8.9** — Add all K8s cluster services and Ingress VIP as NetBox records `→ NetBox Virtualization`
- [ ] **8.10** — Add Grafana datasource for NetBox (if plugin available) `→ Grafana > Datasources`

---

## Phase 9 — Cluster Verification & Health Checks

### Automated Health Check Script

- [ ] **9.1** — Write `scripts/verify-cluster-health.sh` — check all nodes Ready `→ kubectl get nodes`
- [ ] **9.2** — Script: verify all pods Running/Completed across all namespaces `→ kubectl get pods -A`
- [ ] **9.3** — Script: verify all PVCs Bound in all namespaces `→ kubectl get pvc -A`
- [ ] **9.4** — Script: verify all Ingress resources have a load-balancer IP `→ kubectl get ingress -A`
- [ ] **9.5** — Script: HTTP 200 check for all 8 service URLs `→ curl -sk URL | head`
- [ ] **9.6** — Script: LDAP connectivity test (ldapsearch via each bind account) `→ ldapsearch -H ldaps://ipa01:636`
- [ ] **9.7** — Script: Splunk index count > 0 for os_logs and k8s_audit `→ curl Splunk REST API`
- [ ] **9.8** — Run verify-cluster-health.sh, fix any failures before proceeding `→ bash verify-cluster-health.sh`

### End-to-End Integration Tests

- [ ] **9.9** — Test GitOps loop: commit to GitLab → AWX auto-triggers → playbook runs `→ GitLab webhook`
- [ ] **9.10** — Test LDAP login to all 6 applications with FreeIPA test user `→ all apps`
- [ ] **9.11** — Test SSH with HBAC: infra-admin user can SSH to k8s nodes `→ ssh k8s-w01.lab.internal`
- [ ] **9.12** — Test HBAC denial: non-infra-admin user cannot SSH (expect deny) `→ should fail`
- [ ] **9.13** — Verify Prometheus scraping all targets (check /targets page) `→ https://prometheus.lab.internal/targets`
- [ ] **9.14** — Verify Grafana dashboards show live node-exporter metrics `→ Grafana > Dashboards`
- [ ] **9.15** — Verify Zabbix shows all hosts UP with green status `→ Zabbix > Dashboard`
- [ ] **9.16** — Verify Splunk receiving and indexing logs from all 5 hosts `→ index=os_logs | dedup host`
- [ ] **9.17** — Trigger test Prometheus alert, verify it fires in Alertmanager and Splunk `→ simulate high CPU`
- [ ] **9.18** — Test Longhorn failover: drain a worker, verify PVCs remount on other nodes `→ kubectl drain`
- [ ] **9.19** — Test TLS: verify all *.lab.internal certs are signed by FreeIPA CA `→ openssl s_client`

---

## Phase 10 — Security Evidence & CMMC Documentation

### Evidence Collection

- [ ] **10.1** — Screenshot: `kubectl get nodes` (all Ready) `→ portfolio evidence`
- [ ] **10.2** — Screenshot: Grafana dashboard with live metrics from all 5 nodes `→ portfolio evidence`
- [ ] **10.3** — Screenshot: Splunk — os_logs index with data from all hosts `→ portfolio evidence`
- [ ] **10.4** — Screenshot: AWX job history showing successful playbook runs `→ portfolio evidence`
- [ ] **10.5** — Screenshot: GitLab CI pipeline passing (lint + validate) `→ portfolio evidence`
- [ ] **10.6** — Screenshot: FreeIPA HBAC rules (allow_all disabled) `→ portfolio evidence`
- [ ] **10.7** — Screenshot: Longhorn UI showing volumes and replicas `→ portfolio evidence`
- [ ] **10.8** — Screenshot: NetBox CMDB with all VMs and IP addresses `→ portfolio evidence`
- [ ] **10.9** — Export Splunk saved search results as CSV for CMMC evidence package `→ Search > Export`
- [ ] **10.10** — Export AWX job history as PDF or CSV for CMMC evidence package `→ AWX > Activity Stream`

### CMMC Control Validation

- [ ] **10.11** — Run Splunk SPL: AC evidence — login success/fail counts by user and host `→ index=os_logs auth`
- [ ] **10.12** — Run Splunk SPL: AU evidence — audit log gap check (any hours with 0 events?) `→ timechart span=1h`
- [ ] **10.13** — Run Splunk SPL: CM evidence — K8s resource changes by user `→ index=k8s_audit verb IN (create,update,delete)`
- [ ] **10.14** — Run Splunk SPL: SI evidence — detect suspicious binaries executed `→ EXECVE nc wget curl`
- [ ] **10.15** — Document AIDE file integrity baseline and verification procedure `→ docs/aide-runbook.md`
- [ ] **10.16** — Document secret rotation procedure (rotate-secrets.sh) `→ docs/secret-rotation.md`
- [ ] **10.17** — Write `docs/cmmc-mapping.md` — complete control-to-implementation mapping `→ 110 practices`

---

## Phase 11 — Portfolio Additions *(Recommended)*

### Python Security Automation

- [√] **11.1** — Write Python script: AIDE report parser → Splunk HEC ingest `→ scripts/aide-to-splunk.py`
- [√] **11.2** — Write Python script: FreeIPA account lifecycle auditor (stale accounts) `→ scripts/ipa-account-audit.py`
- [√] **11.3** — Write Python script: K8s audit log analyzer (flag secret access anomalies) `→ scripts/k8s-audit-analyzer.py`
- [ ] **11.4** — Add pytest unit tests for each automation script `→ tests/test_*.py`
- [ ] **11.5** — Add GitLab CI stage to lint and test Python scripts on every push `→ .gitlab-ci.yml`

### Threat Model

- [√] **11.6** — Write `docs/threat-model.md` — STRIDE analysis of the K8s cluster `→ Spoofing, Tampering...`
- [√] **11.7** — Document top 5 attack vectors and mitigating controls for each `→ e.g. etcd access, LDAP injection` docs/attack-vectors.md
- [√] **11.8** — Map threat mitigations back to NIST 800-171 controls `→ links to cmmc-mapping.md`

### AWS Cloud Companion *(Optional)*

- [ ] **11.9** — Write `terraform/aws/` — basic VPC, Security Groups, EC2 with IAM role `→ GovCloud region`
- [ ] **11.10** — Configure AWS S3 as Longhorn backup target (cross-environment DR) `→ backupstore s3://`
- [ ] **11.11** — Add AWS Security Hub findings to Splunk via CloudWatch Logs `→ Lambda or Kinesis Firehose`
- [ ] **11.12** — Write `docs/aws-integration.md` explaining the hybrid on-prem/cloud design `→ architecture diagram`

### Final Portfolio Polish

- [ ] **11.13** — Record short screen recording showing: GitOps loop + LDAP login + Splunk data `→ OBS or Loom (<5 min)`
- [√] **11.14** — Write GitHub README with architecture diagram, quickstart, and key highlights `→ README.md`
- [ ] **11.15** — Push all code to public GitHub repo with clean commit history `→ git push github main`
- [ ] **11.16** — Add repo link to resume and LinkedIn profile `→ portfolio section`
- [ ] **11.17** — Prepare 5-minute demo walkthrough narrative for interviews `→ talk track`

---

## Quick Reference

### VM Layout

| Hostname | IP | vCPU | RAM | Disk | Role |
|---|---|---|---|---|---|
| ipa01 | 192.168.10.5 | 2 | 4 GB | 40 GB | FreeIPA · DNS · CA · LDAP |
| k8s-cp01 | 192.168.10.10 | 4 | 8 GB | 80 GB | RKE2 server · etcd · API |
| k8s-w01 | 192.168.10.11 | 6 | 16 GB | 200 GB | AWX · GitLab CE |
| k8s-w02 | 192.168.10.12 | 6 | 16 GB | 200 GB | Splunk · Prometheus · Grafana |
| k8s-w03 | 192.168.10.13 | 4 | 8 GB | 100 GB | NetBox · Zabbix |
| **Total** | | **22** | **52 GB** | **620 GB** | |

### Deployment Dependency Order

```
Proxmox template
  └── Terraform (VMs)
        └── Ansible base OS + CIS hardening
              └── FreeIPA (DNS must be up before anything else resolves)
                    └── RKE2 control plane
                          └── RKE2 workers
                                └── MetalLB → ingress-nginx → cert-manager → Sealed Secrets → Longhorn
                                      └── GitLab → AWX
                                            └── Prometheus stack → Zabbix → Splunk → NetBox
                                                  └── Verification → Evidence → Portfolio
```

### Service URLs

| Service | URL | Namespace |
|---|---|---|
| AWX | https://awx.lab.internal | devops |
| GitLab CE | https://gitlab.lab.internal | devops |
| Grafana | https://grafana.lab.internal | monitoring |
| Prometheus | https://prometheus.lab.internal | monitoring |
| Alertmanager | https://alerts.lab.internal | monitoring |
| Zabbix | https://zabbix.lab.internal | monitoring |
| Splunk | https://splunk.lab.internal | logging |
| NetBox | https://netbox.lab.internal | netops |
| Longhorn | https://longhorn.lab.internal | longhorn-system |
| FreeIPA | https://ipa01.lab.internal | — (bare metal) |

### Key Commands Cheatsheet

```bash
# Terraform
terraform init && terraform plan && terraform apply

# Ansible
ansible all -m ping
ansible-playbook ansible/playbooks/provision_vms.yml
ansible-playbook ansible/playbooks/harden_os.yml
ansible-playbook ansible/playbooks/install_rke2_server.yml
ansible-playbook ansible/playbooks/install_rke2_agent.yml
ansible-playbook ansible/playbooks/site.yml

# K8s cluster check
kubectl get nodes -o wide
kubectl get pods -A
kubectl get pvc -A
kubectl get ingress -A

# Verify all services
bash scripts/verify-cluster-health.sh

# Sealed secret creation
kubeseal --fetch-cert > pub-cert.pem
kubeseal --cert pub-cert.pem < secret.yaml > sealed-secret.yaml

# FreeIPA quick checks
kinit admin
ipa user-find
ipa hbacrule-find
ipa dnsrecord-find lab.internal
```

---

*Infrastructure Security Engineering Portfolio · Jason A. Slocomb · Proxmox / RKE2 / FreeIPA / CMMC Level 2*
