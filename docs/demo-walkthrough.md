# Demo Walkthrough — homelab-k8s

A narrated walkthrough of the homelab-k8s security automation project, demonstrating a fully operational CMMC Level 2 aligned stack running on AWS.

📹 **Demo Video:** [Watch on Loom](https://www.loom.com/share/0adf554e3ddb41ff899879d20068500d)
💻 **GitHub:** [jslocomb/homelab-k8s](https://github.com/jslocomb/homelab-k8s)

---

## What the Demo Shows

This walkthrough covers all major components of the homelab-k8s stack:

- **GitHub Repository** — README, architecture diagram, and CMMC control mapping
- **Architecture Diagram** — Interactive infrastructure layout with network topology, service map, and port reference
- **FreeIPA** — Centralized LDAP/Kerberos identity management, users, and HBAC groups
- **GitLab CE** — Internal source control mirrored to GitHub with full commit history
- **AWX** — Ansible automation dashboard, NetBox dynamic inventory, and FreeIPA LDAP authentication
- **Splunk** — SIEM with live audit log aggregation from all nodes
- **Grafana** — Real-time Kubernetes cluster observability via kube-prometheus-stack
- **Terminal** — RKE2 node status confirming all three nodes in Ready state

---

## Narration Script

### Scene 1 — GitHub Repo
*"This is the homelab-k8s portfolio repository. The project demonstrates a production-grade security automation project on AWS, aligned to NIST SP 800-171 and CMMC Level 2 controls. The README includes a full stack overview and control mapping."*

---

### Scene 2 — Architecture Diagram
*"The architecture diagram shows the full infrastructure layout across the AWS VPC. Each service is mapped to its node, network segment, and compliance control family. This design transfers directly to AWS GovCloud IL2 and IL4 with only region and AMI updates."*

---

### Scene 3 — FreeIPA
*"FreeIPA provides centralized identity management using LDAP and Kerberos — the same stack approved for DoD IL2 and IL4 environments. Users and groups are managed here, with HBAC rules controlling which users can access which systems."*

---

### Scene 4 — GitLab
*"GitLab CE serves as the internal source control and CI/CD platform, mirrored to GitHub. All infrastructure changes are committed here first, providing a full audit trail of configuration changes aligned to CMMC control CM 3.4.3."*

---

### Scene 5 — AWX
*"AWX provides auditable infrastructure automation with full user attribution. The NetBox dynamic inventory automatically discovers all lab nodes from the CMDB, eliminating static inventory files. LDAP authentication is handled by FreeIPA — demonstrated here with a testuser login."*

---

### Scene 6 — Splunk
*"Splunk aggregates audit logs from all nodes via Universal Forwarders. Linux audit logs, secure logs, and Falco runtime detections all flow into indexed searches. This demonstrates audit record creation and retention aligned to CMMC control AU 3.3.1."*

---

### Scene 7 — Grafana
*"Grafana provides real-time Kubernetes cluster observability via the kube-prometheus-stack. Node health, pod counts, and network traffic are visible across all three RKE2 nodes — control plane and both workers."*

---

### Scene 8 — Terminal
*"Finally, confirming all three RKE2 Kubernetes nodes are in a Ready state — control plane and both workers running on Rocky Linux 9.7, binary-compatible with RHEL 9 and approved for AWS GovCloud deployment."*

---

## Recreating the Demo Locally

To recreate this demo with a running AWS environment, open the following SSH tunnels from your local machine:

### GitLab
```bash
ssh -L 8929:10.0.10.227:8929 bastion -N -f
```

### Splunk
```bash
ssh -L 8000:10.0.10.117:8000 bastion -N -f
```

### AWX
```bash
# Start port-forward on k8s-cp01
ssh k8s-cp01 "nohup sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml -n awx port-forward svc/awx-service 8052:80 --address 0.0.0.0 > /tmp/awx-pf.log 2>&1 &"

# Open local tunnel
ssh -L 8052:10.0.10.146:8052 bastion -N -f
```

### Grafana
```bash
# Start port-forward on k8s-cp01
ssh k8s-cp01 "nohup sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80 --address 0.0.0.0 > /tmp/grafana-pf.log 2>&1 &"

# Open local tunnel
ssh -L 3000:10.0.10.146:3000 bastion -N -f
```

### FreeIPA
```bash
sudo ssh -i ~/.ssh/id_ed25519 -L 443:10.0.10.113:443 rocky@<bastion-public-ip> -N -f
```

### Service URLs

| Service | URL |
|---------|-----|
| FreeIPA | https://localhost |
| GitLab | http://localhost:8929 |
| AWX | http://localhost:8052 |
| Splunk | http://localhost:8000 |
| Grafana | http://localhost:3000 |
| Architecture Diagram | https://curious-wisp-e95465.netlify.app |
| GitHub Repo | https://github.com/jslocomb/homelab-k8s |

---

## Verify All Tunnels Are Open

```bash
ps aux | grep "ssh -L" | grep -v grep
```

## Confirm RKE2 Node Status

```bash
ssh k8s-cp01 "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes"
```
