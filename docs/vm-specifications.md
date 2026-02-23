# VM Specifications

## Proxmox Host Requirements (Minimum)

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 8 cores | 16+ cores |
| RAM | 64GB | 128GB |
| Storage | 1TB NVMe | 2TB NVMe |
| Network | 1GbE | 10GbE |

## VM Inventory

| VM | Hostname | IP | vCPU | RAM | Disk | Purpose |
|---|---|---|---|---|---|---|
| FreeIPA | ipa01.lab.internal | 192.168.10.5 | 2 | 4GB | 40GB | Identity, DNS, CA |
| K8s Control Plane | k8s-cp01.lab.internal | 192.168.10.10 | 4 | 8GB | 80GB | RKE2 server, etcd |
| K8s Worker 1 | k8s-w01.lab.internal | 192.168.10.11 | 6 | 16GB | 200GB | AWX, GitLab |
| K8s Worker 2 | k8s-w02.lab.internal | 192.168.10.12 | 6 | 16GB | 200GB | Splunk, Prometheus, Grafana |
| K8s Worker 3 | k8s-w03.lab.internal | 192.168.10.13 | 4 | 8GB | 100GB | NetBox, Zabbix, overflow |

**Total:** 22 vCPU · 52GB RAM · 620GB disk

## Proxmox VM Settings (per VM)

| Setting | Value | Reason |
|---|---|---|
| Machine | q35 | Better hardware emulation, PCIe support |
| BIOS | OVMF (UEFI) | Modern firmware, Secure Boot capable |
| CPU | host | AES-NI passthrough for crypto operations |
| Balloon | Disabled | Conflicts with K8s memory management |
| Disk | VirtIO SCSI | Best performance, iothread=1 |
| Network | VirtIO | Best network performance |
| QEMU Agent | Enabled | Proxmox can report IP, graceful shutdown |

## Rocky Linux 9 Template Preparation

Before Terraform can clone VMs, create a Rocky Linux 9 cloud-init template in Proxmox:

```bash
# On Proxmox host
wget https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2

qm create 9000 --name rocky9-template --memory 2048 --cores 2 --net0 virtio,bridge=vmbr1
qm importdisk 9000 Rocky-9-GenericCloud.latest.x86_64.qcow2 local-lvm
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1
qm template 9000
```
