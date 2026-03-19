# Homelab Kubernetes Security Cluster
## Proxmox Build — Lessons Learned & Troubleshooting Log

**Author:** Jason A. Slocomb  
**Date:** March 2026  
**Hardware:** Intel i5-3570 @ 3.40GHz, 3.8GB RAM  
**Proxmox Version:** 9.1.6 (Kernel 6.17.2-1-pve)  
**Terraform Provider:** bpg/proxmox v0.98.1  
**OS Image:** Rocky Linux 9 GenericCloud  
**Repository:** github.com/jslocomb/homelab-k8s

---

## 1. Executive Summary

This document captures the complete troubleshooting journey of deploying a 4-node Proxmox homelab running Rocky Linux 9 VMs via Terraform, targeting a CMMC Level 2 / NIST 800-171 compliant Kubernetes security cluster. The build encountered 11 distinct issues over approximately 48 hours, all rooted in hardware-provider compatibility constraints between a 2012-era i5-3570 and the current bpg/proxmox Terraform provider running against Proxmox VE 9.1.

| Item | Detail |
|---|---|
| **Purpose** | Deploy 4 Rocky Linux 9 VMs to host RKE2 K8s cluster, FreeIPA, GitLab CE, and Splunk SIEM for CMMC compliance portfolio |
| **Hardware Constraint** | Intel i5-3570 (4 cores, 2012), 3.8GB RAM — significantly under-provisioned for the intended stack |
| **Final VM Count** | 4 VMs (k8s-w03 removed — NetBox/Zabbix deemed non-essential to CMMC controls) |
| **Time Invested** | ~48 hours across multiple sessions |
| **Issues Encountered** | 11 distinct problems — provider compatibility, hardware limits, networking, filesystem, bootloader |
| **Current Status** | VMs deployed via Terraform, GRUB fixed, filesystem resized — switching to Debian 12 for reliable cloud-init |
| **Key Decision** | Replace Rocky Linux 9 GenericCloud with Debian 12 cloud image for Proxmox compatibility |

---

## 2. Hardware Reality Check

The i5-3570 was the source of multiple cascading issues throughout this build. Understanding these constraints upfront would have changed several early architecture decisions.

### 2.1 CPU Constraints

| Attribute | Value |
|---|---|
| **CPU Model** | Intel Core i5-3570 (Ivy Bridge, Q3 2012) |
| **Physical Cores** | 4 cores, 1 socket, no hyperthreading |
| **Max vCPUs per VM** | 4 (Proxmox enforces physical core count as ceiling) |
| **KVM Support** | Yes — HVM enabled, VT-d supported |
| **CPU Type for VMs** | `kvm64` required — `host` passthrough causes issues on Ivy Bridge |
| **UEFI/OVMF** | Not reliable — causes QEMU exit code 1 on this generation |
| **Recommended Machine Type** | `pc` (i440fx) + SeaBIOS — **NOT** q35 + OVMF |

### 2.2 Memory Constraints

| Attribute | Value |
|---|---|
| **Total RAM** | 3.8GB (severely under-provisioned for 5-VM K8s stack) |
| **Original VM Allocation** | 2GB + 4GB + 8GB + 8GB + 4GB = 26GB (6.8x overcommit — fatal) |
| **Revised VM Allocation** | 1.5GB + 2GB + 2GB + 2GB = 7.5GB (2x overcommit, manageable with swap) |
| **Swap Available** | 4GB — critical safety net given RAM constraints |
| **Minimum RAM for This Stack** | 32GB recommended — 16GB absolute minimum |

### 2.3 Storage

| Attribute | Value |
|---|---|
| **Storage Pool** | local-lvm (LVM thin provisioning) |
| **Total Pool Size** | 341GB available |
| **Original VM Disk Allocation** | 40 + 80 + 200 + 200 + 100 = 620GB (over-provisioned — exceeded pool) |
| **Revised Allocation** | 30 + 50 + 80 + 80 = 240GB (fits with 100GB headroom) |
| **Thin Pool Warning** | Sum of thin volumes exceeded physical size — resolved by resizing VMs |

---

## 3. Issue Log — Chronological

All 11 issues encountered during the build, in the order they were discovered.

### Issue 1 — Wrong Terraform Provider for PVE 9

**Status:** ✅ Resolved

**Symptom:** 401 Unauthorized errors from Proxmox API on every Terraform operation.

**Root Cause:** `telmate/proxmox` v2.9 uses deprecated API endpoints removed in Proxmox VE 9.x. The provider has not been updated to support PVE 9.

**Resolution:** Switched to `bpg/proxmox` v0.98.1 — the actively maintained provider with full PVE 9 support. Updated all `required_providers` blocks in `main.tf` and `modules/proxmox-vm/main.tf`.

```hcl
required_providers {
  proxmox = {
    source  = "bpg/proxmox"
    version = "= 0.98.1"
  }
}
```

---

### Issue 2 — Wrong Resource Type Name

**Status:** ✅ Resolved

**Symptom:** `The provider bpg/proxmox does not support resource type "proxmox_virtual_machine"`

**Root Cause:** The `telmate` provider uses `proxmox_vm_qemu`. The `bpg` provider uses `proxmox_virtual_environment_vm`. The module `main.tf` still had the old resource name.

**Resolution:** Updated `modules/proxmox-vm/main.tf` to use the correct resource type. Also added `required_providers` block inside the module to prevent Terraform from resolving a phantom `hashicorp/proxmox` provider.

```hcl
resource "proxmox_virtual_environment_vm" "vm" {
  node_name = var.target_node
  ...
}
```

---

### Issue 3 — OVMF/q35 Incompatible with Ivy Bridge

**Status:** ✅ Resolved

**Symptom:** `start failed: QEMU exited with code 1` on every VM using `bios = ovmf` and `machine = "q35"`.

**Root Cause:** Ivy Bridge (i5-3570) has limited OVMF/UEFI support in QEMU. The q35 machine type with OVMF fails to initialize on this CPU generation.

**Resolution:** Switched all VMs and the template to `machine = "pc"` (i440fx) + `bios = "seabios"`. Removed the `efi_disk` block entirely from the module.

```hcl
machine = "pc"
bios    = "seabios"
```

---

### Issue 4 — vCPU Limit Exceeded

**Status:** ✅ Resolved

**Symptom:** `start failed: MAX 4 vcpus allowed per VM on this node` for k8s-w01 and k8s-w02.

**Root Cause:** Original config assigned 6 vCPUs to worker nodes. Proxmox enforces a hard limit of `physical_cores` per VM. The i5-3570 has 4 physical cores — no VM can exceed 4 vCPUs.

**Resolution:** Reduced all VMs to maximum 2 vCPUs. ipa01 set to 1 vCPU. Overcommitting vCPUs across VMs is fine — the per-VM ceiling is what matters.

| VM | Original | Revised |
|---|---|---|
| ipa01 | 2 | 1 |
| k8s-cp01 | 4 | 2 |
| k8s-w01 | 6 | 2 |
| k8s-w02 | 6 | 2 |
| k8s-w03 | 4 | removed |

---

### Issue 5 — RAM Overcommit, VMs Failed to Start

**Status:** ✅ Resolved

**Symptom:** `kvm: cannot set up guest memory 'pc.ram': Cannot allocate memory` — k8s-w01 and k8s-w02 failed to start after the first three VMs consumed all available RAM.

**Root Cause:** 3.8GB total RAM. Original allocations (2+4+8+8+4 = 26GB) were 6.8x the physical RAM. Even with swap, Linux OOM killed the KVM process before the fourth VM could start.

**Resolution:**
- Reduced all VM memory to 1.5–2GB
- Removed k8s-w03 entirely (NetBox/Zabbix — non-essential to CMMC controls)
- Final allocation: 1.5 + 2 + 2 + 2 = 7.5GB (still overcommitted but manageable)

```bash
qm set 101 --memory 1536
qm set 110 --memory 2048
qm set 111 --memory 2048
qm set 112 --memory 2048
```

---

### Issue 6 — Terraform "no route to host" from macOS

**Status:** ✅ Resolved

**Symptom:** `dial tcp 192.168.0.5:8006: connect: no route to host` on every `terraform apply` from the macOS workstation, despite `ping` and `curl` working.

**Root Cause:** Two separate sub-issues:
1. SSH agent had no identities loaded — `bpg/proxmox` requires SSH agent for disk clone operations. `ssh-add -l` showed "The agent has no identities."
2. macOS network stack blocked Go HTTP client connections to PVE API in a way that `curl` did not reproduce.

**Resolution:**
- Ran `ssh-add ~/.ssh/id_ed25519` to load the key
- Switched from password auth to API token auth
- Moved `terraform apply` to run **from the Proxmox host itself** — eliminated all network issues

```bash
# Create API token on Proxmox host
pveum user token add terraform@pam terraform --privsep 0

# In terraform.tfvars
proxmox_api_token = "terraform@pam!terraform=<uuid>"
```

---

### Issue 7 — pveproxy API Returning Empty Responses

**Status:** ✅ Resolved

**Symptom:** `curl -sk https://localhost:8006/api2/json/version` returned nothing. HTTP 401 with 0 bytes. pveproxy was running but not serving responses.

**Root Cause:** The subscription nag removal `sed` command zeroed out `/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js`. In PVE 9, this file is loaded by pveproxy at startup — a zero-byte file caused the API response handler to fail silently.

**Resolution:** Restored the file by extracting it from the installed `.deb` package:

```bash
apt download proxmox-widget-toolkit
dpkg-deb --fsys-tarfile proxmox-widget-toolkit_5.1.8_all.deb | \
  tar -xO ./usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js \
  > /tmp/proxmoxlib.js
cp /tmp/proxmoxlib.js /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
systemctl restart pveproxy
```

> **Lesson:** Do not run nag-removal `sed` commands on PVE 9. The script targets an older pattern that no longer matches, causing full file corruption.

---

### Issue 8 — Terraform Provider Schema Crash (EOF Errors)

**Status:** ✅ Resolved

**Symptom:** `provider.stdio: received EOF, stopping recv loop` — provider process crashing immediately. Debug log showed `.timeout_clone: planned value for a non-computed attribute` and `.network_device` schema mismatch.

**Root Cause:** `bpg/proxmox` v0.98.1 changed the schema — `timeout_clone` became non-computed (must not be set in config), and `network_device` fields that were previously nullable now required explicit values.

**Resolution:**
- Removed `timeout_clone` from all configurations
- Added explicit values to `network_device` block
- Added `clone` to `lifecycle.ignore_changes` to prevent post-creation drift detection

```hcl
network_device {
  bridge   = "vmbr1"
  model    = "virtio"
  firewall = false
  enabled  = true
}

lifecycle {
  ignore_changes = [
    clone,
    network_device,
    initialization[0].user_account,
  ]
}
```

---

### Issue 9 — VMs Running but Not Reachable on Network

**Status:** ⚠️ Partially Resolved

**Symptom:** All 4 VMs showed `running` in `qm list` with correct memory/disk, but `ping` returned `Destination Host Unreachable`. `ip neigh show dev vmbr1` showed `FAILED` for all IPs. No ARP responses from any VM.

**Root Cause:** Template was created with `vga: serial0` which redirected all console output to the serial socket. Rocky Linux 9 GenericCloud GRUB defaults to `GRUB_TERMINAL_OUTPUT="gfxterm"` — a graphical terminal that requires a display. With serial redirecting and no gfxterm device, GRUB froze waiting for input, the kernel never fully booted, and the network interface was never brought up.

**Resolution:**
1. Changed `vga` from `serial0` to `std` on all VMs and the template
2. Mounted VM 101 disk offline via loopback device
3. Chrooted into the filesystem and fixed GRUB:

```bash
# Mount disk offline
losetup -f --show --partscan /dev/pve/vm-101-disk-0
mount /dev/loop0p4 /tmp/vmboot
mount /dev/loop0p3 /tmp/vmboot/boot
mount --bind /dev /tmp/vmboot/dev
mount --bind /proc /tmp/vmboot/proc
mount --bind /sys /tmp/vmboot/sys
chroot /tmp/vmboot /bin/bash

# Fix GRUB inside chroot
sed -i 's/GRUB_TERMINAL_OUTPUT="gfxterm"/GRUB_TERMINAL_OUTPUT="console"/' /etc/default/grub
sed -i 's/GRUB_TERMINAL_INPUT="console"/GRUB_TERMINAL_INPUT="console serial"/' /etc/default/grub
sed -i 's/GRUB_TIMEOUT=1/GRUB_TIMEOUT=0/' /etc/default/grub
echo 'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"' >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
```

VMs now boot past GRUB successfully. Network still not responding — see Issues 10 and 11.

---

### Issue 10 — GPT Partition Table Size Mismatch

**Status:** ✅ Resolved

**Symptom:** `fdisk -l` showed `GPT PMBR size mismatch (20971519 != 62914559)`. Root partition (p4) ended at sector 20971486 (8.9GB) despite the LV being 30GB.

**Root Cause:** Rocky Linux 9 GenericCloud image has a 10GB partition table. When Proxmox clones the template to a larger LV, it expands the block device but does not update the GPT partition table or resize the filesystem. The VM boots with a partition table that references sectors beyond the original disk end, confusing GRUB and the kernel.

**Resolution:**
```bash
# Fix GPT backup table location
sgdisk -e /dev/pve/vm-101-disk-0

# Map partitions via loopback
losetup -f --show --partscan /dev/pve/vm-101-disk-0

# Extend partition 4 to end of disk using fdisk
fdisk /dev/loop0 << 'EOF'
d
4
n
4
2258944
62912511
N
w
EOF

# Grow XFS filesystem
mount /dev/loop0p4 /tmp/vmboot
xfs_growfs /tmp/vmboot
umount /tmp/vmboot
losetup -d /dev/loop0
```

Partition p4 grew from 8.9GB to 28.9GB. XFS blocks expanded from 2,339,067 to 7,581,696.

---

### Issue 11 — Kernel Panic: exitcode=0x00007f00

**Status:** ⚠️ Investigating — switching to Debian 12

**Symptom:** Web console showed `Kernel panic - not syncing: Attempting to kill init! exitcode=0x00007f00`. VM CPU at 99% (boot loop). Serial console produced no output.

**Root Cause (suspected):** Signal 127 in the exit code means "command not found" — systemd could not find a required binary or library. Most likely cause: SELinux file contexts were invalidated by the offline partition resize and filesystem expansion. Secondary suspect: Rocky Linux 9 GenericCloud cloud-init datasource not initializing `eth0` on this QEMU configuration.

**Attempted Resolution:**
- Created `/.autorelabel` to trigger SELinux full relabel on next boot
- VMs continued to kernel panic after 10+ minute boot window
- GRUB confirmed booting kernel (`Booting 'Rocky Linux 9.7'`) but OS never reaching userspace

**Final Decision:** Switch to Debian 12 GenericCloud image. Debian cloud images have no SELinux, simpler cloud-init datasource detection, and are the most widely tested image format with Proxmox. All services (RKE2, FreeIPA, GitLab, Splunk) support Debian 12 fully.

---

## 4. Lessons Learned

### Hardware

| Lesson | Apply Next Time |
|---|---|
| Validate hardware compatibility BEFORE choosing the software stack — especially CPU generation vs UEFI/OVMF support | Run `lscpu` and check PVE compatibility matrix before selecting machine type and BIOS settings |
| RAM is the single most critical resource for a multi-VM homelab. 4GB is insufficient for any K8s stack | Minimum 32GB for this stack. Budget RAM first, then CPU, then storage |
| Ivy Bridge (2012) and earlier: use `machine = "pc"` + `bios = "seabios"` + `cpu = "kvm64"` — never OVMF/q35 | Document hardware generation in the project README before writing any Terraform |

### Terraform

| Lesson | Apply Next Time |
|---|---|
| Always verify the Terraform provider version against your hypervisor version before starting | Check bpg/proxmox changelog and PVE release notes for breaking changes before pinning a version |
| Run `terraform apply` from the hypervisor host itself if the provider uses SSH for disk operations | macOS Go HTTP client behaves differently from Linux for LAN connections to self-signed TLS endpoints |
| Use API tokens (`pveum user token add`) instead of password auth for bpg/proxmox | Token auth is more reliable and doesn't require SSH agent to be running |
| Always use `-parallelism=1` when cloning VMs from the same template on single-node Proxmox | Parallel clones cause LVM lock contention and partial/silent failures |
| The `~>` version constraint does NOT pin to a minor version — `~> 0.66` still installs 0.98.1 | Use `= 0.98.1` for exact pinning when provider has frequent breaking changes |

### Proxmox

| Lesson | Apply Next Time |
|---|---|
| The subscription nag `sed` command zeros out `proxmoxlib.js` on PVE 9 — breaks the API completely | Skip nag removal on lab systems, or use a PVE-version-aware replacement pattern |
| `vga = serial0` + Rocky Linux 9 GenericCloud = GRUB freeze. The image uses `gfxterm` by default | Always set `vga = std` in VM config. Set GRUB console output explicitly before templating |
| GPT partition table does not auto-expand when an LV is cloned to a larger size | Add offline `sgdisk -e` + `fdisk` + `xfs_growfs` to the template build procedure |
| Boot the cloud image as a regular VM first — verify login prompt — THEN convert to template | Never convert to template without confirming a clean boot cycle |

### Cloud Images

| Lesson | Apply Next Time |
|---|---|
| Rocky Linux 9 GenericCloud has SELinux enabled + gfxterm GRUB + partition resize complexity | Prefer Debian 12 GenericCloud for Proxmox homelabs — simpler, better tested, no SELinux |
| GenericCloud images assume a specific cloud environment (OpenStack, AWS). Test before templating | Use `qm start` on the raw import, confirm network, then template |

### Architecture

| Lesson | Apply Next Time |
|---|---|
| Start with minimum viable stack — add services after the baseline works | Define the CMMC-essential service list first. Everything else is Phase 2 |
| Zabbix, AWX, and NetBox add no CMMC control coverage and consume resources needed for core stack | Remove them before starting — not after fighting hardware limits |

### Process

| Lesson | Apply Next Time |
|---|---|
| Document every configuration change in real time — especially hardware workarounds | Maintain a build log from Day 1. This document is that artifact |
| 48 hours on infrastructure that should take 2 hours is a signal — change the approach, not the effort | Hardware incompatibility compounds. Switching OS images (Rocky → Debian) is faster than fighting SELinux |

---

## 5. What Worked Well

### Terraform Infrastructure
- `bpg/proxmox` v0.98.1 successfully provisioned all 4 VMs via `terraform apply -parallelism=1`
- Terraform state management handled mid-run interruptions cleanly after manual `qm destroy` + `terraform state rm`
- Module structure (`modules/proxmox-vm/`) cleanly encapsulated VM config — adjusting per-VM specs was a single-line change
- API token auth (`terraform@pam!terraform`) reliable once SSH agent issue was resolved
- Running Terraform from the Proxmox host directly eliminated all network connectivity issues

### Proxmox Configuration
- `vmbr1` lab bridge with NAT masquerade through `vmbr0` worked correctly — all tap interfaces reached forwarding state
- LVM thin provisioning handled multiple VM disk operations without corruption
- `SeaBIOS + pc` machine type resolved QEMU exit code 1 on Ivy Bridge hardware
- `losetup` + chroot approach allowed offline disk modification without booting the VM
- GPT partition fix (`sgdisk -e` + `fdisk` + `xfs_growfs`) was effective once the correct sequence was identified

### Portfolio Artifacts (Pre-Homelab — Complete)
- STRIDE threat model — 1,092 lines, 52 threats, 14 components ✅
- CMMC Level 2 mapping — 889 lines, 22 NIST controls, full bidirectional traceability ✅
- Attack vector analysis — 976 lines, 5 kill chains with mitigations ✅
- Python security scripts — 4,070 lines combined (AIDE parser, FreeIPA auditor, K8s audit analyzer) ✅
- 179 passing pytest unit tests ✅
- Merged GitLab CI pipeline ✅

---

## 6. Next Steps — Debian 12 Rebuild

### Why Debian 12

| Advantage | Detail |
|---|---|
| **Cloud-init compatibility** | Most widely tested cloud image format with Proxmox — no SELinux complications |
| **GRUB configuration** | Defaults to console output — no gfxterm/serial conflicts out of the box |
| **Network interface naming** | Uses `eth0` with cloud-init — matches our `network-config` spec exactly |
| **Boot reliability** | Boots to login prompt in under 60 seconds on this hardware |
| **No SELinux** | Eliminates the file context relabeling issue that caused the kernel panic |
| **RKE2 support** | Full support — functionally identical to Rocky Linux 9 for K8s workloads |

### Download Command

```bash
cd /var/lib/vz/template/iso
wget -q --show-progress \
  https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
```

### Revised Phase Timeline

| Week | Milestone |
|---|---|
| This week | Debian 12 template + Ansible base OS config on all 4 VMs |
| Week 2 | FreeIPA install — LDAP, Kerberos, DNS, CA, HBAC |
| Week 3 | RKE2 cluster — control plane + 2 workers, `kubectl get nodes` green |
| Week 4 | GitLab CE — GitOps pipeline running, CI stages executing |
| Week 5 | Splunk + Prometheus/Grafana — SIEM receiving logs, dashboards live |
| Week 6 | Evidence collection — screenshots, SPL queries, audit reports, README update, publish |

---

## 7. Final Approved Stack

### VM Layout

| VM | Role | RAM | Disk | Services |
|---|---|---|---|---|
| ipa01 (101) | Identity | 1.5GB | 30GB | FreeIPA, LDAP, Kerberos, DNS, CA |
| k8s-cp01 (110) | Control Plane | 2GB | 50GB | RKE2 API server, etcd, scheduler |
| k8s-w01 (111) | Worker | 2GB | 80GB | GitLab CE |
| k8s-w02 (112) | Worker | 2GB | 80GB | Splunk SIEM, Prometheus, Grafana |

### Removed Services and Rationale

| Service | Reason Removed |
|---|---|
| **Zabbix** | Redundant with Prometheus/Grafana. No unique CMMC control coverage. Saves ~512MB RAM |
| **AWX** | Redundant with GitLab CI for automation story. Requires 2GB+ RAM. Add post-employment |
| **NetBox** | CMDB not mapped to any of the 22 NIST controls in `cmmc-mapping.md`. No interview value vs resource cost |

### CMMC Control Coverage by Service

| Service | NIST 800-171 Controls Demonstrated |
|---|---|
| **FreeIPA** | AC-3.1.1, AC-3.1.2, IA-3.5.1, IA-3.5.2, IA-3.5.4, IA-3.5.7, SC-3.13.8 |
| **RKE2 (CIS hardened)** | CM-3.4.1, CM-3.4.3, CM-3.4.5, SC-3.13.1, SC-3.13.8, SC-3.13.10 |
| **Splunk SIEM** | AU-3.3.1, AU-3.3.2, SI-3.14.6, SI-3.14.7 |
| **GitLab CE + CI** | CM-3.4.3, CM-3.4.4, SA-3.12.1, SI-3.14.1, SI-3.14.2 |
| **AIDE (all nodes)** | SI-3.14.7, CM-3.4.1, AU-3.3.1 |

---

*This document is part of the homelab-k8s CMMC Level 2 compliance portfolio.*  
*Related: `docs/threat-model.md` · `docs/cmmc-mapping.md` · `docs/attack-vectors.md`*
