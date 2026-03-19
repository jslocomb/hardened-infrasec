#!/bin/bash
# bootstrap-proxmox.sh
# Initial Proxmox host setup — run once after fresh Proxmox install.
set -euo pipefail

echo "=== Proxmox Bootstrap ==="

# Remove enterprise repo (no subscription)
sed -i 's/^deb/# deb/' /etc/apt/sources.list.d/pve-enterprise.list 2>/dev/null || true
sed -i 's/^deb/# deb/' /etc/apt/sources.list.d/ceph.list 2>/dev/null || true

# Add community repo
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" \
  > /etc/apt/sources.list.d/pve-community.list

apt-get update
apt-get upgrade -y

# Install useful tools
apt-get install -y \
  vim \
  htop \
  iotop \
  net-tools \
  nfs-kernel-server \
  open-iscsi

# Create lab network bridge vmbr1
cat >> /etc/network/interfaces << 'EOF'

auto vmbr1
iface vmbr1 inet static
    address 192.168.10.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o vmbr0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s 192.168.10.0/24 -o vmbr0 -j MASQUERADE
EOF

# Create Terraform Proxmox API user
pveum user add terraform@pam --comment "Terraform automation user"
pveum role add TerraformRole --privs "VM.Allocate VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Monitor VM.Audit VM.PowerMgmt Datastore.AllocateSpace Datastore.Audit"
pveum aclmod / -user terraform@pam -role TerraformRole
pveum passwd terraform@pam

echo ""
echo "=== Bootstrap Complete ==="
echo "Reboot to apply network changes: reboot"
