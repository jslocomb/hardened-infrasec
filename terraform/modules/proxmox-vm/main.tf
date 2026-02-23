resource "proxmox_vm_qemu" "vm" {
  name        = var.vm_name
  vmid        = var.vm_id
  target_node = var.target_node
  clone       = var.template
  full_clone  = true

  # Hardware
  cores   = var.cores
  sockets = 1
  memory  = var.memory
  cpu     = "host"

  # Machine type — q35 for better hardware emulation
  machine  = "q35"
  bios     = "ovmf"

  # Disk
  disk {
    slot     = 0
    size     = var.disk_size
    type     = "virtio"
    storage  = "local-lvm"
    iothread = 1
    discard  = "on"
  }

  # Network
  network {
    model  = "virtio"
    bridge = "vmbr1"
  }

  # Cloud-init
  os_type    = "cloud-init"
  ipconfig0  = "ip=${var.ip_address}/24,gw=${var.gateway}"
  nameserver = var.nameserver
  sshkeys    = var.ssh_keys

  # Disable memory ballooning — required for K8s
  balloon = 0

  # Startup
  onboot  = true
  agent   = 1

  tags = join(",", var.tags)

  lifecycle {
    ignore_changes = [
      network,
    ]
  }
}
