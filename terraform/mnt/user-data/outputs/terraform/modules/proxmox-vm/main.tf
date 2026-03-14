resource "proxmox_virtual_machine" "vm" {
  node_name = var.target_node
  vm_id     = var.vm_id
  name      = var.vm_name

  # Clone from template
  clone {
    vm_id   = var.template_id
    full    = true
    retries = 3
  }

  # CPU
  cpu {
    cores   = var.cores
    sockets = 1
    type    = "host"
  }

  # Memory — ballooning disabled (required for K8s stability)
  memory {
    dedicated = var.memory
    floating  = 0
  }

  # Machine type — q35 for PCIe, OVMF for UEFI
  machine = "q35"
  bios    = "ovmf"

  # EFI disk — required when bios = ovmf
  efi_disk {
    datastore_id = var.datastore
    type         = "4m"
  }

  # Primary disk — resized from template
  disk {
    datastore_id = var.datastore
    interface    = "virtio0"
    size         = var.disk_size
    discard      = "on"
    iothread     = true
    file_format  = "raw"
  }

  # Network — lab bridge
  network_device {
    bridge = "vmbr1"
    model  = "virtio"
  }

  # Cloud-init
  initialization {
    ip_config {
      ipv4 {
        address = "${var.ip_address}/24"
        gateway = var.gateway
      }
    }
    dns {
      servers = [var.nameserver]
    }
    user_account {
      keys = var.ssh_keys
    }
  }

  # QEMU guest agent — must be installed in the template
  agent {
    enabled = true
    trim    = true
  }

  # Start on Proxmox host boot
  on_boot = true

  # Tags
  tags = var.tags

  # Ignore network changes after creation (Proxmox may reorder NICs)
  lifecycle {
    ignore_changes = [
      network_device,
      initialization[0].user_account,
    ]
  }
}
