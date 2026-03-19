terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.98.1"
    }
  }
}

resource "proxmox_virtual_environment_vm" "vm" {
  node_name = var.target_node
  vm_id     = var.vm_id
  name      = var.vm_name

  # Clone from template
  clone {
    vm_id   = var.template_id
    full    = true
    retries = 3
  }

  # CPU — kvm64 for broad compatibility with Ivy Bridge (i5-3570)
  cpu {
    cores   = var.cores
    sockets = 1
    type    = "kvm64"
  }

  # Memory — ballooning disabled (required for K8s stability)
  memory {
    dedicated = var.memory
    floating  = 0
  }

  # Machine type — i440fx + SeaBIOS for Ivy Bridge compatibility
  machine = "pc"
  bios    = "seabios"

  # Primary disk — resized from template
  disk {
    datastore_id = var.datastore
    interface    = "virtio0"
    size         = var.disk_size
    discard      = "on"
    iothread     = true
    file_format  = "raw"
  }

  # Network — lab bridge vmbr1
  network_device {
    bridge   = "vmbr1"
    model    = "virtio"
    firewall = false
    enabled  = true
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

  # QEMU guest agent
  agent {
    enabled = true
    trim    = true
  }

  on_boot = true
  tags    = var.tags

  lifecycle {
    ignore_changes = [
      clone,
      network_device,
      initialization[0].user_account,
    ]
  }
}
