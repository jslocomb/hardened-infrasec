terraform {
  required_version = ">= 1.6.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.98.1"
    }
  }
}

provider "proxmox" {
  endpoint  = var.proxmox_api_url
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_tls_insecure

  ssh {
    agent    = true
    username = "root"
    node {
      name    = var.proxmox_node
      address = var.proxmox_host_ip
    }
  }
}

# ─── FreeIPA / Identity ───────────────────────────────────────────────────────
module "ipa01" {
  source      = "./modules/proxmox-vm"
  vm_name     = "ipa01"
  vm_id       = 101
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 1
  memory      = 2048
  disk_size   = 30
  ip_address  = var.ip_ipa01
  gateway     = var.gateway
  nameserver  = var.nameserver
  ssh_keys    = [var.ssh_public_key]
  tags        = ["freeipa", "auth"]
  datastore   = var.datastore
}

# ─── K8s Control Plane ────────────────────────────────────────────────────────
module "k8s_cp01" {
  source      = "./modules/proxmox-vm"
  vm_name     = "k8s-cp01"
  vm_id       = 110
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 2
  memory      = 4096
  disk_size   = 50
  ip_address  = var.ip_k8s_cp01
  gateway     = var.gateway
  nameserver  = var.ip_ipa01
  ssh_keys    = [var.ssh_public_key]
  tags        = ["k8s", "control-plane"]
  datastore   = var.datastore
}

# ─── Worker Node 1 (AWX + GitLab) ────────────────────────────────────────────
module "k8s_w01" {
  source      = "./modules/proxmox-vm"
  vm_name     = "k8s-w01"
  vm_id       = 111
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 2
  memory      = 8192
  disk_size   = 80
  ip_address  = var.ip_k8s_w01
  gateway     = var.gateway
  nameserver  = var.ip_ipa01
  ssh_keys    = [var.ssh_public_key]
  tags        = ["k8s", "worker", "awx", "gitlab"]
  datastore   = var.datastore
}

# ─── Worker Node 2 (Splunk + Monitoring) ─────────────────────────────────────
module "k8s_w02" {
  source      = "./modules/proxmox-vm"
  vm_name     = "k8s-w02"
  vm_id       = 112
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 2
  memory      = 8192
  disk_size   = 80
  ip_address  = var.ip_k8s_w02
  gateway     = var.gateway
  nameserver  = var.ip_ipa01
  ssh_keys    = [var.ssh_public_key]
  tags        = ["k8s", "worker", "splunk", "monitoring"]
  datastore   = var.datastore
}
