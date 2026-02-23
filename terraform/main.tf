terraform {
  required_version = ">= 1.6.0"
  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
      version = "~> 2.9"
    }
  }
  # Uncomment to use remote state (recommended)
  # backend "http" {
  #   address        = "https://gitlab.lab.internal/api/v4/projects/<id>/terraform/state/homelab"
  #   lock_address   = "https://gitlab.lab.internal/api/v4/projects/<id>/terraform/state/homelab/lock"
  #   unlock_address = "https://gitlab.lab.internal/api/v4/projects/<id>/terraform/state/homelab/lock"
  #   username       = "terraform"
  #   password       = var.gitlab_token
  #   lock_method    = "POST"
  #   unlock_method  = "DELETE"
  # }
}

provider "proxmox" {
  pm_api_url      = var.proxmox_api_url
  pm_user         = var.proxmox_user
  pm_password     = var.proxmox_password
  pm_tls_insecure = var.proxmox_tls_insecure
}

# ─── FreeIPA VM ───────────────────────────────────────────────────────────────
module "ipa01" {
  source       = "./modules/proxmox-vm"
  vm_name      = "ipa01"
  vm_id        = 101
  target_node  = var.proxmox_node
  template     = var.vm_template
  cores        = 2
  memory       = 4096
  disk_size    = "40G"
  ip_address   = var.ip_ipa01
  gateway      = var.gateway
  nameserver   = var.nameserver
  ssh_keys     = var.ssh_public_keys
  tags         = ["freeipa", "auth"]
}

# ─── K8s Control Plane ────────────────────────────────────────────────────────
module "k8s_cp01" {
  source       = "./modules/proxmox-vm"
  vm_name      = "k8s-cp01"
  vm_id        = 110
  target_node  = var.proxmox_node
  template     = var.vm_template
  cores        = 4
  memory       = 8192
  disk_size    = "80G"
  ip_address   = var.ip_k8s_cp01
  gateway      = var.gateway
  nameserver   = var.ip_ipa01
  ssh_keys     = var.ssh_public_keys
  tags         = ["k8s", "control-plane"]
}

# ─── Worker Node 1 ────────────────────────────────────────────────────────────
module "k8s_w01" {
  source       = "./modules/proxmox-vm"
  vm_name      = "k8s-w01"
  vm_id        = 111
  target_node  = var.proxmox_node
  template     = var.vm_template
  cores        = 6
  memory       = 16384
  disk_size    = "200G"
  ip_address   = var.ip_k8s_w01
  gateway      = var.gateway
  nameserver   = var.ip_ipa01
  ssh_keys     = var.ssh_public_keys
  tags         = ["k8s", "worker", "awx", "gitlab"]
}

# ─── Worker Node 2 ────────────────────────────────────────────────────────────
module "k8s_w02" {
  source       = "./modules/proxmox-vm"
  vm_name      = "k8s-w02"
  vm_id        = 112
  target_node  = var.proxmox_node
  template     = var.vm_template
  cores        = 6
  memory       = 16384
  disk_size    = "200G"
  ip_address   = var.ip_k8s_w02
  gateway      = var.gateway
  nameserver   = var.ip_ipa01
  ssh_keys     = var.ssh_public_keys
  tags         = ["k8s", "worker", "splunk", "monitoring"]
}

# ─── Worker Node 3 ────────────────────────────────────────────────────────────
module "k8s_w03" {
  source       = "./modules/proxmox-vm"
  vm_name      = "k8s-w03"
  vm_id        = 113
  target_node  = var.proxmox_node
  template     = var.vm_template
  cores        = 4
  memory       = 8192
  disk_size    = "100G"
  ip_address   = var.ip_k8s_w03
  gateway      = var.gateway
  nameserver   = var.ip_ipa01
  ssh_keys     = var.ssh_public_keys
  tags         = ["k8s", "worker", "netbox", "zabbix"]
}
