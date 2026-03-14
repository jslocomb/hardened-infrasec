terraform {
  required_version = ">= 1.6.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.70"
    }
  }

  # Uncomment once GitLab is running to store state remotely
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
  endpoint  = var.proxmox_api_url
  username  = var.proxmox_user
  password  = var.proxmox_password
  insecure  = var.proxmox_tls_insecure

  ssh {
    agent    = true
    username = "root"
  }
}

# ─── FreeIPA / Identity ───────────────────────────────────────────────────────
module "ipa01" {
  source      = "./modules/proxmox-vm"
  vm_name     = "ipa01"
  vm_id       = 101
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 2
  memory      = 4096
  disk_size   = 40
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
  cores       = 4
  memory      = 8192
  disk_size   = 80
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
  cores       = 6
  memory      = 16384
  disk_size   = 200
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
  cores       = 6
  memory      = 16384
  disk_size   = 200
  ip_address  = var.ip_k8s_w02
  gateway     = var.gateway
  nameserver  = var.ip_ipa01
  ssh_keys    = [var.ssh_public_key]
  tags        = ["k8s", "worker", "splunk", "monitoring"]
  datastore   = var.datastore
}

# ─── Worker Node 3 (NetBox + Zabbix) ─────────────────────────────────────────
module "k8s_w03" {
  source      = "./modules/proxmox-vm"
  vm_name     = "k8s-w03"
  vm_id       = 113
  target_node = var.proxmox_node
  template_id = var.vm_template_id
  cores       = 4
  memory      = 8192
  disk_size   = 100
  ip_address  = var.ip_k8s_w03
  gateway     = var.gateway
  nameserver  = var.ip_ipa01
  ssh_keys    = [var.ssh_public_key]
  tags        = ["k8s", "worker", "netbox", "zabbix"]
  datastore   = var.datastore
}
