variable "proxmox_api_url" {
  description = "Proxmox API endpoint — e.g. https://192.168.1.100:8006"
  type        = string
}

variable "proxmox_user" {
  description = "Proxmox API user — e.g. terraform@pam"
  type        = string
  default     = "terraform@pam"
}

variable "proxmox_password" {
  description = "Proxmox API password"
  type        = string
  sensitive   = true
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification for self-signed Proxmox cert"
  type        = bool
  default     = true
}

variable "proxmox_node" {
  description = "Proxmox target node name — check top-left in Proxmox UI, usually 'pve'"
  type        = string
  default     = "pve"
}

# bpg/proxmox clones by VM ID, not name
variable "vm_template_id" {
  description = "VM ID of the Rocky Linux 9 cloud-init template (created in step 1.8-1.12)"
  type        = number
  default     = 9000
}

variable "datastore" {
  description = "Proxmox storage pool for VM disks — check Proxmox UI > Datacenter > Storage"
  type        = string
  default     = "local-lvm"
}

variable "ssh_public_key" {
  description = "SSH public key injected into VMs via cloud-init — output of: cat ~/.ssh/id_ed25519.pub"
  type        = string
}

variable "gateway" {
  description = "Default gateway for all lab VMs — Proxmox vmbr1 address"
  type        = string
  default     = "192.168.10.1"
}

variable "nameserver" {
  description = "Initial DNS server before FreeIPA is running — use gateway or a public resolver"
  type        = string
  default     = "192.168.10.1"
}

# ─── IP Addresses ─────────────────────────────────────────────────────────────

variable "ip_ipa01" {
  description = "FreeIPA VM static IP"
  type        = string
  default     = "192.168.10.5"
}

variable "ip_k8s_cp01" {
  description = "K8s control plane static IP"
  type        = string
  default     = "192.168.10.10"
}

variable "ip_k8s_w01" {
  description = "K8s worker 1 static IP"
  type        = string
  default     = "192.168.10.11"
}

variable "ip_k8s_w02" {
  description = "K8s worker 2 static IP"
  type        = string
  default     = "192.168.10.12"
}

variable "ip_k8s_w03" {
  description = "K8s worker 3 static IP"
  type        = string
  default     = "192.168.10.13"
}
