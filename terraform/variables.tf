variable "proxmox_api_url" {
  description = "Proxmox API endpoint"
  type        = string
}

variable "proxmox_user" {
  description = "Proxmox API user (e.g. terraform@pam)"
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
  description = "Proxmox target node name"
  type        = string
  default     = "pve"
}

variable "vm_template" {
  description = "Proxmox VM template name for Rocky Linux 9"
  type        = string
  default     = "rocky9-template"
}

variable "ssh_public_keys" {
  description = "SSH public keys injected into VMs"
  type        = string
}

variable "gateway" {
  description = "Default gateway for all VMs"
  type        = string
  default     = "192.168.10.1"
}

variable "nameserver" {
  description = "Initial nameserver before FreeIPA is up"
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
