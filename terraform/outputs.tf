output "ipa01_ip" {
  description = "FreeIPA VM IP address"
  value       = module.ipa01.ip_address
}

output "k8s_control_plane_ip" {
  description = "K8s control plane IP (RKE2 API :6443, join :9345)"
  value       = module.k8s_cp01.ip_address
}

output "k8s_worker_ips" {
  description = "K8s worker node IPs"
  value = {
    w01 = module.k8s_w01.ip_address
    w02 = module.k8s_w02.ip_address
    w03 = module.k8s_w03.ip_address
  }
}

output "ansible_inventory_hint" {
  description = "Reminder: update ansible/inventory/hosts.yml with these IPs before running playbooks"
  value       = "Update ansible/inventory/hosts.yml with the IPs above before running playbooks."
}
