output "ipa01_ip" {
  description = "FreeIPA VM IP address"
  value       = var.ip_ipa01
}

output "k8s_control_plane_ip" {
  description = "K8s control plane IP (RKE2 API)"
  value       = var.ip_k8s_cp01
}

output "k8s_worker_ips" {
  description = "K8s worker node IPs"
  value = {
    w01 = var.ip_k8s_w01
    w02 = var.ip_k8s_w02
    w03 = var.ip_k8s_w03
  }
}

output "ansible_inventory_hint" {
  description = "Reminder to update ansible/inventory/hosts.yml with these IPs"
  value       = "Update ansible/inventory/hosts.yml with the IPs above before running playbooks."
}
