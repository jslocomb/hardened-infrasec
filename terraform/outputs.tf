output "vm_id" {
  value = proxmox_virtual_machine.vm.vm_id
}

output "vm_name" {
  value = proxmox_virtual_machine.vm.name
}

output "ip_address" {
  value = var.ip_address
}
