output "vm_id"   { value = proxmox_vm_qemu.vm.vmid }
output "vm_name" { value = proxmox_vm_qemu.vm.name }
output "ip"      { value = var.ip_address }
