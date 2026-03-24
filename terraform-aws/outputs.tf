output "bastion_public_ip" {
  description = "Bastion host public IP — SSH entry point"
  value       = aws_instance.bastion.public_ip
}

output "bastion_public_dns" {
  description = "Bastion host public DNS"
  value       = aws_instance.bastion.public_dns
}

output "ipa01_private_ip" {
  description = "FreeIPA server private IP"
  value       = module.ipa01.private_ip
}

output "k8s_cp01_private_ip" {
  description = "K8s control plane private IP"
  value       = module.k8s_cp01.private_ip
}

output "k8s_w01_private_ip" {
  description = "K8s worker 01 (GitLab) private IP"
  value       = module.k8s_w01.private_ip
}

output "k8s_w02_private_ip" {
  description = "K8s worker 02 (Splunk/monitoring) private IP"
  value       = module.k8s_w02.private_ip
}

output "ssh_config" {
  description = "Paste this into ~/.ssh/config"
  value       = <<-EOT
    Host bastion
        HostName ${aws_instance.bastion.public_ip}
        User rocky
        IdentityFile ~/.ssh/id_ed25519

    Host ipa01
        HostName ${module.ipa01.private_ip}
        User rocky
        ProxyJump bastion

    Host k8s-cp01
        HostName ${module.k8s_cp01.private_ip}
        User rocky
        ProxyJump bastion

    Host k8s-w01
        HostName ${module.k8s_w01.private_ip}
        User rocky
        ProxyJump bastion

    Host k8s-w02
        HostName ${module.k8s_w02.private_ip}
        User rocky
        ProxyJump bastion
  EOT
}
