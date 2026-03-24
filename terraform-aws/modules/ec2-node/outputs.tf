output "private_ip" {
  description = "Instance private IP"
  value       = aws_instance.node.private_ip
}

output "instance_id" {
  description = "Instance ID"
  value       = aws_instance.node.id
}
