variable "name" {
  description = "Instance name"
  type        = string
}

variable "ami" {
  description = "AMI ID"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID"
  type        = string
}

variable "key_name" {
  description = "EC2 key pair name"
  type        = string
}

variable "security_group" {
  description = "Security group ID"
  type        = string
}

variable "disk_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 30
}

variable "role" {
  description = "Node role tag"
  type        = string
}

variable "project" {
  description = "Project tag"
  type        = string
  default     = "homelab-k8s"
}
