variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR (bastion)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "Private subnet CIDR (lab nodes)"
  type        = string
  default     = "10.0.10.0/24"
}

variable "admin_cidr" {
  description = "Your home IP in CIDR notation for SSH access e.g. 1.2.3.4/32"
  type        = string
  sensitive   = true
}

variable "rocky9_ami" {
  description = "Rocky Linux 9 AMI ID for us-west-2"
  type        = string
  default     = "ami-002f381c4f976fe07"
}

variable "instance_type" {
  description = "EC2 instance type for lab nodes"
  type        = string
  default     = "t3.medium"
}

variable "ssh_public_key" {
  description = "SSH public key for EC2 key pair"
  type        = string
  sensitive   = true
}
