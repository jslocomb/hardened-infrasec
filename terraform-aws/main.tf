terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "aws_availability_zones" "available" {
  state = "available"
}

# ─── VPC ──────────────────────────────────────────────────────────────────────

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "homelab-k8s-vpc"
    Project = "homelab-k8s"
  }
}

# ─── Internet Gateway ─────────────────────────────────────────────────────────

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name    = "homelab-k8s-igw"
    Project = "homelab-k8s"
  }
}

# ─── Subnets ──────────────────────────────────────────────────────────────────

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name    = "homelab-k8s-public"
    Project = "homelab-k8s"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name    = "homelab-k8s-private"
    Project = "homelab-k8s"
  }
}

# ─── Route Tables ─────────────────────────────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name    = "homelab-k8s-public-rt"
    Project = "homelab-k8s"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway for private subnet internet access
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name    = "homelab-k8s-nat-eip"
    Project = "homelab-k8s"
  }
}

resource "aws_nat_gateway" "lab" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name    = "homelab-k8s-nat"
    Project = "homelab-k8s"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.lab.id
  }

  tags = {
    Name    = "homelab-k8s-private-rt"
    Project = "homelab-k8s"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ─── Security Groups ──────────────────────────────────────────────────────────

# Bastion host — SSH from your IP only
resource "aws_security_group" "bastion" {
  name        = "homelab-k8s-bastion"
  description = "Bastion host - SSH access from admin IP"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "homelab-k8s-bastion-sg"
    Project = "homelab-k8s"
  }
}

# Lab nodes — SSH from bastion, inter-node communication
resource "aws_security_group" "lab_nodes" {
  name        = "homelab-k8s-nodes"
  description = "Lab cluster nodes"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description     = "SSH from bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  ingress {
    description = "All traffic within lab"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  # FreeIPA ports
  ingress {
    description = "FreeIPA LDAP"
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "FreeIPA LDAPS"
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "FreeIPA Kerberos TCP"
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "FreeIPA Kerberos UDP"
    from_port   = 88
    to_port     = 88
    protocol    = "udp"
    self        = true
  }

  ingress {
    description = "FreeIPA DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "FreeIPA DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    self        = true
  }

  # RKE2 ports
  ingress {
    description = "RKE2 API server"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "RKE2 etcd"
    from_port   = 2379
    to_port     = 2380
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "RKE2 supervisor"
    from_port   = 9345
    to_port     = 9345
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "Flannel VXLAN"
    from_port   = 8472
    to_port     = 8472
    protocol    = "udp"
    self        = true
  }

  ingress {
    description = "Kubelet metrics"
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    self        = true
  }

  # Web services from bastion (for accessing GitLab, Grafana, Splunk)
  ingress {
    description     = "HTTP from bastion"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  ingress {
    description     = "HTTPS from bastion"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "homelab-k8s-nodes-sg"
    Project = "homelab-k8s"
  }
}

# ─── Key Pair ─────────────────────────────────────────────────────────────────

resource "aws_key_pair" "lab" {
  key_name   = "homelab-k8s"
  public_key = var.ssh_public_key

  tags = {
    Name    = "homelab-k8s-key"
    Project = "homelab-k8s"
  }
}

# ─── Bastion Host ─────────────────────────────────────────────────────────────

resource "aws_instance" "bastion" {
  ami                    = var.rocky9_ami
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.bastion.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name    = "bastion"
    Project = "homelab-k8s"
    Role    = "bastion"
  }
}

# ─── Lab Nodes ────────────────────────────────────────────────────────────────

module "ipa01" {
  source         = "./modules/ec2-node"
  name           = "ipa01"
  ami            = var.rocky9_ami
  instance_type  = "t3.large"
  subnet_id      = aws_subnet.private.id
  key_name       = aws_key_pair.lab.key_name
  security_group = aws_security_group.lab_nodes.id
  disk_size      = 30
  role           = "freeipa"
  project        = "homelab-k8s"
}

module "k8s_cp01" {
  source         = "./modules/ec2-node"
  name           = "k8s-cp01"
  ami            = var.rocky9_ami
  instance_type  = var.instance_type
  subnet_id      = aws_subnet.private.id
  key_name       = aws_key_pair.lab.key_name
  security_group = aws_security_group.lab_nodes.id
  disk_size      = 50
  role           = "k8s-control-plane"
  project        = "homelab-k8s"
}

module "k8s_w01" {
  source         = "./modules/ec2-node"
  name           = "k8s-w01"
  ami            = var.rocky9_ami
  instance_type  = var.instance_type
  subnet_id      = aws_subnet.private.id
  key_name       = aws_key_pair.lab.key_name
  security_group = aws_security_group.lab_nodes.id
  disk_size      = 80
  role           = "k8s-worker-gitlab"
  project        = "homelab-k8s"
}

module "k8s_w02" {
  source         = "./modules/ec2-node"
  name           = "k8s-w02"
  ami            = var.rocky9_ami
  instance_type  = var.instance_type
  subnet_id      = aws_subnet.private.id
  key_name       = aws_key_pair.lab.key_name
  security_group = aws_security_group.lab_nodes.id
  disk_size      = 80
  role           = "k8s-worker-monitoring"
  project        = "homelab-k8s"
}

