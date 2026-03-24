resource "aws_instance" "node" {
  ami                    = var.ami
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  key_name               = var.key_name
  vpc_security_group_ids = [var.security_group]

  root_block_device {
    volume_size = var.disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name    = var.name
    Project = var.project
    Role    = var.role
  }
}
