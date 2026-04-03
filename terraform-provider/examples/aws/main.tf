terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    hardbox = {
      source  = "jackby03/hardbox"
      version = "~> 0.3"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "hardbox" {
  hardbox_version = "latest"
}

# ── EC2 instance ──────────────────────────────────────────────────────────────

resource "aws_instance" "web" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id              = var.subnet_id

  tags = {
    Name = "hardbox-demo"
  }
}

resource "aws_security_group" "web" {
  name        = "hardbox-demo-sg"
  description = "hardbox demo — SSH restricted to known CIDRs"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from bastion/VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── hardbox hardening ─────────────────────────────────────────────────────────

resource "hardbox_apply" "web" {
  host        = aws_instance.web.public_ip
  user        = "ubuntu"
  private_key = file(var.private_key_path)
  # Obtain with: ssh-keyscan -t ed25519 <ip> | awk '{print $3}'
  host_key    = var.host_public_key

  profile       = "cloud-aws"
  report_format = "json"

  fail_on_critical    = true
  fail_on_high        = true
  rollback_on_failure = true

  depends_on = [aws_instance.web]
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "instance_id" {
  value = aws_instance.web.id
}

output "hardbox_applied_at" {
  value = hardbox_apply.web.applied_at
}

output "hardbox_findings" {
  value = hardbox_apply.web.findings
}
