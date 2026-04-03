variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "Ubuntu 22.04 LTS AMI ID for the target region."
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 key pair for SSH access."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the instance will be launched."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the EC2 instance."
  type        = string
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to reach SSH (port 22)."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "private_key_path" {
  description = "Local path to the SSH private key file."
  type        = string
  default     = "~/.ssh/id_rsa"
}

variable "host_public_key" {
  description = "Base64-encoded SSH public host key (from ssh-keyscan -t ed25519 <host> | awk '{print $3}')."
  type        = string
}
