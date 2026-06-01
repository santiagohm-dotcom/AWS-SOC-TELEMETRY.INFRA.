# ==============================================================================
# ASOP Global Infrastructure Variables
# ==============================================================================

# ------------------------------------------------------------------------------
# AWS Region
# ------------------------------------------------------------------------------
variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "Target AWS region for the entire ASOP deployment"
}

# ------------------------------------------------------------------------------
# Networking
# ------------------------------------------------------------------------------
variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "Base CIDR block for the ASOP VPC"
}

variable "kali_subnet_cidr" {
  type        = string
  default     = "10.0.10.0/24"
  description = "CIDR block for Kali Linux (Attacker subnet)"
}

variable "lab_subnet_cidr" {
  type        = string
  default     = "10.0.20.0/24"
  description = "CIDR block for Sensor and SIEM (Defensive subnet)"
}

# ------------------------------------------------------------------------------
# Security
# ------------------------------------------------------------------------------
variable "my_public_ip" {
  type        = string
  description = "Your local public IP address with CIDR mask (e.g., '190.68.100.50/32') for SSH and Kibana access"

  validation {
    condition     = can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", var.my_public_ip))
    error_message = "my_public_ip must be a valid CIDR format (e.g., '203.0.113.45/32')"
  }
}

variable "key_name" {
  type        = string
  description = "The name of the SSH key pair registered in AWS"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.key_name))
    error_message = "key_name must contain only letters, numbers, underscores, and hyphens"
  }
}

# ------------------------------------------------------------------------------
# Instance Types (Optimized for low-tier / portafolio)
# ------------------------------------------------------------------------------
variable "instance_type_siem" {
  type        = string
  default     = "t3.medium"
  description = "EC2 instance type for SIEM node (needs 4GB+ RAM for Elasticsearch)"
}

variable "instance_type_sensor" {
  type        = string
  default     = "t3.micro"
  description = "EC2 instance type for Sensor node (Suricata + Docker honeypots)"
}

variable "instance_type_kali" {
  type        = string
  default     = "t3.micro"
  description = "EC2 instance type for Kali Linux (attacker node)"
}

# ------------------------------------------------------------------------------
# Storage (EBS Volumes)
# ------------------------------------------------------------------------------
variable "root_volume_size_siem" {
  type        = number
  default     = 30
  description = "Root EBS volume size in GB for SIEM node"
}

variable "root_volume_size_sensor" {
  type        = number
  default     = 20
  description = "Root EBS volume size in GB for Sensor node"
}

variable "root_volume_size_kali" {
  type        = number
  default     = 25
  description = "Root EBS volume size in GB for Kali node"
}

variable "root_volume_type" {
  type        = string
  default     = "gp3"
  description = "EBS volume type (gp3 is cost-effective for labs)"

  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.root_volume_type)
    error_message = "root_volume_type must be gp2, gp3, io1, or io2"
  }
}