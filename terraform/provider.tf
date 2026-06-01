# terraform/provider.tf

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ASOP-SOC-Telemetry"
      ManagedBy   = "Terraform"
      Environment = "Development"
      Lab         = "Security-Observability"
    }
  }
}