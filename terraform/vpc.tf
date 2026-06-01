# ==============================================================================
# AWS Network Infrastructure - ASOP Isolated Lab Environment
# ==============================================================================
# Low-tier design: Single public subnet for all instances (no NAT Gateway)
# All instances get public IPs for direct access and internet connectivity
# Security is enforced via Security Groups, not network isolation
# ==============================================================================

# ------------------------------------------------------------------------------
# VPC (Virtual Private Cloud)
# ------------------------------------------------------------------------------
resource "aws_vpc" "soc_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "asop-telemetry-vpc"
  }
}

# ------------------------------------------------------------------------------
# Internet Gateway (For public internet access)
# ------------------------------------------------------------------------------
resource "aws_internet_gateway" "soc_igw" {
  vpc_id = aws_vpc.soc_vpc.id

  tags = {
    Name = "asop-igw"
  }
}

# ------------------------------------------------------------------------------
# Subnets
# ------------------------------------------------------------------------------
# All instances share the same public subnet design (low-tier, no NAT)
# Security Groups provide the actual access control

# Subnet for Kali Linux (Attacker)
resource "aws_subnet" "kali_subnet" {
  vpc_id                  = aws_vpc.soc_vpc.id
  cidr_block              = var.kali_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "asop-kali-subnet"
  }
}

# Subnet for Sensor and SIEM (shared private subnet style but with public IPs)
resource "aws_subnet" "lab_subnet" {
  vpc_id                  = aws_vpc.soc_vpc.id
  cidr_block              = var.lab_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "asop-lab-subnet"
  }
}

# ------------------------------------------------------------------------------
# Route Tables
# ------------------------------------------------------------------------------

# Public route table with Internet Gateway route
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.soc_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.soc_igw.id
  }

  tags = {
    Name = "asop-public-rt"
  }
}

# ------------------------------------------------------------------------------
# Route Table Associations
# ------------------------------------------------------------------------------

# Associate Kali subnet with public route table
resource "aws_route_table_association" "kali_assoc" {
  subnet_id      = aws_subnet.kali_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Associate Lab subnet (Sensor + SIEM) with public route table
resource "aws_route_table_association" "lab_assoc" {
  subnet_id      = aws_subnet.lab_subnet.id
  route_table_id = aws_route_table.public_rt.id
}