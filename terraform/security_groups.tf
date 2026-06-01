# ==============================================================================
# AWS Security Groups - ASOP Micro-Segmented Lab Control
# ==============================================================================

# ------------------------------------------------------------------------------
# Security Group for Node 1: Kali Linux (The Attacker)
# ------------------------------------------------------------------------------
resource "aws_security_group" "kali_sg" {
  name        = "asop-kali-sg"
  description = "Security group for Kali Linux attack node"
  vpc_id      = aws_vpc.soc_vpc.id

  ingress {
    description = "SSH access from your public IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_public_ip]
  }

  # Outbound: Kali needs full internet access for tools and updates
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "asop-kali-sg"
  }
}

# ------------------------------------------------------------------------------
# Security Group for Node 2: Detection Sensor (Honeypots + Suricata)
# ------------------------------------------------------------------------------
resource "aws_security_group" "sensor_sg" {
  name        = "asop-sensor-sg"
  description = "Security group for Detection Sensor with honeypots"
  vpc_id      = aws_vpc.soc_vpc.id

  # Management
  ingress {
    description = "SSH management from your public IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_public_ip]
  }

  # Honeypot ports exposed to internet (threat intelligence gathering)
  ingress {
    description = "Cowrie SSH honeypot (public)"
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Dionaea FTP honeypot (public)"
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Dionaea SMB honeypot (public)"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Dionaea MSSQL honeypot (public)"
    from_port   = 1433
    to_port     = 1433
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Optional: Full attack simulation from Kali (for testing)
  ingress {
    description     = "Allow all attack traffic from Kali for testing"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.kali_sg.id]
  }

  # Outbound: Sensor needs internet for updates and to send logs to SIEM
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "asop-sensor-sg"
  }
}

# ------------------------------------------------------------------------------
# Security Group for Node 3: SIEM Core Hub (Elasticsearch + Logstash + Kibana)
# ------------------------------------------------------------------------------
resource "aws_security_group" "siem_sg" {
  name        = "asop-siem-sg"
  description = "Security group for Elasticsearch, Logstash, and Kibana"
  vpc_id      = aws_vpc.soc_vpc.id

  # Management
  ingress {
    description = "SSH management from your public IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_public_ip]
  }

  # Kibana web interface
  ingress {
    description = "Kibana dashboard access from your public IP only"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = [var.my_public_ip]
  }

  # Logstash beats input (receives logs from sensor)
  ingress {
    description     = "Logstash Beats input from Sensor SG only"
    from_port       = 5044
    to_port         = 5044
    protocol        = "tcp"
    security_groups = [aws_security_group.sensor_sg.id]
  }

  # Optional: Elasticsearch API (for debugging, restrict to internal)
  ingress {
    description     = "Elasticsearch API access from Sensor only"
    from_port       = 9200
    to_port         = 9200
    protocol        = "tcp"
    security_groups = [aws_security_group.sensor_sg.id]
  }

  # Outbound: SIEM needs internet for updates and optional integrations
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "asop-siem-sg"
  }
}