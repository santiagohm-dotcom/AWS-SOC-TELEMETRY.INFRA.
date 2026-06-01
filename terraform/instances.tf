# ------------------------------------------------------------------------------
# AMI Discovery (Ubuntu 22.04 LTS Official)
# ------------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical official owner ID

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ------------------------------------------------------------------------------
# Node 1: Kali Linux (The Attacker) - Usando AMI ID directo
# ------------------------------------------------------------------------------
resource "aws_instance" "kali_node" {
  ami                         = "ami-003fa928ba1faa587" # Kali Linux AMI ID
  key_name                    = var.key_name
  instance_type               = var.instance_type_kali
  subnet_id                   = aws_subnet.kali_subnet.id
  vpc_security_group_ids      = [aws_security_group.kali_sg.id]
  associate_public_ip_address = true

  # No user_data - Kali se usa manualmente

  root_block_device {
    volume_size           = var.root_volume_size_kali
    volume_type           = var.root_volume_type
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "asop-kali-attacker"
  }
}


# ------------------------------------------------------------------------------
# Node 2: Detection Sensor (Depends on SIEM IP)
# ------------------------------------------------------------------------------
resource "aws_instance" "sensor_node" {
  ami                         = data.aws_ami.ubuntu.id
  key_name                    = var.key_name
  instance_type               = var.instance_type_sensor
  subnet_id                   = aws_subnet.lab_subnet.id
  vpc_security_group_ids      = [aws_security_group.sensor_sg.id]
  associate_public_ip_address = true

  iam_instance_profile = aws_iam_instance_profile.soc_instance_profile.name

  depends_on = [aws_instance.siem_node]

  user_data = base64gzip(<<-EOF
              #!/bin/bash
              ${file("${path.module}/scripts/install_sensor.sh")}
              
              SIEM_IP="${aws_instance.siem_node.private_ip}"
              echo "[ASOP] Configuring Filebeat to send logs to SIEM at: $${SIEM_IP}"
              
              sed -i "s/LOGSTASH_SERVER_IP/$${SIEM_IP}/g" /etc/filebeat/filebeat.yml
              systemctl restart filebeat
              
              echo "[ASOP] Sensor initialization complete. Logs shipping to $${SIEM_IP}:5044"
              EOF
  )

  root_block_device {
    volume_size           = var.root_volume_size_sensor
    volume_type           = var.root_volume_type
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "asop-detection-sensor"
  }
}

# ------------------------------------------------------------------------------
# Node 3: SIEM Core Hub (Must be created before sensor)
# ------------------------------------------------------------------------------
resource "aws_instance" "siem_node" {
  ami                         = data.aws_ami.ubuntu.id
  key_name                    = var.key_name
  instance_type               = var.instance_type_siem
  subnet_id                   = aws_subnet.lab_subnet.id
  vpc_security_group_ids      = [aws_security_group.siem_sg.id]
  associate_public_ip_address = true

  iam_instance_profile = aws_iam_instance_profile.soc_instance_profile.name

  user_data = base64gzip(file("${path.module}/scripts/install_siem.sh"))

  root_block_device {
    volume_size           = var.root_volume_size_siem
    volume_type           = var.root_volume_type
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "asop-siem-hub"
  }
}