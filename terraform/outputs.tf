# ==============================================================================
# ASOP SOC Lab Outputs
# ==============================================================================

# ------------------------------------------------------------------------------
# Node 1: Kali Linux (Attacker)
# ------------------------------------------------------------------------------
output "kali_public_ip" {
  value       = aws_instance.kali_node.public_ip
  description = "Kali Linux public IP for SSH access"
}

output "kali_private_ip" {
  value       = aws_instance.kali_node.private_ip
  description = "Kali Linux private IP within VPC"
}

# ------------------------------------------------------------------------------
# Node 2: Detection Sensor (Honeypots + Suricata + Filebeat)
# ------------------------------------------------------------------------------
output "sensor_public_ip" {
  value       = aws_instance.sensor_node.public_ip
  description = "Sensor node public IP for SSH and honeypot access"
}

output "sensor_private_ip" {
  value       = aws_instance.sensor_node.private_ip
  description = "Sensor node private IP (used for internal communication)"
}

# ------------------------------------------------------------------------------
# Node 3: SIEM Core Hub (Elasticsearch + Logstash + Kibana)
# ------------------------------------------------------------------------------
output "siem_public_ip" {
  value       = aws_instance.siem_node.public_ip
  description = "SIEM node public IP for SSH and Kibana access"
}

output "siem_private_ip" {
  value       = aws_instance.siem_node.private_ip
  description = "SIEM private IP - configure this as LOGSTASH_SERVER_IP in sensor"
}

# ------------------------------------------------------------------------------
# Web Interfaces
# ------------------------------------------------------------------------------
output "kibana_url" {
  value       = "http://${aws_instance.siem_node.public_ip}:5601"
  description = "Kibana dashboard URL (open in browser)"
}