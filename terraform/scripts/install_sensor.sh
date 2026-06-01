#!/bin/bash
# install_sensor.sh - ASOP Sensor Node (Suricata + Honeypots + Filebeat)
# Deploys IDS, honeypots (Cowrie/Dionaea) and ships logs to SIEM.

set -uo pipefail

DEBUG_LOG="/var/log/asop-debug.log"
HONEYPOT_HOME="/opt/asop-honeypots"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${DEBUG_LOG}"; }

exec > >(tee -a "${DEBUG_LOG}") 2>&1

log "=== ASOP Sensor Node Installation Started ==="

# Simple wait for apt to be ready (avoid lock issues)
sleep 5

# System update
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

# Install dependencies (separate commands to avoid failures)
apt-get install -y docker.io docker-compose curl jq net-tools ufw wget gnupg
apt-get install -y suricata

# Add Elastic repository for Filebeat
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -y
apt-get install -y filebeat

# Configure Docker
systemctl enable --now docker
usermod -aG docker ubuntu
chmod 666 /var/run/docker.sock

# Firewall rules (honeypot ports open to internet)
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp
ufw allow 2222/tcp          # Cowrie SSH
ufw allow 21/tcp            # Dionaea FTP
ufw allow 445/tcp           # Dionaea SMB
ufw allow 1433/tcp          # Dionaea MSSQL
echo "y" | ufw enable

# ============================================================================
# SURICATA IDS CONFIGURATION
# ============================================================================
log "Configuring Suricata..."

INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' 2>/dev/null || echo "eth0")
log "Detected interface: ${INTERFACE}"

mkdir -p /etc/suricata

cat > /etc/suricata/suricata.yaml << 'EOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"

default-log-dir: /var/log/suricata/

af-packet:
  - interface: INTERFACE_PLACEHOLDER
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow, stats]

default-rule-path: /etc/suricata/rules
rule-files:
  - local.rules

logging:
  default-log-level: notice
EOF

sed -i "s/INTERFACE_PLACEHOLDER/${INTERFACE}/g" /etc/suricata/suricata.yaml

# Simple local rules for testing
mkdir -p /etc/suricata/rules
cat > /etc/suricata/rules/local.rules << 'EOF'
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:9000001; rev:1;)
alert tcp any any -> any any (msg:"TCP Traffic Detected"; sid:9000002; rev:1;)
alert udp any any -> any any (msg:"UDP Traffic Detected"; sid:9000003; rev:1;)
EOF

# Validate configuration (non‑fatal)
if suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
    log "Suricata configuration is valid"
else
    log "ERROR: Suricata configuration invalid"
    suricata -T -c /etc/suricata/suricata.yaml
fi

systemctl enable suricata
systemctl restart suricata

if systemctl is-active --quiet suricata; then
    log "Suricata started successfully"
else
    log "WARNING: Suricata failed to start"
fi

# ============================================================================
# HONEYPOTS (Cowrie + Dionaea)
# ============================================================================
log "Setting up honeypots..."

mkdir -p ${HONEYPOT_HOME}/cowrie/var/log/cowrie
mkdir -p ${HONEYPOT_HOME}/cowrie/var/lib/cowrie
mkdir -p ${HONEYPOT_HOME}/dionaea/log
chmod -R 777 ${HONEYPOT_HOME}/cowrie/var

cat > ${HONEYPOT_HOME}/docker-compose.yml << 'EOF'
version: '3.8'
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: asop-cowrie
    restart: always
    ports: ["2222:2222"]
    volumes:
      - ./cowrie/var:/cowrie/cowrie-git/var
    networks: [asop-net]
  dionaea:
    image: dinotools/dionaea:latest
    container_name: asop-dionaea
    restart: always
    ports: ["21:21", "445:445", "1433:1433"]
    volumes:
      - ./dionaea/log:/opt/dionaea/var
    networks: [asop-net]
networks:
  asop-net:
    name: asop-net
EOF

cd ${HONEYPOT_HOME}
docker-compose up -d
log "Honeypots started"

# ============================================================================
# FILEBEAT CONFIGURATION
# ============================================================================
log "Configuring Filebeat..."

cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/asop-honeypots/cowrie/var/log/cowrie/*.json
  json.keys_under_root: true
  fields:
    event_type: cowrie

- type: log
  enabled: true
  paths:
    - /opt/asop-honeypots/dionaea/log/**/*.json
  json.keys_under_root: true
  fields:
    event_type: dionaea

- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  fields:
    event_type: suricata

output.logstash:
  hosts: ["LOGSTASH_SERVER_IP:5044"]

logging.level: info
EOF

systemctl enable filebeat
log "Filebeat configured (LOGSTASH_SERVER_IP will be replaced by Terraform)"

# ============================================================================
# HEALTH CHECK SCRIPT
# ============================================================================
mkdir -p /opt/asop-sensor
cat > /opt/asop-sensor/health.sh << 'EOF'
#!/bin/bash
echo "=== ASOP Sensor Health ==="
echo "Suricata: $(systemctl is-active suricata)"
echo "Docker: $(systemctl is-active docker)"
echo "Cowrie: $(docker ps --format '{{.Names}}' | grep -c asop-cowrie || echo 0) containers"
echo "Dionaea: $(docker ps --format '{{.Names}}' | grep -c asop-dionaea || echo 0) containers"
echo "Filebeat: $(systemctl is-active filebeat)"
echo "Last Suricata alerts:"
tail -5 /var/log/suricata/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert") | .alert.signature' 2>/dev/null | head -3 || echo "No alerts yet"
EOF

chmod +x /opt/asop-sensor/health.sh
ln -sf /opt/asop-sensor/health.sh /usr/local/bin/asop-sensor-health

log "=== Installation completed ==="
log "Run 'asop-sensor-health' to check status"