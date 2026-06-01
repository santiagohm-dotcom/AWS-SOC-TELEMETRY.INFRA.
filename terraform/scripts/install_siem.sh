#!/bin/bash
# install_siem.sh - ASOP SIEM Node (Elasticsearch, Logstash, Kibana, CLI dashboard)
# Centralized logging and alerting platform with a smart CLI dashboard.

set -euo pipefail

DEBUG_LOG="/var/log/asop-debug.log"
SCRIPT_NAME="install_siem.sh"
ASOP_HOME="/opt/asop-siem"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] [${SCRIPT_NAME}] ${message}" | tee -a "${DEBUG_LOG}"
}
log_info() { log "INFO" "$*"; }
log_error() { log "ERROR" "$*"; exit 1; }

exec > >(tee -a "${DEBUG_LOG}") 2>&1
log_info "=========================================="
log_info "ASOP SIEM Node Initialization Started"
log_info "=========================================="

# Root check
if [ "$EUID" -ne 0 ]; then
    log_error "Must be run as root"
fi

# Fetch AWS instance metadata (if available)
if command -v curl &>/dev/null; then
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || echo "unknown")
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "unknown")
else
    INSTANCE_ID="unknown"; PRIVATE_IP="unknown"; PUBLIC_IP="unknown"
fi
log_info "Instance: ${INSTANCE_ID} | Private: ${PRIVATE_IP} | Public: ${PUBLIC_IP}"

# Basic hardening
systemctl disable --now bluetooth.service cups.service avahi-daemon.service snapd.service 2>/dev/null || true
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Wait for any pending apt operation
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 5; done

# System update and dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y
apt-get install -y apt-transport-https wget gnupg2 curl sed openjdk-17-jre-headless net-tools jq ufw python3 python3-pip software-properties-common
pip3 install requests --quiet

# Kernel tuning for Elasticsearch
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# Firewall rules
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 5601/tcp comment 'Kibana'
ufw allow 5044/tcp comment 'Logstash beats'
ufw --force enable

# Add Elastic Stack repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -y

# Install Elasticsearch, Logstash, Kibana
apt-get install -y elasticsearch logstash kibana

# ============================================================================
# ELASTICSEARCH (single node, security disabled for lab)
# ============================================================================
systemctl stop elasticsearch
rm -rf /var/lib/elasticsearch/*
cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: asop-lab
node.name: asop-siem-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
action.destructive_requires_name: false
EOF

mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options << 'EOF'
-Xms1g
-Xmx1g
EOF
sed -i '/^-Xms/d' /etc/elasticsearch/jvm.options 2>/dev/null || true
sed -i '/^-Xmx/d' /etc/elasticsearch/jvm.options 2>/dev/null || true
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch /etc/elasticsearch

systemctl enable elasticsearch
systemctl start elasticsearch
log_info "Waiting for Elasticsearch to be ready..."
sleep 30
curl -s http://localhost:9200 > /dev/null || log_error "Elasticsearch failed to start"

# ============================================================================
# LOGSTASH
# ============================================================================
mkdir -p /etc/logstash/conf.d /etc/logstash/jvm.options.d
cat > /etc/logstash/jvm.options.d/heap.options << 'EOF'
-Xms512m
-Xmx512m
EOF

# Beats input from sensor
cat > /etc/logstash/conf.d/01-beats-input.conf << 'EOF'
input {
  beats {
    port => 5044
    host => "0.0.0.0"
    ssl => false
  }
}
EOF

# Filters (suricata, cowrie, dionaea)
cat > /etc/logstash/conf.d/02-filters.conf << 'EOF'
filter {
  json { source => "message" target => "parsed" skip_on_invalid_json => true }
  mutate {
    add_field => { "[asop][ingest_timestamp]" => "%{@timestamp}" }
    remove_field => ["message", "parsed", "input", "ecs", "agent", "host", "log"]
  }
  if [fields][event_type] == "suricata" {
    mutate { add_tag => ["ids", "suricata"] }
    date { match => ["[parsed][timestamp]", "ISO8601"] target => "@timestamp" timezone => "UTC" }
    mutate {
      rename => ["[parsed][src_ip]", "[source][ip]"]
      rename => ["[parsed][dest_ip]", "[destination][ip]"]
      rename => ["[parsed][src_port]", "[source][port]"]
      rename => ["[parsed][dest_port]", "[destination][port]"]
      rename => ["[parsed][proto]", "[network][protocol]"]
      rename => ["[parsed][alert][signature]", "[alert][signature]"]
      rename => ["[parsed][alert][severity]", "[alert][severity]"]
    }
  }
  if [fields][event_type] == "cowrie" {
    mutate { add_tag => ["honeypot", "ssh", "cowrie"] }
    date { match => ["[parsed][timestamp]", "ISO8601"] target => "@timestamp" }
    mutate {
      rename => ["[parsed][eventid]", "[honeypot][cowrie][event_id]"]
      rename => ["[parsed][username]", "[honeypot][cowrie][username]"]
      rename => ["[parsed][password]", "[honeypot][cowrie][password]"]
      rename => ["[parsed][src_ip]", "[source][ip]"]
    }
  }
  if [fields][event_type] == "dionaea" {
    mutate { add_tag => ["honeypot", "dionaea"] }
    date { match => ["[parsed][timestamp]", "ISO8601"] target => "@timestamp" }
    mutate {
      rename => ["[parsed][connection][remote_host]", "[source][ip]"]
      rename => ["[parsed][connection][remote_port]", "[source][port]"]
      rename => ["[parsed][connection][local_port]", "[destination][port]"]
    }
  }
}
EOF

# Output to Elasticsearch
cat > /etc/logstash/conf.d/30-elasticsearch-output.conf << 'EOF'
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "asop-logs-%{+YYYY.MM.dd}"
    manage_template => true
    template_name => "asop-logs-template"
    template_overwrite => true
  }
}
EOF

chown -R logstash:logstash /etc/logstash/conf.d /var/log/logstash

systemctl enable logstash
systemctl start logstash
sleep 15
systemctl is-active --quiet logstash || log_error "Logstash failed to start"

# ============================================================================
# KIBANA
# ============================================================================
cat > /etc/kibana/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
telemetry.enabled: false
EOF

systemctl enable kibana
systemctl start kibana
sleep 20

# ============================================================================
# ELASTICSEARCH INDEX TEMPLATE
# ============================================================================
sleep 10
curl -X PUT "localhost:9200/_index_template/asop-logs-template" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["asop-logs-*"],
  "priority": 100,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "alert": { "properties": { "signature": { "type": "text" }, "severity": { "type": "integer" } } },
        "source": { "type": "object" },
        "destination": { "type": "object" }
      }
    }
  }
}' 2>/dev/null || log_info "Could not create index template (may already exist)"

# ============================================================================
# SOC CLI DASHBOARD (filters non‑alert events)
# ============================================================================
log_info "Installing SOC CLI Dashboard (intelligent filtering)..."

mkdir -p ${ASOP_HOME}
cat > ${ASOP_HOME}/soc_cli_dashboard.py << 'EOFPYTHON'
#!/usr/bin/env python3
# ASOP Security Assistant - CLI Dashboard (shows only real alerts)
import requests, json, sys, time, argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

ELASTICSEARCH_HOST = "http://localhost:9200"
INDEX_PATTERN = "asop-logs-*"
HEADERS = {"Content-Type": "application/json"}

SEVERITY_ICONS = {1: "🔴 CRITICAL", 2: "🟠 HIGH", 3: "🟡 MEDIUM", 4: "🔵 LOW", 5: "⚪ INFO"}

class Colors:
    HEADER, CYAN, GREEN, WARNING, FAIL, END, BOLD, DIM = \
        '\033[95m', '\033[96m', '\033[92m', '\033[93m', '\033[91m', '\033[0m', '\033[1m', '\033[2m'

def translate_suricata_event(source: Dict) -> Optional[str]:
    alert = source.get('alert')
    if not alert:
        return None
    sig = alert.get('signature', 'Unknown')
    sev = alert.get('severity', 3)
    return f"⚠️ [IDS] {SEVERITY_ICONS.get(sev, '')} | {sig[:80]}"

def translate_cowrie_event(source: Dict) -> str:
    user = source.get('username', 'unknown')
    src = source.get('src_ip', source.get('source', {}).get('ip', 'unknown'))
    return f"🔑 [SSH Honeypot] Login attempt as '{user}' from {src}"

def translate_dionaea_event(source: Dict) -> str:
    port = source.get('dest_port', source.get('destination', {}).get('port', 'unknown'))
    src = source.get('src_ip', source.get('source', {}).get('ip', 'unknown'))
    return f"🪤 [Dionaea] Connection from {src} on port {port}"

def translate_system_event(source: Dict) -> str:
    msg = source.get('message', '')
    if 'Failed password' in msg:
        import re
        u = re.search(r'for (invalid user )?(\S+)', msg)
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        return f"🔑 [System] SSH brute force from {ip.group(1) if ip else '?'} as '{u.group(2) if u else '?'}'"
    return f"📋 [System] {msg[:80]}"

def translate_event(source: Dict, log_source: str) -> Optional[str]:
    if log_source == 'suricata': return translate_suricata_event(source)
    if log_source == 'cowrie':   return translate_cowrie_event(source)
    if log_source == 'dionaea':  return translate_dionaea_event(source)
    if log_source == 'system':   return translate_system_event(source)
    return None

def get_network_context(source: Dict) -> Tuple[str, str, str, str]:
    src_ip = source.get('source', {}).get('ip') or source.get('src_ip', 'N/A')
    src_port = source.get('source', {}).get('port') or source.get('src_port', 'N/A')
    dst_ip = source.get('destination', {}).get('ip') or source.get('dest_ip', 'N/A')
    dst_port = source.get('destination', {}).get('port') or source.get('dest_port', 'N/A')
    if src_ip == 'N/A':
        src_ip = source.get('src_ip', 'N/A')
        dst_ip = source.get('dest_ip', 'N/A')
        src_port = source.get('src_port', 'N/A')
        dst_port = source.get('dest_port', 'N/A')
    return str(src_ip), str(src_port), str(dst_ip), str(dst_port)

def print_header():
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}🛡️  ASOP Security Assistant - Real-Time Threat Dashboard{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.DIM}Only security alerts (IDS, honeypots, auth failures) are shown{Colors.END}\n")

def print_event(event: Dict, idx):
    src = event.get('_source', {})
    ts = src.get('@timestamp', datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        time_str = dt.strftime('%H:%M:%S')
        date_str = dt.strftime('%Y-%m-%d')
    except:
        time_str = ts[11:19] if len(ts) > 19 else ts
        date_str = ts[:10] if len(ts) > 10 else 'N/A'

    log_source = src.get('fields', {}).get('event_type', src.get('event_type', 'unknown'))
    sensor = src.get('fields', {}).get('sensor_id', src.get('sensor_id', 'unknown'))
    sip, sport, dip, dport = get_network_context(src)
    intelligence = translate_event(src, log_source)
    if intelligence is None:
        return

    color = Colors.FAIL if 'CRITICAL' in intelligence or '🔴' in intelligence else (Colors.WARNING if 'HIGH' in intelligence or '🟠' in intelligence else Colors.CYAN)
    print(f"{Colors.BOLD}[{idx}]{Colors.END} {Colors.GREEN}{date_str} {time_str}{Colors.END}")
    print(f"   📍 Source: {log_source.upper()} | Sensor: {sensor}")
    print(f"   🌐 Network: {sip}:{sport} → {dip}:{dport}")
    print(f"   {color}{intelligence}{Colors.END}\n")

def query_elasticsearch(query_body: Dict) -> Optional[Tuple[List, int]]:
    url = f"{ELASTICSEARCH_HOST}/{INDEX_PATTERN}/_search"
    try:
        resp = requests.post(url, json=query_body, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('hits', {}).get('hits', []), data.get('hits', {}).get('total', {}).get('value', 0)
        else:
            print(f"{Colors.FAIL}❌ Elasticsearch error: HTTP {resp.status_code}{Colors.END}")
            return None, 0
    except Exception as e:
        print(f"{Colors.FAIL}❌ Connection error: {e}{Colors.END}")
        return None, 0

def show_last_events(limit: int = 10):
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "alert"}},
                    {"term": {"fields.event_type": "cowrie"}},
                    {"term": {"fields.event_type": "dionaea"}},
                    {"term": {"fields.event_type": "system"}}
                ]
            }
        }
    }
    result = query_elasticsearch(query)
    if result is None:
        return
    hits, total = result
    print_header()
    if total == 0:
        print(f"{Colors.WARNING}⚠️ No security alerts found in Elasticsearch{Colors.END}")
        print(f"{Colors.DIM}   Waiting for sensor to send logs...{Colors.END}\n")
        return
    print(f"{Colors.DIM}Total alerts: {total} | Showing: {len(hits)} most recent{Colors.END}\n")
    displayed = 0
    for i, hit in enumerate(hits, 1):
        src = hit.get('_source', {})
        if src.get('fields', {}).get('event_type') == 'suricata' and not src.get('alert'):
            continue
        print_event(hit, i)
        displayed += 1
    if displayed == 0:
        print(f"{Colors.WARNING}⚠️ No alert events to display (non‑alert logs were filtered).{Colors.END}")

def follow_events(interval: int = 5):
    print_header()
    print(f"{Colors.GREEN}📡 Streaming live security alerts (Ctrl+C to stop){Colors.END}\n")
    last_ts = None
    try:
        while True:
            query = {
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "should": [
                            {"exists": {"field": "alert"}},
                            {"term": {"fields.event_type": "cowrie"}},
                            {"term": {"fields.event_type": "dionaea"}}
                        ]
                    }
                }
            }
            if last_ts:
                query["query"]["bool"]["filter"] = {"range": {"@timestamp": {"gt": last_ts}}}
            result = query_elasticsearch(query)
            if result:
                hits, _ = result
                for hit in reversed(hits):
                    ts = hit.get('_source', {}).get('@timestamp', '')
                    if ts != last_ts:
                        src = hit.get('_source', {})
                        if src.get('alert') or src.get('fields', {}).get('event_type') in ('cowrie', 'dionaea'):
                            print_event(hit, "•")
                            last_ts = ts
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 Stopped streaming.{Colors.END}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-l', '--limit', type=int, default=10)
    p.add_argument('-f', '--follow', action='store_true')
    args = p.parse_args()
    if args.follow:
        follow_events()
    else:
        show_last_events(args.limit)

if __name__ == "__main__":
    main()
EOFPYTHON

chmod +x ${ASOP_HOME}/soc_cli_dashboard.py
ln -sf ${ASOP_HOME}/soc_cli_dashboard.py /usr/local/bin/asop-dashboard

# ============================================================================
# HEALTH CHECK SCRIPT
# ============================================================================
cat > ${ASOP_HOME}/health.sh << 'EOF'
#!/bin/bash
echo "=== ASOP SIEM Health ==="
echo "Elasticsearch: $(systemctl is-active elasticsearch)"
echo "Logstash: $(systemctl is-active logstash)"
echo "Kibana: $(systemctl is-active kibana)"
echo "Dashboard CLI: $(which asop-dashboard 2>/dev/null && echo 'installed' || echo 'missing')"
echo ""
echo "Kibana URL: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null):5601"
echo ""
echo "Total alerts in Elasticsearch:"
curl -s "http://localhost:9200/_cat/indices/asop-logs-*?h=docs.count" 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0"
EOF

chmod +x ${ASOP_HOME}/health.sh
ln -sf ${ASOP_HOME}/health.sh /usr/local/bin/asop-health

# ============================================================================
# FINAL
# ============================================================================
log_info "=========================================="
log_info "ASOP SIEM Node Installation Complete"
log_info "=========================================="
log_info "Kibana: http://${PUBLIC_IP}:5601"
log_info "Commands: asop-dashboard, asop-health"
log_info "Debug log: ${DEBUG_LOG}"