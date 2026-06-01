#!/usr/bin/env python3
# soc_cli_dashboard.py - ASOP Security Assistant
# CLI dashboard that translates Elasticsearch logs into human-readable alerts.

import requests
import json
import sys
import time
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

ELASTICSEARCH_HOST = "http://localhost:9200"
INDEX_PATTERN = "asop-logs-*"
HEADERS = {"Content-Type": "application/json"}

SEVERITY_ICONS = {
    1: "🔴 CRITICAL",
    2: "🟠 HIGH",
    3: "🟡 MEDIUM",
    4: "🔵 LOW",
    5: "⚪ INFO"
}

class Colors:
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def translate_suricata_event(source: Dict) -> Optional[str]:
    """Translate Suricata alert into human-readable string. Return None if not an alert."""
    alert = source.get('alert')
    if not alert:
        return None
    signature = alert.get('signature', 'Unknown signature')
    severity = alert.get('severity', 3)
    icon = SEVERITY_ICONS.get(severity, "⚪ UNKNOWN")
    return f"⚠️ [IDS] {icon} | {signature[:80]}"

def translate_cowrie_event(source: Dict) -> str:
    username = source.get('username', 'unknown')
    src_ip = source.get('src_ip', source.get('source', {}).get('ip', 'unknown'))
    return f"🔑 [SSH Honeypot] Login attempt as '{username}' from {src_ip}"

def translate_dionaea_event(source: Dict) -> str:
    dest_port = source.get('dest_port', source.get('destination', {}).get('port', 'unknown'))
    src_ip = source.get('src_ip', source.get('source', {}).get('ip', 'unknown'))
    return f"🪤 [Dionaea] Connection from {src_ip} on port {dest_port}"

def translate_system_event(source: Dict) -> str:
    message = source.get('message', '')
    if 'Failed password' in message:
        import re
        user_match = re.search(r'for (invalid user )?(\S+)', message)
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        user = user_match.group(2) if user_match else 'unknown'
        ip = ip_match.group(1) if ip_match else 'unknown'
        return f"🔑 [System] SSH brute force from {ip} as '{user}'"
    return f"📋 [System] {message[:80]}"

def translate_event(source: Dict, log_source: str) -> Optional[str]:
    if log_source == 'suricata':
        return translate_suricata_event(source)
    elif log_source == 'cowrie':
        return translate_cowrie_event(source)
    elif log_source == 'dionaea':
        return translate_dionaea_event(source)
    elif log_source == 'system':
        return translate_system_event(source)
    else:
        # Unknown source – skip or show generic
        return None

def get_network_context(source: Dict) -> Tuple[str, str, str, str]:
    src_ip = source.get('source', {}).get('ip') or source.get('src_ip', 'N/A')
    src_port = source.get('source', {}).get('port') or source.get('src_port', 'N/A')
    dest_ip = source.get('destination', {}).get('ip') or source.get('dest_ip', 'N/A')
    dest_port = source.get('destination', {}).get('port') or source.get('dest_port', 'N/A')
    # Fallback for Suricata alerts (src/dest are top-level)
    if src_ip == 'N/A':
        src_ip = source.get('src_ip', 'N/A')
        dest_ip = source.get('dest_ip', 'N/A')
        src_port = source.get('src_port', 'N/A')
        dest_port = source.get('dest_port', 'N/A')
    return str(src_ip), str(src_port), str(dest_ip), str(dest_port)

def print_header():
    print()
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}🛡️  ASOP Security Assistant - Real-Time Threat Dashboard{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.DIM}Only security alerts are shown (IDS, honeypots, auth failures){Colors.END}")
    print()

def print_event(event: Dict, index: int):
    source = event.get('_source', {})
    timestamp = source.get('@timestamp', datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        time_str = dt.strftime('%H:%M:%S')
        date_str = dt.strftime('%Y-%m-%d')
    except:
        time_str = timestamp[11:19] if len(timestamp) > 19 else timestamp
        date_str = timestamp[:10] if len(timestamp) > 10 else 'N/A'

    fields = source.get('fields', {})
    log_source = fields.get('event_type', source.get('event_type', 'unknown'))
    sensor_id = fields.get('sensor_id', source.get('sensor_id', 'unknown'))

    src_ip, src_port, dest_ip, dest_port = get_network_context(source)
    intelligence = translate_event(source, log_source)

    if intelligence is None:
        return  # skip non-alert events

    # Color based on severity or content
    if 'CRITICAL' in intelligence or '🔴' in intelligence:
        color = Colors.FAIL
    elif 'HIGH' in intelligence or '🟠' in intelligence:
        color = Colors.WARNING
    else:
        color = Colors.CYAN

    print(f"{Colors.BOLD}[{index}]{Colors.END} {Colors.GREEN}{date_str} {time_str}{Colors.END}")
    print(f"   📍 Source: {log_source.upper()} | Sensor: {sensor_id}")
    print(f"   🌐 Network: {src_ip}:{src_port} → {dest_ip}:{dest_port}")
    print(f"   {color}{intelligence}{Colors.END}")
    print()

def query_elasticsearch(query_body: Dict) -> Optional[Tuple[List, int]]:
    url = f"{ELASTICSEARCH_HOST}/{INDEX_PATTERN}/_search"
    try:
        resp = requests.post(url, json=query_body, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get('hits', {}).get('hits', [])
            total = data.get('hits', {}).get('total', {}).get('value', 0)
            return hits, total
        else:
            print(f"{Colors.FAIL}❌ Elasticsearch error: HTTP {resp.status_code}{Colors.END}")
            return None, 0
    except Exception as e:
        print(f"{Colors.FAIL}❌ Connection error: {e}{Colors.END}")
        return None, 0

def show_last_events(limit: int = 10, alert_only: bool = False):
    # Query: only events that have an 'alert' field or are from honeypots/system
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "alert"}},           # Suricata alerts
                    {"term": {"fields.event_type": "cowrie"}},
                    {"term": {"fields.event_type": "dionaea"}},
                    {"term": {"fields.event_type": "system"}}
                ]
            }
        }
    }
    if alert_only:
        # Only Suricata alerts and honeypot events (already filtered)
        pass

    result = query_elasticsearch(query)
    if result is None:
        return
    hits, total = result

    print_header()
    if total == 0:
        print(f"{Colors.WARNING}⚠️ No security alerts found in Elasticsearch{Colors.END}")
        print(f"{Colors.DIM}   Waiting for sensor to send logs...{Colors.END}")
        return

    print(f"{Colors.DIM}Total alerts: {total} | Showing: {len(hits)} most recent{Colors.END}")
    print()

    displayed = 0
    for i, hit in enumerate(hits, 1):
        source = hit.get('_source', {})
        # Double‑check: if suricata event without alert, skip
        if source.get('fields', {}).get('event_type') == 'suricata' and not source.get('alert'):
            continue
        print_event(hit, i)
        displayed += 1

    if displayed == 0:
        print(f"{Colors.WARNING}⚠️ No alert events to display (non‑alert logs were filtered).{Colors.END}")

def follow_events(interval: int = 5):
    print_header()
    print(f"{Colors.GREEN}📡 Streaming live security alerts (Ctrl+C to stop){Colors.END}")
    print()
    last_timestamp = None
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
            if last_timestamp:
                query["query"]["bool"]["filter"] = {"range": {"@timestamp": {"gt": last_timestamp}}}
            result = query_elasticsearch(query)
            if result:
                hits, _ = result
                for hit in reversed(hits):
                    ts = hit.get('_source', {}).get('@timestamp', '')
                    if ts != last_timestamp:
                        # Only print if it's a real alert (exists alert or is honeypot)
                        src = hit.get('_source', {})
                        if src.get('alert') or src.get('fields', {}).get('event_type') in ('cowrie', 'dionaea'):
                            print_event(hit, "•")
                            last_timestamp = ts
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 Stopped streaming.{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description='ASOP Security Assistant CLI')
    parser.add_argument('-l', '--limit', type=int, default=10, help='Number of events to show')
    parser.add_argument('-f', '--follow', action='store_true', help='Stream live events')
    parser.add_argument('-a', '--alert-only', action='store_true', help='Show only alerts (default)')
    args = parser.parse_args()

    if args.follow:
        follow_events()
    else:
        show_last_events(limit=args.limit, alert_only=args.alert_only)

if __name__ == "__main__":
    main()