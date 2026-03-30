#!/usr/bin/env bash
# block-scanner-ips.sh — Extract malicious IPs from log analyzer data and add to ipset
# Runs as cron job after data.json is refreshed

set -euo pipefail

DATA_JSON="/var/www/log-analyzer/html/data.json"
IPSET_ABUSIVE="abusive_ips"
IPSET_SCANNERS="scanner_nets"
PERSIST_ABUSIVE="/etc/ipset-abusive.conf"
PERSIST_SCANNERS="/etc/ipset-scanners.conf"
LOG="/var/log/block-scanner-ips.log"

[ -f "$DATA_JSON" ] || { echo "$(date -Iseconds) ERROR: $DATA_JSON not found" >> "$LOG"; exit 1; }

RESULTS=$(python3 - "$DATA_JSON" "$IPSET_ABUSIVE" "$IPSET_SCANNERS" <<'PYEOF'
import json, re, sys, subprocess, ipaddress

data_path, ipset_abusive, ipset_scanners = sys.argv[1], sys.argv[2], sys.argv[3]

MALICIOUS_PATHS = [
    r'/wp-admin', r'/wp-login', r'/wp-content', r'/wp-json', r'/wp-config', r'/xmlrpc\.php',
    r'/wordpress/', r'/\.env', r'/\.git/', r'/\.streamlit/',
    r'/cgi-bin/', r'/HNAP', r'/SDK/', r'/sdk$',
    r'/admin\.php', r'/login$', r'/admin$', r'/dashboard$', r'/hudson$', r'/user$',
    r'/swagger\.json', r'/api/v\d+/config', r'/api/v\d+/\.env',
    r'/evox/', r'/nmaplowercheck',
    r'/developmentserver/', r'/luci/',
    r'\.php$',
]
SAFE_PATHS = [r'/send_mail\.php', r'/favicon', r'/robots\.txt', r'/sitemap\.xml']

SCANNER_RDNS = ['censys-scanner.com', 'internet-measurement.com', 'shodan.io',
                'shadowserver.org', 'stretchoid.com', 'binaryedge.ninja']

BLOCKED_COUNTRIES = {'RU','BY','KZ','BR','IN','CN','PH','ID','IR','KP','VN','NG'}

patterns = [re.compile(p, re.IGNORECASE) for p in MALICIOUS_PATHS]
safe_patterns = [re.compile(p, re.IGNORECASE) for p in SAFE_PATHS]

CF_RANGES = [
    '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
    '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
    '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
    '104.24.0.0/14','172.64.0.0/13'
]
cf_nets = [ipaddress.ip_network(r) for r in CF_RANGES]

def is_cloudflare(ip_str):
    try:
        return any(ipaddress.ip_address(ip_str) in net for net in cf_nets)
    except:
        return False

def is_safe_path(path):
    return any(rx.search(path) for rx in safe_patterns)

def is_scanner_path(path):
    return any(rx.search(path) for rx in patterns) and not is_safe_path(path)

with open(data_path) as f:
    data = json.load(f)

block_ips = set()
scanner_ips = set()

# Identify scanner IPs from notable rDNS
for n in data.get('notable', []):
    if any(s in n.get('label', '').lower() for s in SCANNER_RDNS):
        for ip in n.get('ips', []):
            if ':' not in ip:
                scanner_ips.add(ip)

# Identify malicious IPs from sessions
for s in data.get('sessions', []):
    ip = s.get('origin_ip', '')
    if ':' in ip:
        continue
    # Check rDNS hostname for known scanners
    hostname = (s.get('geo', {}).get('hostname') or '').lower()
    if any(scanner in hostname for scanner in SCANNER_RDNS):
        scanner_ips.add(ip)
        continue
    # Block IPs from blocked countries (including Cloudflare-proxied)
    cc = s.get('geo', {}).get('country_code', '')
    if cc in BLOCKED_COUNTRIES:
        block_ips.add(ip)
        continue
    if s.get('is_malicious', False):
        block_ips.add(ip)
        continue
    for p in s.get('path_summary', []):
        if is_scanner_path(p):
            block_ips.add(ip)
            break

# Add to abusive_ips
result = subprocess.run(['ipset', 'list', ipset_abusive], capture_output=True, text=True)
existing = {line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip()[0].isdigit()}
new_abusive = block_ips - existing
for ip in new_abusive:
    subprocess.run(['ipset', 'add', ipset_abusive, ip], capture_output=True)

# Add individual scanner IPs to scanner_nets (as /32)
new_scanner = 0
for ip in scanner_ips:
    r = subprocess.run(['ipset', 'test', ipset_scanners, ip], capture_output=True)
    if r.returncode != 0:
        subprocess.run(['ipset', 'add', ipset_scanners, ip], capture_output=True)
        new_scanner += 1

print(f"{len(new_abusive)} {new_scanner}")
PYEOF
)

NEW_ABUSIVE=$(echo "$RESULTS" | awk '{print $1}')
NEW_SCANNER=$(echo "$RESULTS" | awk '{print $2}')

CHANGED=0
if [ "$NEW_ABUSIVE" -gt 0 ] 2>/dev/null; then
    ipset save "$IPSET_ABUSIVE" > "$PERSIST_ABUSIVE"
    CHANGED=1
fi
if [ "$NEW_SCANNER" -gt 0 ] 2>/dev/null; then
    ipset save "$IPSET_SCANNERS" > "$PERSIST_SCANNERS"
    CHANGED=1
fi

if [ "$CHANGED" -eq 1 ]; then
    echo "$(date -Iseconds) Blocked $NEW_ABUSIVE abusive + $NEW_SCANNER scanner IPs" >> "$LOG"
else
    echo "$(date -Iseconds) No new IPs to block" >> "$LOG"
fi
