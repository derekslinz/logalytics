#!/usr/bin/env bash
# enforce-ipset-blocks.sh — Enforce IP-based blocks via ipset, based on Logalytics analysis
# Extracts scanner IPs, malicious IPs, and country-blocked IPs from data.json
# Adds IPs to ipsets, logs iptables events, and reports to AbuseIPDB
# Runs as cron job after data.json is refreshed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_JSON="${DATA_JSON:-$SCRIPT_DIR/../html/data.json}"
IPSET_ABUSIVE="${IPSET_ABUSIVE:-abusive_ips}"
IPSET_SCANNERS="${IPSET_SCANNERS:-scanner_nets}"
PERSIST_ABUSIVE="${PERSIST_ABUSIVE:-/etc/ipset-abusive.conf}"
PERSIST_SCANNERS="${PERSIST_SCANNERS:-/etc/ipset-scanners.conf}"
LOG="${LOG:-/var/log/enforce-ipset-blocks.log}"
ABUSEIPDB_KEY_FILE="${ABUSEIPDB_KEY_FILE:-/etc/abuseipdb.key}"
ABUSEIPDB_LOG="${ABUSEIPDB_LOG:-/var/log/abuseipdb-reports.log}"
CONFIG_JS="${CONFIG_JS:-$SCRIPT_DIR/../html/config.js}"
IPTABLES_LOG="${IPTABLES_LOG:-/var/log/iptables-blocks.log}"

# Configurables via environment
export ABUSE_SCORE_THRESHOLD="${ABUSE_SCORE_THRESHOLD:-75}"
export ABUSE_REPORT_THRESHOLD="${ABUSE_REPORT_THRESHOLD:-10}"
export BLOCKED_COUNTRIES="${BLOCKED_COUNTRIES:-RU BY KZ BR IN CN PH ID IR KP VN NG}"
export ENABLE_IPTABLES_LOGGING="${ENABLE_IPTABLES_LOGGING:-1}"

# Helper function to ensure iptables rules exist with logging
setup_iptables_logging() {
    # Only run if logging is enabled and iptables is available
    [ "$ENABLE_IPTABLES_LOGGING" != "1" ] && return 0
    command -v iptables >/dev/null 2>&1 || return 0
    
    # Attempt to add logging rules with timeout (non-blocking)
    # Note: These rules need to be added to INPUT chain before DROP/REJECT rules
    (
        timeout 1 iptables -nL INPUT 2>/dev/null | grep -q "abusive_ips.*LOG" || \
        timeout 1 iptables -I INPUT -m set --match-set abusive_ips src -j LOG --log-prefix "[ABUSIVE_IPS] " --log-level 6 2>/dev/null
    ) &
    (
        timeout 1 iptables -nL INPUT 2>/dev/null | grep -q "scanner_nets.*LOG" || \
        timeout 1 iptables -I INPUT -m set --match-set scanner_nets src -j LOG --log-prefix "[SCANNER_NETS] " --log-level 6 2>/dev/null
    ) &
    wait
}

# Generate frontend config so UI stays in sync with backend blocklist
cat <<EOF > "$CONFIG_JS"
window.APP_CONFIG = {
    "BLOCKED_COUNTRIES": $(echo "[\"${BLOCKED_COUNTRIES// /\",\"}\"]")
};
EOF


[ -f "$DATA_JSON" ] || { echo "$(date -Iseconds) ERROR: $DATA_JSON not found" >> "$LOG"; exit 1; }

# Set up iptables logging rules if enabled
setup_iptables_logging

# Pass API key to Python via env
if [ -f "$ABUSEIPDB_KEY_FILE" ]; then
    export ABUSEIPDB_KEY=$(cat "$ABUSEIPDB_KEY_FILE" | tr -d '[:space:]')
fi

RESULTS=$(python3 - "$DATA_JSON" "$IPSET_ABUSIVE" "$IPSET_SCANNERS" <<'PYEOF'
import json, re, sys, subprocess, ipaddress, os, tempfile, time
from datetime import datetime, timezone
import urllib.request, urllib.parse

data_path, ipset_abusive, ipset_scanners = sys.argv[1], sys.argv[2], sys.argv[3]
BLOCK_HISTORY_FILE = os.environ.get('BLOCK_HISTORY_FILE', '/var/lib/log_analyzer/data/blocked_ips.json')
SAFE_IPS_RAW = os.environ.get('SAFE_IPS', '')
IPTABLES_LOG_FILE = os.environ.get('IPTABLES_LOG', '/var/log/iptables-blocks.log')
MAIN_LOG_FILE = os.environ.get('LOG', '/var/log/enforce-ipset-blocks.log')
ENABLE_IPTABLES_LOGGING = os.environ.get('ENABLE_IPTABLES_LOGGING', '1') == '1'
# Configuration from environment
ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY', '')
ABUSE_SCORE_THRESHOLD = int(os.environ.get('ABUSE_SCORE_THRESHOLD', 75))
ABUSE_REPORT_THRESHOLD = int(os.environ.get('ABUSE_REPORT_THRESHOLD', 10))


MALICIOUS_PATHS = [
    r'/wp-admin', r'/wp-login', r'/wp-content', r'/wp-json', r'/wp-config', r'/xml-?rpc',
    r'/wordpress/', r'/\.env', r'/\.git/', r'/\.streamlit/',
    r'/cgi-bin/', r'/HNAP', r'/SDK/', r'/sdk$',
    r'/admin\.php', r'/login$', r'/admin$', r'/dashboard$', r'/hudson$', r'/user$',
    r'/swagger\.json', r'/api/v\d+/config', r'/api/v\d+/\.env',
    r'/evox/', r'/nmaplowercheck',
    r'/developmentserver/', r'/luci/',
    r'/phpmyadmin', r'/pma/', r'/xampp/', r'/_vti_bin/', r'/manager/html', r'/muieblackcat',
    r'\.php$',
]
SAFE_PATHS = [r'/send_mail\.php', r'/favicon', r'/robots\.txt', r'/sitemap\.xml']

SCANNER_RDNS = [
    'censys-scanner.com', 'internet-measurement.com', 'shodan.io', 'shodan.net',
    'shadowserver.org', 'stretchoid.com', 'binaryedge.ninja', 'onyphe.io',
    'leakix.net', 'rapid7.com', 'syscan.org', 'binalyze.com', 'netsystemsresearch.com',
    'project25499.com', 'expanseinc.com', 'criminalip.com', 'zoomseye.org',
    'netmap.io', 'rwth-aachen.de', 'hurricanethreat.com', 'bitping.com',
    'intrinsec.com', 'securitytrails.com', 'panthera.network', 'leakix.com',
    'fofa.info', 'fofa.so'
]

BLOCKED_COUNTRIES = set(os.environ.get('BLOCKED_COUNTRIES', '').split())
SAFE_IPS = {ip.strip() for ip in re.split(r'[\s,]+', SAFE_IPS_RAW) if ip.strip()}

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

def is_safe_ip(ip_str):
    return ip_str in SAFE_IPS

def log_ip_block(ip, reason, evidence_str=''):
    """Log IP block event to iptables log file if enabled"""
    if not ENABLE_IPTABLES_LOGGING:
        return
    try:
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        log_entry = f"{ts} BLOCKED {ip} reason={reason}"
        if evidence_str:
            log_entry += f" evidence={evidence_str}"
        with open(IPTABLES_LOG_FILE, 'a') as f:
            f.write(log_entry + '\n')
    except Exception:
        pass  # Don't fail blocking on logging errors

def is_scanner_path(path):
    return any(rx.search(path) for rx in patterns) and not is_safe_path(path)

def suspicious_paths(paths):
    return [p for p in paths if is_scanner_path(p)]

def get_status_counts(session):
    status_counts = session.get('status_counts', {}) or {}
    s2 = int(status_counts.get('2xx', 0) or 0)
    s4 = int(status_counts.get('4xx', 0) or 0)
    s5 = int(status_counts.get('5xx', 0) or 0)
    return s2, s4, s5

def derive_session_evidence(session):
    # Policy: any session with successful (2xx) responses is considered safe
    # for path-based malicious evidence.
    s2, s4, s5 = get_status_counts(session)
    if s2 > 0:
        return (None, None, [])

    paths = session.get('path_summary', []) or []
    suspicious = suspicious_paths(paths)
    if suspicious:
        return ('malicious_path_probe', suspicious[0], suspicious)

    if (s4 + s5) > 0:
        return ('suspicious_status_profile', f'4xx={s4},5xx={s5}', [])

    tags = [t for t in (session.get('tags', []) or []) if t]
    if tags:
        return ('analyzer_tag_signal', tags[0], [])

    intent = (session.get('intent') or '').strip()
    if intent and intent.lower() != 'passive traffic':
        return ('analyzer_intent_signal', intent, [])

    return (None, None, [])

with open(data_path) as f:
    data = json.load(f)

block_ips = set()
scanner_ips = set()
reportable = {}  # ip -> set of malicious paths (for AbuseIPDB)
block_reasons = {}  # ip -> {'reason': str, 'evidence': [str, ...]}

IGNORE_IPS = {'::1', '127.0.0.1', '0.0.0.0'}

def mark_block(ip, reason, evidence=None):
    block_ips.add(ip)
    if ip in block_reasons:
        return
    block_reasons[ip] = {
        'reason': reason,
        'evidence': [evidence] if evidence else []
    }

# Identify scanner IPs from notable rDNS
for n in data.get('notable', []):
    if any(s in n.get('label', '').lower() for s in SCANNER_RDNS):
        for ip in n.get('ips', []):
            if ':' not in ip:
                scanner_ips.add(ip)

# Identify malicious IPs from sessions
for s in data.get('sessions', []):
    ip = s.get('origin_ip', '')
    if ':' in ip or ip in IGNORE_IPS:
        continue
    if is_safe_ip(ip):
        continue
    # Check rDNS hostname for known scanners
    hostname = (s.get('geo', {}).get('hostname') or '').lower()
    if any(scanner in hostname for scanner in SCANNER_RDNS):
        scanner_ips.add(ip)
        continue
    # Block IPs from blocked countries (including Cloudflare-proxied)
    cc = s.get('geo', {}).get('country_code', '')
    if cc in BLOCKED_COUNTRIES:
        mark_block(ip, 'blocked_country', f'country={cc}')
        continue
    if s.get('is_malicious', False):
        reason, evidence, suspicious = derive_session_evidence(s)
        if reason and evidence:
            mark_block(ip, reason, evidence)
            if suspicious:
                reportable.setdefault(ip, set()).update(suspicious)
        continue
    s2, _s4, _s5 = get_status_counts(s)
    for p in s.get('path_summary', []):
        if s2 == 0 and is_scanner_path(p):
            mark_block(ip, 'malicious_path_probe', p)
            reportable.setdefault(ip, set()).add(p)
            break

# Check uncategorized IPs against AbuseIPDB
result = subprocess.run(['ipset', 'list', ipset_abusive], capture_output=True, text=True)
existing = {line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip()[0].isdigit()}

all_seen_ips = set()
for s in data.get('sessions', []):
    ip = s.get('origin_ip', '')
    if ':' not in ip and ip not in IGNORE_IPS and not is_safe_ip(ip):
        all_seen_ips.add(ip)
unknown_ips = all_seen_ips - block_ips - scanner_ips - existing

abuse_blocked = 0
if ABUSEIPDB_KEY and unknown_ips:
    for ip in list(unknown_ips)[:50]:  # cap at 50 lookups per run (free tier: 1000/day)
        try:
            req = urllib.request.Request(
                f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90',
                headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            d = json.loads(resp.read()).get('data', {})
            score = d.get('abuseConfidenceScore', 0)
            reports = d.get('totalReports', 0)
            if score >= ABUSE_SCORE_THRESHOLD and reports >= ABUSE_REPORT_THRESHOLD:
                mark_block(ip, 'abuseipdb_threshold', f'score={score},reports={reports}')
                reportable.setdefault(ip, set()).add(f'AbuseIPDB score: {score}% ({reports} reports)')
                abuse_blocked += 1
            time.sleep(0.1)
        except Exception:
            pass

# Add to abusive_ips
new_abusive = block_ips - existing
for ip in new_abusive:
    reason_info = block_reasons.get(ip, {'reason': 'unknown', 'evidence': []})
    evidence_str = ' | '.join(reason_info.get('evidence', [])[:3]) if reason_info.get('evidence') else ''
    log_ip_block(ip, reason_info.get('reason', 'unknown'), evidence_str)
    subprocess.run(['ipset', 'add', ipset_abusive, ip], capture_output=True)

# Ensure safe IPs are never blocked (remove from sets if present)
for ip in SAFE_IPS:
    subprocess.run(['ipset', 'del', ipset_abusive, ip], capture_output=True)
    subprocess.run(['ipset', 'del', ipset_scanners, ip], capture_output=True)

# Persist first-seen block timestamp for newly blocked IPs
try:
    block_history = {}
    if os.path.exists(BLOCK_HISTORY_FILE):
        with open(BLOCK_HISTORY_FILE, 'r') as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                block_history = loaded

    blocked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    # Remove safe IPs from persisted history to avoid stale blocked metadata in analyzer output
    for ip in SAFE_IPS:
        block_history.pop(ip, None)

    # Record metadata for currently detected blocked IPs so reasons are available
    # even for IPs that were already present in ipset before this script version.
    for ip in sorted(block_ips):
        reason_info = block_reasons.get(ip, {'reason': 'unknown', 'evidence': []})
        existing_entry = block_history.get(ip)

        if isinstance(existing_entry, str):
            # Migrate legacy format: {"ip": "2026-...Z"}
            block_history[ip] = {
                'blocked_at': existing_entry,
                'block_reason': reason_info.get('reason', 'unknown'),
                'evidence': reason_info.get('evidence', [])
            }
            continue

        if isinstance(existing_entry, dict):
            # Preserve original blocked_at; fill missing metadata.
            existing_entry.setdefault('blocked_at', blocked_at)
            existing_entry.setdefault('block_reason', reason_info.get('reason', 'unknown'))
            existing_entry.setdefault('evidence', reason_info.get('evidence', []))
            continue

        block_history[ip] = {
            'blocked_at': blocked_at,
            'block_reason': reason_info.get('reason', 'unknown'),
            'evidence': reason_info.get('evidence', [])
        }

    os.makedirs(os.path.dirname(BLOCK_HISTORY_FILE), exist_ok=True)
    with open(BLOCK_HISTORY_FILE, 'w') as fh:
        json.dump(block_history, fh, indent=2, sort_keys=True)
except Exception:
    # Non-fatal: blocking should continue even if history persistence fails.
    pass

# Add individual scanner IPs to scanner_nets (as /32)
new_scanner = 0
for ip in scanner_ips:
    r = subprocess.run(['ipset', 'test', ipset_scanners, ip], capture_output=True)
    if r.returncode != 0:
        log_ip_block(ip, 'scanner_detection', 'known_scanner_rdns')
        subprocess.run(['ipset', 'add', ipset_scanners, ip], capture_output=True)
        new_scanner += 1

# Write reportable IPs (new ones only) to temp file for AbuseIPDB
new_reportable = {ip: list(paths) for ip, paths in reportable.items() if ip in new_abusive}
report_file = os.path.join(tempfile.gettempdir(), 'abuseipdb_report.json')
with open(report_file, 'w') as f:
    json.dump(new_reportable, f)

print(f"{len(new_abusive)} {new_scanner} {len(new_reportable)} {abuse_blocked}")
PYEOF
)

NEW_ABUSIVE=$(echo "$RESULTS" | awk '{print $1}')
NEW_SCANNER=$(echo "$RESULTS" | awk '{print $2}')
NEW_REPORTABLE=$(echo "$RESULTS" | awk '{print $3}')
ABUSE_CHECKED=$(echo "$RESULTS" | awk '{print $4}')

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
    echo "$(date -Iseconds) Blocked $NEW_ABUSIVE abusive + $NEW_SCANNER scanner + $ABUSE_CHECKED via AbuseIPDB" >> "$LOG"
else
    echo "$(date -Iseconds) No new IPs to block (AbuseIPDB flagged: $ABUSE_CHECKED)" >> "$LOG"
fi

# --- AbuseIPDB Reporting ---
REPORT_FILE="/tmp/abuseipdb_report.json"
if [ -f "$ABUSEIPDB_KEY_FILE" ] && [ -f "$REPORT_FILE" ] && [ "$NEW_REPORTABLE" -gt 0 ] 2>/dev/null; then
    ABUSEIPDB_KEY=$(cat "$ABUSEIPDB_KEY_FILE")
    REPORTED=0

    python3 - "$REPORT_FILE" "$ABUSEIPDB_KEY" "$ABUSEIPDB_LOG" <<'PYEOF'
import json, sys, urllib.request, urllib.parse, time

report_file, api_key, log_file = sys.argv[1], sys.argv[2], sys.argv[3]

# AbuseIPDB categories:
# 14 = Port Scan, 21 = Web App Attack, 19 = Ping of Death (scanner)
CATEGORIES = "14,21"

with open(report_file) as f:
    reportable = json.load(f)

reported = 0
for ip, paths in reportable.items():
    comment = f"Automated: web scanner probing exploit paths: {', '.join(paths[:5])}"
    if len(comment) > 1024:
        comment = comment[:1021] + "..."

    data = urllib.parse.urlencode({
        'ip': ip,
        'categories': CATEGORIES,
        'comment': comment,
    }).encode()

    req = urllib.request.Request(
        'https://api.abuseipdb.com/api/v2/report',
        data=data,
        headers={
            'Key': api_key,
            'Accept': 'application/json',
        },
        method='POST'
    )

    try:
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        score = result.get('data', {}).get('abuseConfidenceScore', '?')
        with open(log_file, 'a') as lf:
            lf.write(f"{ip} reported (score: {score}%) paths: {', '.join(paths[:3])}\n")
        reported += 1
    except Exception as e:
        with open(log_file, 'a') as lf:
            lf.write(f"{ip} FAILED: {e}\n")

    # Rate limit: max 15 reports/sec on free tier
    time.sleep(0.1)

print(reported)
PYEOF

    REPORTED=$?
    echo "$(date -Iseconds) Reported $NEW_REPORTABLE IPs to AbuseIPDB" >> "$LOG"
    rm -f "$REPORT_FILE"
fi
