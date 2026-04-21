import re
import json
import maxminddb
import socket
import os
import glob
import gzip
import subprocess
import sys
import time
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

LOG_FILES = ['/var/log/nginx/access.log', '/var/log/nginx/access.log.1']
LOG_GLOBS = ['/var/log/nginx/access.log*']
MMDB_FILE = '/var/lib/GeoIP/GeoLite2-City.mmdb'
ASN_MMDB_FILE = '/var/lib/GeoIP/GeoLite2-ASN.mmdb'
OWNER_IP = '143.179.217.69'
OUTPUT_FILES = [
    '/var/www/logalytics/html/data.json',
    '/root/.gemini/antigravity/scratch/log_analyzer/web/data.json'
]

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

DATA_DIR = '/var/lib/log_analyzer/data'

BOTS_FILE = os.path.join(DATA_DIR, 'bots.json')
MALICIOUS_FILE = os.path.join(DATA_DIR, 'malicious_paths.txt')
ABUSIVE_FILE = os.path.join(DATA_DIR, 'abusive_ips.txt')
BLOCK_HISTORY_FILE = os.path.join(DATA_DIR, 'blocked_ips.json')
DNS_CACHE_FILE = os.path.join(DATA_DIR, 'dns_cache.json')

# Optional cap; default keeps full range for timeline/history fidelity.
# Set LOG_ANALYZER_MAX_SESSIONS to a positive integer to cap output.
MAX_OUTPUT_SESSIONS = int(os.environ.get('LOG_ANALYZER_MAX_SESSIONS', '0') or '0')
DNS_CACHE_TTL_SECONDS = int(os.environ.get('LOG_ANALYZER_DNS_CACHE_TTL_SECONDS', '604800') or '604800')
DNS_CACHE_MAX_ENTRIES = int(os.environ.get('LOG_ANALYZER_DNS_CACHE_MAX_ENTRIES', '200000') or '200000')

# Progress reporting controls
PROGRESS_ENABLED = os.environ.get('LOG_ANALYZER_PROGRESS', '1') != '0'
PROGRESS_INTERVAL_LINES = int(os.environ.get('LOG_ANALYZER_PROGRESS_INTERVAL_LINES', '50000') or '50000')

# Fallback Regex Patterns
BOT_PATTERN_FALLBACK = re.compile(
    r'(bot|crawler|spider|slurp|facebookexternalhit|ia_archiver|bingbot|googlebot|yandex|baidu|duckduckgo|uptime|monitoring|pingdom|semrush|ahrefs|rogerbot|exabot|dotbot|mj12bot|grapeshot|meanpathbot|adsbot-google|mediapartners-google|chrome-lighthouse|lighthouse|letsencrypt|validation server|dataprovider|curl|python-requests|httpx|go-http-client)',
    re.IGNORECASE
)

CENSUS_BOT_PATTERN = re.compile(
    r'(censys|l9scan|zgrab|masscan|nmap|onyphe|cnsat|shadowserver|shodan|stretchoid|binaryedge|rapid7|leakix|fofa|internet-measurement|project25499|expanseinc|criminalip|zoomseye|netmap|bitping|intrinsec|securitytrails|panthera)',
    re.IGNORECASE
)

MALICIOUS_PATHS_FALLBACK = re.compile(
    r'(\.php|wp-admin|wp-login|xml-?rpc|\.env|\.git|\.config|admin|backup|shell|cgi-bin|wp/v2/users|server-status|login\.action|login\.do|\.jsp|\.asp|\.aws/|\.ssh/|\.kube/)',
    re.IGNORECASE
)

# Hyperscale Cloud Providers
CLOUD_PATTERN = re.compile(
    r'(amazon|aws|google cloud|googleusercontent|microsoft|azure|oracle|ibm|softlayer|alibaba|aliyun|tencent|baidu|fastly|stackpath)',
    re.IGNORECASE
)
CLOUD_ASNS = {
    16509, 14618, 54113, # Amazon
    15169, 396982, # Google
    8075, 12076, # Microsoft
    45062, 38365, # Baidu
    37963, 45102, # Aliyun / Alibaba
    20940, # Akamai (often considered cloud infrastructure)
}

# Hosting / Data Center Providers
HOSTING_PATTERN = re.compile(
    r'(digitalocean|linode|hetzner|ovh|leaseweb|choopa|vultr|contabo|akamai|it7|m247|constant|fasthosts|ionos|cloudflare|scaleway|pfcloud|host|data center|datacenter|server|vps|dedicated|cogent|hurricane|zenlayer|colocrossing|quadranet|liquidweb|iweb|namecheap|bluehost|hostgator|dreamhost|inmotion|a2hosting|siteground)',
    re.IGNORECASE
)
HOSTING_ASNS = {
    14061, # DigitalOcean
    20473, # Vultr
    63949, # Linode
    24940, 42730, # Hetzner
    16276, # OVH
    13335, # Cloudflare
    21342, # Scaleway
    398101, # Censys (Scanner, but often in hosting space)
    203446, # ONYPHE
}

LOG_PATTERN = re.compile(
    r'(?P<ip>[^ ]+) - (?P<edge_ip>[^ ]+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]+)" "(?P<agent>[^"]+)"(?: "(?P<cf_ip>[^"]*)" "(?P<xff>[^"]*)")?'
)

def load_bots():
    try:
        if os.path.exists(BOTS_FILE):
            with open(BOTS_FILE, 'r') as f:
                data = json.load(f)
                return [re.compile(b['pattern'], re.IGNORECASE) for b in data]
    except Exception as e:
        print(f"Warning: Could not load bots.json: {e}")
    return []

def load_malicious_paths():
    try:
        if os.path.exists(MALICIOUS_FILE):
            with open(MALICIOUS_FILE, 'r') as f:
                return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except Exception as e:
        print(f"Warning: Could not load malicious_paths.txt: {e}")
    return set()

def save_malicious_path(path):
    os.makedirs(os.path.dirname(MALICIOUS_FILE), exist_ok=True)
    with open(MALICIOUS_FILE, 'a') as f:
        f.write(f"{path}\n")

def normalize_malicious_path(value):
    path = normalize_path((value or '').strip())
    if not path:
        return ''
    if not path.startswith('/'):
        path = '/' + path
    return path

def confirm_add_malicious_path(path):
    warning = (
        "WARNING: Adding a malicious path can increase false positives and may block legitimate traffic.\n"
        f"Path to add: {path}\n"
        "Type 'yes' to confirm: "
    )
    try:
        answer = input(warning)
    except EOFError:
        return False
    return answer.strip().lower() == 'yes'

def add_malicious_path(path, force=False):
    normalized_path = normalize_malicious_path(path)
    if not normalized_path:
        print("Error: --add-malicious-path requires a non-empty path value.", file=sys.stderr)
        return 1

    existing = load_malicious_paths()
    if normalized_path in existing:
        print(f"No change: path already exists in malicious list: {normalized_path}")
        return 0

    if not force and not confirm_add_malicious_path(normalized_path):
        print("Aborted: malicious path was not added.", file=sys.stderr)
        return 1

    save_malicious_path(normalized_path)
    print(f"Added malicious path: {normalized_path}")
    return 0

def load_abusive_ips():
    try:
        if os.path.exists(ABUSIVE_FILE):
            with open(ABUSIVE_FILE, 'r') as f:
                return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except Exception as e:
        print(f"Warning: Could not load abusive_ips.txt: {e}")
    return set()

def load_block_history():
    try:
        if os.path.exists(BLOCK_HISTORY_FILE):
            with open(BLOCK_HISTORY_FILE, 'r') as f:
                raw = json.load(f)
                if not isinstance(raw, dict):
                    return {}

                normalized = {}
                for ip, entry in raw.items():
                    if isinstance(entry, str):
                        normalized[ip] = {
                            'blocked_at': entry,
                            'block_reason': 'unknown',
                            'evidence': []
                        }
                    elif isinstance(entry, dict):
                        normalized[ip] = {
                            'blocked_at': entry.get('blocked_at'),
                            'block_reason': entry.get('block_reason', 'unknown'),
                            'evidence': entry.get('evidence', []) if isinstance(entry.get('evidence', []), list) else []
                        }
                return normalized
    except Exception as e:
        print(f"Warning: Could not load blocked_ips.json: {e}")
    return {}

def load_dns_cache():
    try:
        if not os.path.exists(DNS_CACHE_FILE):
            return {}
        with open(DNS_CACHE_FILE, 'r') as f:
            raw = json.load(f)
            if not isinstance(raw, dict):
                return {}

        now = int(time.time())
        out = {}
        for ip, entry in raw.items():
            if isinstance(entry, str):
                # Legacy format: {"ip": "hostname"}
                out[ip] = {'hostname': entry, 'cached_at': now}
                continue
            if not isinstance(entry, dict):
                continue

            hostname = entry.get('hostname')
            cached_at = int(entry.get('cached_at') or 0)
            if DNS_CACHE_TTL_SECONDS > 0 and cached_at and (now - cached_at) > DNS_CACHE_TTL_SECONDS:
                continue
            out[ip] = {'hostname': hostname, 'cached_at': cached_at or now}
        return out
    except Exception as e:
        print(f"Warning: Could not load dns_cache.json: {e}")
    return {}

def save_dns_cache(dns_cache):
    try:
        if not isinstance(dns_cache, dict):
            return

        items = sorted(
            dns_cache.items(),
            key=lambda kv: int((kv[1] or {}).get('cached_at', 0)),
            reverse=True
        )
        if DNS_CACHE_MAX_ENTRIES > 0:
            items = items[:DNS_CACHE_MAX_ENTRIES]

        payload = {
            ip: {
                'hostname': entry.get('hostname') if isinstance(entry, dict) else None,
                'cached_at': int((entry or {}).get('cached_at', int(time.time()))) if isinstance(entry, dict) else int(time.time())
            }
            for ip, entry in items
        }

        os.makedirs(os.path.dirname(DNS_CACHE_FILE), exist_ok=True)
        with open(DNS_CACHE_FILE, 'w') as f:
            json.dump(payload, f, indent=2, sort_keys=True)
    except Exception as e:
        print(f"Warning: Could not save dns_cache.json: {e}")

import html

# Pattern Clustering for "Level 2 Telemetry"
PATTERN_GROUPS = [
    (re.compile(r'(wp-admin|wp-login|xml-?rpc|wp-content|wp-includes|wp-config|wordpress)', re.IGNORECASE), "WordPress Scanner"),
    (re.compile(r'(\.env|\.git|\.config|config\.php|web\.config|\.php\.)', re.IGNORECASE), "Config/Env Scanner"),
    (re.compile(r'(cgi-bin|bin/sh|cmd\.exe|\.asp|\.jsp|shell)', re.IGNORECASE), "RCE/Shell Probe"),
    (re.compile(r'(\.sql|\.db|\.sqlite|phpmyadmin|adminer)', re.IGNORECASE), "Database Probe"),
    (re.compile(r'(\.aws|\.kube|identity|token)', re.IGNORECASE), "Cloud/K8s Probe")
]

BOT_DOMAINS = {
    "googlebot.com": "Googlebot",
    "search.msn.com": "Bingbot",
    "bing.com": "Bingbot",
    "yandex.com": "YandexBot",
    "yandex.ru": "YandexBot",
    "baidu.com": "BaiduSpider",
    "duckduckgo.com": "DuckDuckGoBot"
}

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def verify_bot(ip, hostname):
    """Forward-Confirmed Reverse DNS (FCrDNS)"""
    if not hostname: return False
    # Check if hostname ends with a known bot domain
    matched_domain = next((d for d in BOT_DOMAINS if hostname.endswith(d)), None)
    if not matched_domain: return False
    
    try:
        # Resolve the hostname back to an IP
        resolved_ip = socket.gethostbyname(hostname)
        return resolved_ip == ip
    except (socket.herror, socket.gaierror):
        return False

def is_notable(hostname, asn_name, asn_num, is_verified_bot):
    if not hostname and not asn_name: return False, None
    combined = ((hostname or "") + (asn_name or "")).lower()
    
    # ISP Exclusions
    isp_keywords = ['comcast', 'at&t', 'verizon', 't-mobile', 'orange', 'spectrum', 'british-telecom', 'residential']
    if any(k in combined for k in isp_keywords): return False, None

    # Hosting Provider Labeling (Attribution Hygiene)
    is_hosting = any(k in combined for k in HOSTING_PATTERN.pattern.split('|')) or \
                 (asn_num in HOSTING_ASNS) or (asn_num in CLOUD_ASNS)
    
    if is_hosting and not is_verified_bot:
        return True, f"ASN: AS{asn_num} ({sanitize(asn_name)}) | Confidence: hosting provider only | Actor: unknown"

    # Verified Bot
    if is_verified_bot:
        return True, f"Verified Actor: {BOT_DOMAINS.get(next((d for d in BOT_DOMAINS if hostname.endswith(d)), ''), 'Unknown Bot')}"

    # Generic Unverified RDNS
    if hostname:
        return True, f"RDNS: {sanitize(hostname)} (unverified) | Actor: unknown"

    return False, None

def get_asn(ip, reader):
    try:
        data = reader.get(ip)
        if data:
            return data.get('autonomous_system_number'), data.get('autonomous_system_organization')
    except Exception:
        pass
    return None, None

def parse_time(time_str):
    try:
        dt = datetime.strptime(time_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        return dt.timestamp()
    except Exception:
        return 0

def sanitize(text):
    if not text: return ""
    return html.escape(str(text))

def normalize_path(path):
    # Strip control chars, normalize slashes
    path = "".join(c for c in path if c.isprintable())
    path = re.sub(r'/+', '/', path)
    return path

def open_log_file(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')

def discover_log_files():
    discovered = set(LOG_FILES)
    for pattern in LOG_GLOBS:
        for p in glob.glob(pattern):
            discovered.add(p)

    existing = [p for p in discovered if os.path.exists(p)]

    def log_sort_key(path):
        if path.endswith('access.log'):
            return 0
        m = re.search(r'access\.log\.(\d+)', path)
        if m:
            return int(m.group(1))
        return 10_000

    return sorted(existing, key=log_sort_key)

def progress(stage, current=None, total=None, extra=''):
    if not PROGRESS_ENABLED:
        return

    ts = datetime.now().strftime('%H:%M:%S')
    msg = f"[{ts}] [log_analyze] {stage}"

    if current is not None and total:
        pct = (current / total) * 100 if total else 0
        msg += f" ({current}/{total}, {pct:.1f}%)"
    elif current is not None:
        msg += f" ({current})"

    if extra:
        msg += f" - {extra}"

    print(msg, file=sys.stderr, flush=True)

def update_path_stats(store, path, session_key, ip, is_blocked):
    entry = store.get(path)
    if entry is None:
        entry = {
            'hits': 0,
            'sessions': set(),
            'ips': set(),
            'blocked_sessions': set(),
            'blocked_ips': set(),
        }
        store[path] = entry

    entry['hits'] += 1
    entry['sessions'].add(session_key)
    entry['ips'].add(ip)
    if is_blocked:
        entry['blocked_sessions'].add(session_key)
        entry['blocked_ips'].add(ip)

def top_path_items(path_stats, limit):
    items = sorted(path_stats.items(), key=lambda kv: kv[1]['hits'], reverse=True)
    if limit > 0:
        return items[:limit]
    return items

def parse_args():
    parser = argparse.ArgumentParser(
        prog='log_analyze.py',
        description='Analyze nginx access logs into clustered session telemetry JSON for Logalytics.'
    )
    parser.add_argument(
        '--top-paths',
        dest='top_paths',
        type=int,
        default=10,
        help='Number of top malicious and non-malicious paths to print in summary stats (default: 10).'
    )
    parser.add_argument(
        '--add-malicious-path',
        dest='add_malicious_path',
        type=str,
        default=None,
        help='Manually add a path to malicious_paths.txt and exit.'
    )
    parser.add_argument(
        '--yes',
        dest='yes',
        action='store_true',
        help='Skip confirmation prompt when using --add-malicious-path.'
    )
    return parser.parse_args()

def analyze(top_paths=10):
    top_paths = max(0, int(top_paths))
    progress('Initializing analysis')
    bot_regexes = load_bots()
    malicious_paths_list = load_malicious_paths()
    block_history = load_block_history()
    dns_cache = load_dns_cache()
    progress('Loaded persistent DNS cache', len(dns_cache))
    
    city_reader = None
    asn_reader = None
    ip_cache = {}
    country_ips = {}
    sessions = {}
    malicious_path_stats = {}
    non_malicious_path_stats = {}

    try:
        city_reader = maxminddb.open_database(MMDB_FILE)
        asn_reader = maxminddb.open_database(ASN_MMDB_FILE)
        progress('Opened GeoIP databases')

        active_logs = discover_log_files()
        if not active_logs:
            progress('No active log files found')
            return

        progress('Discovered log files', len(active_logs), len(active_logs), ', '.join(os.path.basename(p) for p in active_logs))

        # Seed in-run cache from persistent DNS cache
        for ip, entry in dns_cache.items():
            ip_cache[ip] = {'hostname': entry.get('hostname'), 'partial': True}
        progress('Seeded in-memory cache from persistent DNS cache', len(ip_cache))

        # Pre-pass for IP discovery
        new_ips = set()
        for idx, log_file in enumerate(active_logs, 1):
            progress('Pre-scan log file', idx, len(active_logs), os.path.basename(log_file))
            with open_log_file(log_file) as f:
                for line_no, line in enumerate(f, 1):
                    match = LOG_PATTERN.match(line)
                    if match:
                        ip = match.group('ip')
                        if is_valid_ip(ip) and ip != '127.0.0.1' and ip not in ip_cache: new_ips.add(ip)
                    if line_no % PROGRESS_INTERVAL_LINES == 0:
                        progress('Pre-scan progress', line_no, extra=os.path.basename(log_file))

        progress('Pre-scan complete', len(new_ips), extra='unique IPs queued for rDNS')


        # Parallel DNS
        if new_ips:
            progress('Resolving rDNS', len(new_ips), extra='parallel lookup start')
            with ThreadPoolExecutor(max_workers=50) as ex:
                hosts = list(ex.map(get_hostname, new_ips))
            now_ts = int(time.time())
            for ip, host in zip(new_ips, hosts):
                ip_cache[ip] = { 'hostname': host, 'partial': True }
                dns_cache[ip] = {'hostname': host, 'cached_at': now_ts}
            progress('rDNS resolution complete', len(new_ips), extra='parallel lookup finished')
        else:
            progress('No new IPs require rDNS resolution')

        total_processed_lines = 0
        for idx, log_file in enumerate(active_logs, 1):
            progress('Processing log file', idx, len(active_logs), os.path.basename(log_file))
            with open_log_file(log_file) as f:
                for line_no, line in enumerate(f, 1):
                    total_processed_lines += 1
                    match = LOG_PATTERN.match(line)
                    if not match: continue
                
                    data = match.groupdict()
                    # Fallback Logic: CF-Connecting-IP -> X-Forwarded-For -> RemoteAddr (Nginx-processed)
                    origin_ip = data.get('cf_ip')
                    if not origin_ip or origin_ip == '-' or not is_valid_ip(origin_ip):
                        xff = data.get('xff', '')
                        if xff and xff != '-' and is_valid_ip(xff.split(',')[0].strip()):
                            origin_ip = xff.split(',')[0].strip()
                        else:
                            origin_ip = data['ip']
                    
                    if not is_valid_ip(origin_ip) or origin_ip == '127.0.0.1' or origin_ip == OWNER_IP: continue
                    edge_ip = data['edge_ip']


                    
                    path_parts = data['request'].split(' ')
                    path = normalize_path(path_parts[1] if len(path_parts) > 1 else '/')
                    ts = parse_time(data['time'])
                    status = int(data['status'])
                    s_key = (origin_ip, data['agent'])
                    block_meta = block_history.get(origin_ip, {})
                    is_blocked_origin = bool(block_meta.get('blocked_at') or block_meta.get('block_reason'))

                    is_malicious_path = (path in malicious_paths_list) or bool(MALICIOUS_PATHS_FALLBACK.search(path))
                    if is_malicious_path:
                        update_path_stats(malicious_path_stats, path, s_key, origin_ip, is_blocked_origin)
                    else:
                        update_path_stats(non_malicious_path_stats, path, s_key, origin_ip, is_blocked_origin)
                    
                    if origin_ip not in ip_cache or ip_cache[origin_ip].get('partial'):
                        geo_data = city_reader.get(origin_ip)
                        asn_num, asn_name = get_asn(origin_ip, asn_reader)
                        hostname = ip_cache[origin_ip].get('hostname') if origin_ip in ip_cache else get_hostname(origin_ip)
                        if origin_ip not in dns_cache:
                            dns_cache[origin_ip] = {'hostname': hostname, 'cached_at': int(time.time())}
                        is_verified_bot = verify_bot(origin_ip, hostname)
                        is_bot = is_verified_bot or any(r.search(data['agent']) for r in bot_regexes) or \
                                 bool(BOT_PATTERN_FALLBACK.search(data['agent']))
                        
                        combined = ((hostname or "") + (asn_name or "")).lower()
                        is_hosting = any(k in combined for k in HOSTING_PATTERN.pattern.split('|')) or (asn_num in HOSTING_ASNS)
                        is_cloud = (asn_num in CLOUD_ASNS)
                        
                        ip_cache[origin_ip] = {
                            'city': sanitize(geo_data.get('city', {}).get('names', {}).get('en')) if geo_data else None,
                            'country': geo_data.get('country', {}).get('names', {}).get('en') if geo_data else None,
                            'country_code': geo_data.get('country', {}).get('iso_code') if geo_data else None,
                            'hostname': sanitize(hostname),
                            'asn': asn_num,
                            'asn_name': sanitize(asn_name),
                            'is_bot': is_bot,
                            'is_verified_bot': is_verified_bot,
                            'is_cloud': is_cloud,
                            'is_hosting': is_hosting,
                            'lat': geo_data.get('location', {}).get('latitude') if geo_data else None,
                            'lon': geo_data.get('location', {}).get('longitude') if geo_data else None
                        }

                    # Session Discovery & Level 2 Aggregation
                    if s_key not in sessions:
                        sessions[s_key] = {
                            'origin_ip': origin_ip,
                            'edge_ip': edge_ip,
                            'geo': ip_cache[origin_ip],
                            'requests': [],
                            'status_counts': {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0},
                            'first_seen': ts,
                            'last_seen': ts,
                            'intent': "Passive Traffic",
                            'tags': [],
                            'is_malicious': False,
                            'blocked_at': block_meta.get('blocked_at'),
                            'block_reason': block_meta.get('block_reason'),
                            'block_evidence': block_meta.get('evidence', [])
                        }
                    
                    s = sessions[s_key]
                    s['requests'].append({'time': ts, 'path': sanitize(path), 'status': status})
                    if 200 <= status < 300:
                        s['status_counts']['2xx'] += 1
                    elif 300 <= status < 400:
                        s['status_counts']['3xx'] += 1
                    elif 400 <= status < 500:
                        s['status_counts']['4xx'] += 1
                    elif 500 <= status < 600:
                        s['status_counts']['5xx'] += 1
                    s['first_seen'] = min(s['first_seen'], ts)
                    s['last_seen'] = max(s['last_seen'], ts)
                    
                    # Pattern Clustering
                    for pattern, label in PATTERN_GROUPS:
                        if pattern.search(path):
                            s['intent'] = label
                            break

                    # Explainability Tags
                    if status >= 400 and not ip_cache[origin_ip]['is_bot']:
                        if "known scanner pattern" not in s['tags']: s['tags'].append("known scanner pattern")
                    if "Probe" in s['intent'] or "Scanner" in s['intent']:
                        if "common exploit path" not in s['tags']: s['tags'].append("common exploit path")
                    if ip_cache[origin_ip]['is_bot']:
                        if "crawler" not in s['tags']: s['tags'].append("crawler")

                    # Metrics Update
                    c_code = ip_cache[origin_ip]['country_code'] or '??'
                    if c_code not in country_ips:
                        country_ips[c_code] = { 'legit': set(), 'bots': set(), 'malicious': set(), 'name': ip_cache[origin_ip]['country'] or 'Unknown' }
                    
                    is_census_bot = bool(CENSUS_BOT_PATTERN.search(data['agent'])) or \
                                    bool(CENSUS_BOT_PATTERN.search(ip_cache[origin_ip]['hostname'] or ''))

                    is_malicious = (status >= 400 and not ip_cache[origin_ip]['is_bot']) or \
                                  (path in malicious_paths_list) or \
                                  bool(MALICIOUS_PATHS_FALLBACK.search(path)) or \
                                  (c_code in ['RU', 'BY']) or \
                                  is_census_bot
                    
                    if is_malicious: 
                        country_ips[c_code]['malicious'].add(origin_ip)
                        s['is_malicious'] = True
                        if is_census_bot:
                            s['intent'] = "Census Scanner"
                            if "internet census" not in s['tags']:
                                s['tags'].append("internet census")
                    elif ip_cache[origin_ip]['is_bot']: country_ips[c_code]['bots'].add(origin_ip)
                    else: country_ips[c_code]['legit'].add(origin_ip)

                    if line_no % PROGRESS_INTERVAL_LINES == 0:
                        progress(
                            'Processing progress',
                            total_processed_lines,
                            extra=f"sessions={len(sessions)}, ips={len(ip_cache)}, file={os.path.basename(log_file)}"
                        )

    except Exception as e:
        print(f"Error during analysis: {e}")
    finally:
        save_dns_cache(dns_cache)
        progress('Saved persistent DNS cache', len(dns_cache))
        if city_reader: city_reader.close()
        if asn_reader: asn_reader.close()

    # Finalize Telemetry & Clustering
    progress('Finalizing sessions', len(sessions))
    final_sessions = []
    for s in sessions.values():
        dur = max(1, s['last_seen'] - s['first_seen'])
        s['req_count'] = len(s['requests'])
        s['req_rate'] = round(s['req_count'] / dur, 3) 
        s['is_spike'] = s['req_rate'] > 5.0
        s['first_seen_iso'] = datetime.fromtimestamp(s['first_seen']).isoformat()
        s['last_seen_iso'] = datetime.fromtimestamp(s['last_seen']).isoformat()
        s['path_summary'] = list(set(r['path'] for r in s['requests'][-10:]))
        del s['requests']
        final_sessions.append(s)

    final_sessions.sort(key=lambda x: x['last_seen'], reverse=True)
    progress('Sessions finalized', len(final_sessions))

    # Recompute Uniques Correctly
    output_sessions = final_sessions[:MAX_OUTPUT_SESSIONS] if MAX_OUTPUT_SESSIONS > 0 else final_sessions

    output_data = {
        'sessions': output_sessions,
        'summary': {
            'countries': {c: {k: (len(v) if isinstance(v, set) else v) for k, v in st.items()} for c, st in country_ips.items()},
            'total_requests': sum(s['req_count'] for s in final_sessions),
            'unique_origin_ips': len(ip_cache),
            'updated_at': datetime.now().isoformat()
        }
    }
    progress('Prepared output payload', len(output_sessions), extra='sessions selected for output')
    # Notable Entities
    notable_entities = {}
    for ip, info in ip_cache.items():
        notable, label = is_notable(info.get('hostname'), info.get('asn_name'), info.get('asn'), info.get('is_verified_bot'))
        if notable:
            if label not in notable_entities: notable_entities[label] = set()
            notable_entities[label].add(ip)
    output_data['notable'] = [{'label': l, 'ips': list(ips), 'count': len(ips)} for l, ips in notable_entities.items()]

    for f in OUTPUT_FILES:
        try:
            os.makedirs(os.path.dirname(f), exist_ok=True)
            with open(f, 'w') as out: json.dump(output_data, out, indent=2)
            progress('Wrote output file', extra=f)
        except Exception as e:
            print(f"Warning: Could not write to {f}: {e}")

    progress('Analysis complete', len(final_sessions), extra=f'unique IPs={len(ip_cache)}')

    blocked_sessions = sum(1 for s in final_sessions if s.get('blocked_at') or s.get('block_reason'))
    blocked_ips = len({s.get('origin_ip') for s in final_sessions if s.get('blocked_at') or s.get('block_reason')})
    blocked_paths = len({
        path
        for path, stats in {**malicious_path_stats, **non_malicious_path_stats}.items()
        if stats['blocked_sessions']
    })

    top_malicious_paths = top_path_items(malicious_path_stats, top_paths)
    top_non_malicious_paths = top_path_items(non_malicious_path_stats, top_paths)

    malicious_paths_seen = sum(stats['hits'] for stats in malicious_path_stats.values())
    non_malicious_paths_seen = sum(stats['hits'] for stats in non_malicious_path_stats.values())

    print(f"Security stats: malicious_paths_seen={malicious_paths_seen} unique_malicious_paths={len(malicious_path_stats)}")
    if top_paths > 0 and top_malicious_paths:
        print("Top malicious paths:")
        for path, stats in top_malicious_paths:
            print(
                f"  - {path}: hits={stats['hits']} sessions={len(stats['sessions'])} "
                f"ips={len(stats['ips'])} blocked_sessions={len(stats['blocked_sessions'])} "
                f"blocked_ips={len(stats['blocked_ips'])}"
            )
    print(f"Security stats: non_malicious_paths_seen={non_malicious_paths_seen} unique_non_malicious_paths={len(non_malicious_path_stats)}")
    if top_paths > 0 and top_non_malicious_paths:
        print("Top non-malicious paths:")
        for path, stats in top_non_malicious_paths:
            print(
                f"  - {path}: hits={stats['hits']} sessions={len(stats['sessions'])} "
                f"ips={len(stats['ips'])} blocked_sessions={len(stats['blocked_sessions'])} "
                f"blocked_ips={len(stats['blocked_ips'])}"
            )
    print(f"Blocked stats: blocked_paths={blocked_paths} blocked_ips={blocked_ips} blocked_sessions={blocked_sessions}")

    print(f"Analysis complete. {len(final_sessions)} clustered sessions from {len(ip_cache)} unique origin IPs.")

if __name__ == '__main__':
    args = parse_args()
    if args.add_malicious_path is not None:
        raise SystemExit(add_malicious_path(args.add_malicious_path, force=args.yes))
    analyze(top_paths=args.top_paths)
