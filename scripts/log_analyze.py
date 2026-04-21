import re
import json
import maxminddb
import socket
import os
import glob
import gzip
import subprocess
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

# Optional cap; default keeps full range for timeline/history fidelity.
# Set LOG_ANALYZER_MAX_SESSIONS to a positive integer to cap output.
MAX_OUTPUT_SESSIONS = int(os.environ.get('LOG_ANALYZER_MAX_SESSIONS', '0') or '0')

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
    r'(\.php|wp-admin|wp-login|xmlrpc|\.env|\.git|\.config|admin|backup|shell|cgi-bin|wp/v2/users|server-status|login\.action|login\.do|\.jsp|\.asp|\.aws/|\.ssh/|\.kube/)',
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

def load_abusive_ips():
    try:
        if os.path.exists(ABUSIVE_FILE):
            with open(ABUSIVE_FILE, 'r') as f:
                return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except Exception as e:
        print(f"Warning: Could not load abusive_ips.txt: {e}")
    return set()

import html

# Pattern Clustering for "Level 2 Telemetry"
PATTERN_GROUPS = [
    (re.compile(r'(wp-admin|wp-login|xmlrpc|wp-content|wp-includes|wp-config|wordpress)', re.IGNORECASE), "WordPress Scanner"),
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

def analyze():
    bot_regexes = load_bots()
    malicious_paths_list = load_malicious_paths()
    
    city_reader = None
    asn_reader = None
    ip_cache = {}
    country_ips = {}
    sessions = {}

    try:
        city_reader = maxminddb.open_database(MMDB_FILE)
        asn_reader = maxminddb.open_database(ASN_MMDB_FILE)

        active_logs = discover_log_files()
        if not active_logs: return

        # Pre-pass for IP discovery
        new_ips = set()
        for log_file in active_logs:
            with open_log_file(log_file) as f:
                for line in f:
                    match = LOG_PATTERN.match(line)
                    if match:
                        ip = match.group('ip')
                        if is_valid_ip(ip) and ip != '127.0.0.1' and ip not in ip_cache: new_ips.add(ip)


        # Parallel DNS
        if new_ips:
            with ThreadPoolExecutor(max_workers=50) as ex:
                hosts = list(ex.map(get_hostname, new_ips))
            for ip, host in zip(new_ips, hosts): ip_cache[ip] = { 'hostname': host, 'partial': True }

        for log_file in active_logs:
            with open_log_file(log_file) as f:
                for line in f:
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
                    
                    if origin_ip not in ip_cache or ip_cache[origin_ip].get('partial'):
                        geo_data = city_reader.get(origin_ip)
                        asn_num, asn_name = get_asn(origin_ip, asn_reader)
                        hostname = ip_cache[origin_ip].get('hostname') if origin_ip in ip_cache else get_hostname(origin_ip)
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
                    s_key = (origin_ip, data['agent'])
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
                            'is_malicious': False
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

    except Exception as e:
        print(f"Error during analysis: {e}")
    finally:
        if city_reader: city_reader.close()
        if asn_reader: asn_reader.close()

    # Finalize Telemetry & Clustering
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
        except Exception as e:
            print(f"Warning: Could not write to {f}: {e}")


    print(f"Analysis complete. {len(final_sessions)} clustered sessions from {len(ip_cache)} unique origin IPs.")

if __name__ == '__main__':
    analyze()
