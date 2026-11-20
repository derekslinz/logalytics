#!/usr/bin/env python3
"""
build-shards.py — Logalytics build-time precompute.

Reads the monolithic html/data.json (47 MB, ~20k sessions) and emits a small
summary.json plus time-window session shards under html/shards/, plus a
notables.json. The dashboard then loads only summary.json up front and fetches
session shards on demand as the timeline slider moves — no more 47 MB
fetch+JSON.parse on every page load.

Run once offline against data.json:
    python3 scripts/build-shards.py

data.json is left untouched (it remains the source of truth).
"""

import json
import os
import re
import math
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(BASE, "..", "html")
DATA = os.path.join(HTML, "data.json")
SUMMARY = os.path.join(HTML, "summary.json")
SHARD_DIR = os.path.join(HTML, "shards")
NOTABLES = os.path.join(HTML, "notables.json")

IGNORE_IPS = {"::1", "127.0.0.1", "0.0.0.0"}

# Target ~100 KB per shard. Measured ~527 bytes per lean session, so ~190
# sessions per shard keeps us comfortably under the 100 KB budget.
SESSIONS_PER_SHARD = 90

# Lean session schema — every field app.js actually renders, nothing else.
MALICIOUS_PATHS = [
    r"/wp-admin/i", r"/wp-login/i", r"/wp-content/i", r"/wp-json/i",
    r"/wp-config/i", r"/xmlrpc\.php/i", r"/wordpress//i",
    r"/\.env/i", r"/\.git//i", r"/\.streamlit//i",
    r"/cgi-bin//i", r"/HNAP/i", r"/SDK//i", r"/sdk$/i",
    r"/admin\.php/i", r"/login$/i", r"/admin$/i", r"/dashboard$/i",
    r"/hudson$/i", r"/user$/i", r"/swagger\.json/i",
    r"/api\/v\d+\/config/i", r"/api\/v\d+\/\.env/i",
    r"/evox//i", r"/nmaplowercheck/i", r"/fetch\.php/i",
    r"/sw\.php/i", r"/cnusw\.php/i", r"/ass\.php/i",
    r"/cabs\.php/i", r"/x1da\.php/i", r"/aa2\.php/i",
    r"/fffff\.php/i", r"/jp\.php/i", r"/19\.php/i",
    r"/100\.php/i", r"/xwx1\.php/i", r"/developmentserver//i",
    r"/luci//i", r"^http:/i", r"^\*$",
]
import re as _re
_MALICIOUS_RX = [_re.compile(p.rstrip("/i"), _re.I) for p in MALICIOUS_PATHS]


def is_scanner_traffic(s):
    failed_scanner_paths = s.get("failed_scanner_paths")
    successful_paths = set(s.get("successful_paths") or [])
    if failed_scanner_paths is not None:
        return any(
            path not in successful_paths
            and any(rx.search(path) for rx in _MALICIOUS_RX)
            for path in failed_scanner_paths
        )

    status_counts = s.get("status_counts") or {}
    if int(status_counts.get("2xx", 0) or 0) > 0:
        return False
    return bool(s.get("path_summary") and any(
        any(rx.search(p) for rx in _MALICIOUS_RX) for p in s.get("path_summary") or []
    ))


def is_session_malicious(s):
    status_counts = s.get("status_counts") or {}
    has_success = int(status_counts.get("2xx", 0) or 0) > 0
    tags = set(s.get("tags") or [])
    geo = s.get("geo") or {}
    was_tarpited = bool(s.get("tarpited")) or s.get("intent") == "Tarpited Scanner"
    has_other_signal = (
        geo.get("country_code") in {"RU", "BY"}
        or "internet census" in tags
    )
    if has_success and was_tarpited and not has_other_signal:
        return False
    return bool(s.get("is_malicious"))


def get_traffic_type(s):
    if is_session_malicious(s) or is_scanner_traffic(s):
        return "malicious"
    g = s.get("geo") or {}
    if g.get("is_bot"):
        return "bot"
    if g.get("is_cloud"):
        return "cloud"
    if g.get("is_hosting"):
        return "hosting"
    return "legit"

GEO_KEYS = [
    "lat",
    "lon",
    "country",
    "country_code",
    "city",
    "asn",
    "asn_name",
    "hostname",
    "is_bot",
    "is_verified_bot",
    "is_cloud",
    "is_hosting",
]


def lean_session(s):
    g = s.get("geo") or {}
    geo = {k: g.get(k) for k in GEO_KEYS}
    return {
        "origin_ip": s.get("origin_ip"),
        "edge_ip": s.get("edge_ip"),
        "geo": geo,
        "intent": s.get("intent"),
        "tags": s.get("tags") or [],
        "is_malicious": is_session_malicious(s),
        "req_count": s.get("req_count", 0),
        "req_rate": s.get("req_rate", 0),
        "first_seen_iso": s.get("first_seen_iso"),
        "last_seen_iso": s.get("last_seen_iso"),
        "path_summary": s.get("path_summary") or [],
        "successful_paths": s.get("successful_paths") or [],
        "failed_scanner_paths": s.get("failed_scanner_paths") or [],
        "status_counts": s.get("status_counts") or {},
    }


def session_ts(s, kind="last"):
    key = "first_seen" if kind == "first" else "last_seen"
    v = s.get(key)
    if isinstance(v, (int, float)) and v > 0:
        return v
    iso = s.get(f"{key}_iso")
    if iso:
        try:
            return datetime.fromisoformat(str(iso)).timestamp()
        except ValueError:
            return 0
    return 0


def main():
    with open(DATA, "r", encoding="utf-8") as f:
        data = json.load(f)

    sessions = data.get("sessions") or []
    sessions = [s for s in sessions if s.get("origin_ip") not in IGNORE_IPS]
    sessions.sort(key=lambda s: session_ts(s, "last"))

    # --- aggregate summary over ALL sessions ---
    total_requests = 0
    unique_ips = set()
    countries = {}
    for s in sessions:
        total_requests += s.get("req_count", 0) or 0
        ip = s.get("origin_ip")
        if ip:
            unique_ips.add(ip)
        g = s.get("geo") or {}
        cc = g.get("country_code") or "??"
        c = countries.setdefault(
            cc,
            {
                "name": g.get("country") or "Unknown",
                "total": 0,
                "mal": 0,
                "ips": set(),
                "blocked": 0,
            },
        )
        c["total"] += s.get("req_count", 0) or 0
        if is_session_malicious(s):
            c["mal"] += s.get("req_count", 0) or 0
        if ip:
            c["ips"].add(ip)
    # countries are JSON-serializable: convert sets to sorted lists
    countries_out = {
        cc: {
            "name": v["name"],
            "total": v["total"],
            "mal": v["mal"],
            "ipCount": len(v["ips"]),
        }
        for cc, v in sorted(countries.items(), key=lambda kv: -kv[1]["total"])
    }

    # --- precomputed aggregates over ALL sessions (used for initial render) ---
    status_totals = [0, 0, 0, 0]  # 2xx, 3xx, 4xx, 5xx
    type_counts = {"legit": 0, "cloud": 0, "hosting": 0, "bot": 0, "malicious": 0}
    path_map = {}
    for s in sessions:
        sc = s.get("status_counts") or {}
        status_totals[0] += sc.get("2xx", 0) or 0
        status_totals[1] += sc.get("3xx", 0) or 0
        status_totals[2] += sc.get("4xx", 0) or 0
        status_totals[3] += sc.get("5xx", 0) or 0
        tt = get_traffic_type(s)
        type_counts[tt] += 1
        stats = s.get("path_stats") or {}
        for p, v in stats.items():
            hits = (v.get("hits") if isinstance(v, dict) else v) or 0
            e = path_map.setdefault(p, {"path": p, "count": 0, "ips": set(), "statuses": {}})
            e["count"] += hits
            ip = s.get("origin_ip")
            if ip:
                e["ips"].add(ip)
            if isinstance(v, dict):
                for code, c in (v.get("statuses") or {}).items():
                    e["statuses"][code] = e["statuses"].get(code, 0) + c

    top_paths = sorted(
        ({"path": p, "count": e["count"], "ips": len(e["ips"]),
          "status": sorted(e["statuses"].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
           if e["statuses"] else None}
         for p, e in path_map.items()),
        key=lambda x: -x["count"],
    )[:50]

    # volume buckets: even buckets across the time range
    n = len(sessions)
    bucket_count = max(1, min(30, n))
    bucket_size = max(1, math.ceil(n / bucket_count))
    volume = []
    for i in range(bucket_count):
        chunk = sessions[i * bucket_size: min((i + 1) * bucket_size, n)]
        if not chunk:
            continue
        reqs = sum(s.get("req_count", 0) or 0 for s in chunk)
        ips = {s.get("origin_ip") for s in chunk if s.get("origin_ip")}
        end_ts = session_ts(chunk[-1], "last")
        volume.append({"reqs": reqs, "ipCount": len(ips), "endTs": end_ts})

    # --- filter catalogs: top paths/IPs/providers -> shard indices ---
    # These are small enough to ride in summary.json. app.js uses them to load
    # only the shards that contain sessions matching a selected filter value.
    CLOUD_PROVIDERS_BS = {
        'Amazon': ['AS14618', 'AS16509'],
        'Google': ['AS396982', 'AS15169'],
        'Microsoft': ['AS8075'],
        'Cloudflare': ['AS13335', 'AS132892'],
        'DigitalOcean': ['AS14061'],
        'Akamai': ['AS63949'],
        'OVH': ['AS16276'],
        'Hetzner': ['AS24940'],
        'Contabo': ['AS141995', 'AS51167', 'AS40021'],
        'Alibaba': ['AS37963'],
    }

    def provider_for(geo):
        asn = geo.get('asn')
        asn_name = (geo.get('asn_name') or '')
        if asn:
            token = 'AS' + str(asn)
            for provider, asns in CLOUD_PROVIDERS_BS.items():
                if token in asns:
                    return provider
        low = asn_name.lower()
        for provider in CLOUD_PROVIDERS_BS:
            if provider.lower() in low:
                return provider
        # Generic hosting/cloud keyword fallback (non-ASN).
        for kw in ('aws', 'amazon', 'google', 'microsoft', 'azure', 'digitalocean',
                   'ovh', 'hetzner', 'contabo', 'alibaba', 'akamai', 'cloudflare',
                   'linode', 'vultr', 'rackspace', 'gcp', 'ec2'):
            if kw in low:
                return provider  # returns last matched; fine as a bucket
        return None

    FILTER_TOP_N = 60
    path_session_count = {}
    path_shards = {}
    ip_session_count = {}
    ip_shards = {}
    provider_session_count = {}
    provider_shards = {}

    total = len(sessions)
    for pos, s in enumerate(sessions):
        shard_idx = pos // SESSIONS_PER_SHARD
        ip = s.get('origin_ip')
        if ip:
            ip_session_count[ip] = ip_session_count.get(ip, 0) + 1
            ip_shards.setdefault(ip, set()).add(shard_idx)
        for p in (s.get('path_summary') or []):
            path_session_count[p] = path_session_count.get(p, 0) + 1
            path_shards.setdefault(p, set()).add(shard_idx)
        g = s.get('geo') or {}
        prov = provider_for(g)
        if prov:
            provider_session_count[prov] = provider_session_count.get(prov, 0) + 1
            provider_shards.setdefault(prov, set()).add(shard_idx)

    def catalog(mapping, shard_map, n):
        ranked = sorted(mapping.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
        out = {}
        for key, count in ranked:
            out[key] = {
                'count': count,
                'shards': sorted(shard_map[key]),
            }
        return out

    filters_catalog = {
        'paths': catalog(path_session_count, path_shards, FILTER_TOP_N),
        'ips': catalog(ip_session_count, ip_shards, FILTER_TOP_N),
        'providers': catalog(provider_session_count, provider_shards, FILTER_TOP_N),
    }

    # --- shard ---
    os.makedirs(SHARD_DIR, exist_ok=True)
    # clear stale shards
    for name in os.listdir(SHARD_DIR):
        if name.startswith("sessions-") and name.endswith(".json"):
            os.remove(os.path.join(SHARD_DIR, name))

    shards = []
    n = len(sessions)
    for start in range(0, n, SESSIONS_PER_SHARD):
        chunk = sessions[start : start + SESSIONS_PER_SHARD]
        idx = start // SESSIONS_PER_SHARD
        fname = f"sessions-{idx:03d}.json"
        fpath = os.path.join(SHARD_DIR, fname)
        lean = [lean_session(s) for s in chunk]
        first_ts = session_ts(chunk[0], "last") if chunk else 0
        last_ts = session_ts(chunk[-1], "last") if chunk else 0
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(lean, f, separators=(",", ":"))
        size = os.path.getsize(fpath)
        shards.append(
            {
                "index": idx,
                "file": f"shards/{fname}",
                "first_idx": start,
                "last_idx": min(start + len(chunk) - 1, n - 1),
                "session_count": len(chunk),
                "first_seen": first_ts,
                "last_seen": last_ts,
                "size": size,
            }
        )

    # --- notables (full list for on-demand modal; lean top subset for sidebar) ---
    notables = data.get("notable") or []
    with open(NOTABLES, "w", encoding="utf-8") as f:
        json.dump(notables, f, separators=(",", ":"))

    import re

    def short_label(label):
        s = re.sub(r"^(RDNS|ASN): ", "", label)
        s = s.replace(" (unverified)", "")
        s = s.replace(" | Actor: unknown", "")
        s = s.replace(" | Confidence: ", " | ")
        return s

    def lean_notable(n):
        return {
            "label": n.get("label", ""),
            "short": short_label(n.get("label", "")),
            "ips": n.get("ips") or [],
            "count": n.get("count", 0),
        }

    # Lean top subset for the sidebar (rDNS, cloud/ASN, other hosting) — small
    # enough to ride in summary.json. Full list loads on demand via notables.json.
    IGNORED_RDNS = {"censys-scanner.com", "internet-measurement.com"}
    rdns_list, asn_list, other_list = [], [], []
    for notable_item in notables:
        lab = notable_item.get("label", "")
        if lab.startswith("Verified"):
            continue
        if lab.startswith("RDNS:"):
            if any(d in lab for d in IGNORED_RDNS):
                continue
            rdns_list.append(lean_notable(notable_item))
        elif lab.startswith("ASN:"):
            asn_list.append(lean_notable(notable_item))
        else:
            other_list.append(lean_notable(notable_item))

    rdns_list.sort(key=lambda x: -x["count"])
    asn_list.sort(key=lambda x: -x["count"])
    other_list.sort(key=lambda x: -x["count"])

    top_notables = {
        "rdns": rdns_list[:4],
        "cloud": asn_list[:4],
        "otherHosting": other_list[:3],
    }

    summary = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "data.json",
        "session_count": n,
        "total_requests": total_requests,
        "unique_origin_ips": len(unique_ips),
        "time_range": {
            "first": session_ts(sessions[0], "last") if sessions else 0,
            "last": session_ts(sessions[-1], "last") if sessions else 0,
        },
        "countries": countries_out,
        "topNotables": top_notables,
        "aggregates": {
            "statusTotals": status_totals,
            "typeCounts": type_counts,
            "topPaths": top_paths,
            "volume": volume,
        },
        "shards": shards,
        "filters": filters_catalog,
    }
    with open(SUMMARY, "w", encoding="utf-8") as f:
        json.dump(summary, f, separators=(",", ":"))

    print(f"sessions: {n}")
    print(f"shards:   {len(shards)}  (max {SESSIONS_PER_SHARD} sessions / ~100 KB each)")
    print(f"notables: {len(notables)}")
    print(f"summary:  {os.path.getsize(SUMMARY) / 1024:.1f} KB")
    print(f"notables: {os.path.getsize(NOTABLES) / 1024:.1f} KB")
    print("done.")


if __name__ == "__main__":
    main()
