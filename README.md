# Log Analyzer Pro

Real-time web traffic analysis dashboard with geographic visualization, traffic classification, and threat detection.

![Dashboard](https://img.shields.io/badge/stack-HTML%20%2B%20JS-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Interactive Map** -- Leaflet-based world map with per-session markers color-coded by traffic type, blocked country overlays with "BLOCKED" labels
- **Traffic Classification** -- Automatic categorization into legitimate, cloud, hosting, bot, and malicious traffic
- **Scanner Detection** -- Pattern-matching engine flags requests to well-known exploit paths (WordPress probing, `.env` harvesting, path traversal, PHP shells)
- **Notable Organizations** -- Identifies visitors by rDNS and ASN, grouped into cloud providers vs other hosting, with location data and Google search links in the pop-out modal
- **Country Drill-Down** -- Click any country in the country report modal to expand a full IP table with traffic type, request count, last seen timestamp, and requested paths
- **Blocked IP Indicators** -- `GEO-BLK` and `IP-BLK` badges throughout the live feed, map popups, and country reports for at-a-glance block verification
- **Live Feed** -- Scrollable traffic table with full date+time stamps, IP reputation links, and blocked status indicators
- **Playback** -- Timeline scrubber with adjustable speed to replay traffic patterns

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-username/log-analyzer.git
cd log-analyzer

# Serve locally (Python)
cd html
python3 -m http.server 8080

# Open http://localhost:8080
```

The dashboard expects a `data.json` file in the `html/` directory. A `data.sample.json` is included for reference. Copy it to get started:

```bash
cp html/data.sample.json html/data.json
```

## Architecture

```
html/
  index.html              # Dashboard shell, modals, Leaflet/Chart.js setup
  app.js                  # All application logic
  styles.css              # Dark theme styles
  countries.geojson       # World borders for blocked country overlay
  data.json               # Session data (gitignored, you provide this)
  data.sample.json        # Example data with RFC 5737 documentation IPs

scripts/
  block-scanner-ips.sh    # Cron job: extract malicious IPs from data.json → ipset
  setup-ipsets.sh         # One-time: create ipsets + iptables rules
  load-country-blocks.sh  # Download country CIDR ranges from ipdeny.com → ipset
  nginx-exploit-paths.conf # nginx snippet: 403 on exploit paths (WordPress, .env, etc.)
```

Zero backend dependencies. The dashboard is a static site that reads a single JSON file.

## Data Format

The dashboard consumes a `data.json` file with three top-level keys:

### `sessions` (array)

Each session represents a cluster of requests from one IP:

```json
{
  "origin_ip": "203.0.113.42",
  "edge_ip": "203.0.113.42",
  "geo": {
    "city": "Frankfurt am Main",
    "country": "Germany",
    "country_code": "DE",
    "hostname": "example.host.com",
    "asn": 24940,
    "asn_name": "Hetzner Online GmbH",
    "is_bot": false,
    "is_verified_bot": false,
    "is_cloud": false,
    "is_hosting": true,
    "lat": 50.1109,
    "lon": 8.6821
  },
  "first_seen": 1711800000.0,
  "last_seen": 1711800060.0,
  "intent": "Passive Traffic",
  "tags": ["crawler"],
  "is_malicious": false,
  "req_count": 15,
  "req_rate": 0.25,
  "is_spike": false,
  "first_seen_iso": "2025-03-30T12:00:00",
  "last_seen_iso": "2025-03-30T12:01:00",
  "path_summary": ["/", "/robots.txt"]
}
```

### `notable` (array)

Organizations identified by rDNS or ASN:

```json
{
  "label": "ASN: AS16509 (Amazon.com, Inc.) | Confidence: hosting provider only | Actor: unknown",
  "ips": ["203.0.113.10", "203.0.113.11"],
  "count": 2
}
```

Label prefixes determine categorization:
- `RDNS:` -- reverse DNS identified (displayed with location, linked to Google search for the IP)
- `ASN:` -- ASN-based identification (grouped into cloud providers vs other hosting, linked to Google search for the ASN)
- `Verified Actor:` -- confirmed bot identity (filtered from display)

### `summary` (object)

```json
{
  "total_requests": 6324,
  "unique_origin_ips": 630,
  "updated_at": "2025-03-30T21:37:55",
  "countries": {
    "US": { "legit": 136, "bots": 88, "malicious": 61, "name": "United States" }
  }
}
```

## Configuration

All configuration is in `app.js` constants at the top of the file:

| Constant | Purpose |
|----------|---------|
| `BLOCKED_COUNTRIES` | ISO country codes shown as blocked on the map and flagged in all views |
| `CLOUD_PROVIDERS` | ASN-to-provider mapping for grouping notables (Amazon, Google, Microsoft, Cloudflare, DigitalOcean, Akamai, OVH, Hetzner, Contabo, Alibaba) |
| `IGNORED_RDNS` | rDNS domains excluded from notables (e.g. `censys-scanner.com`, `internet-measurement.com`) |
| `MALICIOUS_PATHS` | Regex patterns that flag sessions as malicious regardless of source |
| `TRAFFIC_COLORS` | Color scheme for traffic type categories |

## Traffic Types

| Type | Color | Criteria |
|------|-------|----------|
| Legitimate | Cyan `#00f2ff` | No bot/cloud/hosting/malicious flags |
| Cloud | Purple `#a855f7` | `geo.is_cloud` is true |
| Hosting | Green `#22c55e` | `geo.is_hosting` is true |
| Bot | Amber `#ffaa00` | `geo.is_bot` is true |
| Malicious | Red `#f43f5e` | `is_malicious` or hits scanner path patterns |

## Blocked IP Indicators

The dashboard shows two types of block badges:

| Badge | Meaning |
|-------|---------|
| `GEO-BLK` | IP is from a country in the `BLOCKED_COUNTRIES` list |
| `IP-BLK` | IP is individually flagged as malicious (scanner paths, known attacker) |
| `BLK` | Shown in country reports for blocked countries |

These appear in the live feed, map popups, and country detail tables. Useful for verifying that firewall rules (ipset, iptables, nginx) are functioning correctly.

## Integration with IP Blocking

The `scripts/` directory contains everything needed to enforce blocking at the server level. The system uses three layers:

### Layer 1: Firewall (ipset + iptables)

```bash
# One-time setup: create ipsets and iptables rules
sudo ./scripts/setup-ipsets.sh

# Load country CIDR blocks (downloads from ipdeny.com)
sudo ./scripts/load-country-blocks.sh ru by kz ir kp cn in br ph id vn ng
```

This creates three ipsets:

| ipset | Type | Purpose |
|-------|------|---------|
| `abusive_ips` | hash:ip | Individual malicious IPs and CDN-proxied IPs from blocked countries |
| `scanner_nets` | hash:net | Censys, Shodan, internet-measurement CIDR ranges |
| `blocked_countries` | hash:net | Country-level CIDR blocks |

### Layer 2: Automated IP extraction (cron)

```bash
# Add to crontab (runs every 6 hours)
echo "0 */6 * * * $(pwd)/scripts/block-scanner-ips.sh" | sudo crontab -
```

`block-scanner-ips.sh` reads `data.json` and:
- Blocks IPs hitting exploit paths (WordPress, `.env`, `.git`, PHP shells, etc.)
- Blocks IPs from geo-blocked countries, **including CDN-proxied traffic** (Cloudflare, etc.)
- Adds scanner rDNS matches (Censys, Shodan, etc.) to the scanner_nets set
- **[Optional]** Checks uncategorized IPs against AbuseIPDB and auto-reports malicious activity (requires API key)
- Persists all changes to disk

Edit `BLOCKED_COUNTRIES`, `MALICIOUS_PATHS`, `SAFE_PATHS`, and `SCANNER_RDNS` at the top of the script to customize.

**AbuseIPDB Integration (Optional):**
To enable automated threat intelligence checking and reporting, create a free account on [AbuseIPDB](https://www.abuseipdb.com/) and save your API key to `/etc/abuseipdb.key`:
```bash
echo "YOUR_API_KEY" | sudo tee /etc/abuseipdb.key
sudo chmod 600 /etc/abuseipdb.key
```
The script will automatically pick it up and use it to block unknown IPs that exceed the threat threshold, as well as report confirmed attackers.

### Layer 3: nginx path blocking

```nginx
# Add to your nginx server block
include /path/to/scripts/nginx-exploit-paths.conf;
```

Returns 403 for all known exploit paths. This catches attacks that bypass IP-level rules (e.g. traffic proxied through Cloudflare WARP).

## Generating data.json

The dashboard is data-source agnostic. You can generate `data.json` from any web server log format. A typical pipeline:

1. Parse nginx/Apache access logs
2. Enrich IPs with GeoIP and ASN data (MaxMind, ipinfo.io, etc.)
3. Cluster requests by IP into sessions
4. Classify intent (bot detection, rate analysis)
5. Identify notable organizations via rDNS and ASN lookup
6. Output the JSON structure above

## Dependencies

All loaded from CDN (no `npm install` required):

- [Leaflet](https://leafletjs.com/) v1.9.4 -- Map rendering
- [Chart.js](https://www.chartjs.org/) -- Status/type/volume charts
- [chartjs-plugin-datalabels](https://chartjs-plugin-datalabels.netlify.app/) -- Chart label overlays
- [Lucide Icons](https://lucide.dev/) -- UI icons
- [Inter](https://rsms.me/inter/) -- Font

## License

MIT
