#!/usr/bin/env bash
# setup-ipsets.sh — Create ipset sets and iptables rules for IP blocking
# Run once on a fresh server. Idempotent (safe to re-run).

set -euo pipefail

echo "=== Creating ipsets ==="

# Individual abusive IPs (hash:ip for exact match)
ipset list abusive_ips >/dev/null 2>&1 || {
    ipset create abusive_ips hash:ip hashsize 8192 maxelem 65536
    echo "Created abusive_ips (hash:ip)"
}

# Scanner network CIDR ranges (hash:net for prefix match)
ipset list scanner_nets >/dev/null 2>&1 || {
    ipset create scanner_nets hash:net hashsize 1024 maxelem 65536
    echo "Created scanner_nets (hash:net)"
}

# Country-level CIDR blocks (hash:net)
ipset list blocked_countries >/dev/null 2>&1 || {
    ipset create blocked_countries hash:net hashsize 4096 maxelem 65536
    echo "Created blocked_countries (hash:net)"
}

echo "=== Populating scanner_nets with known ranges ==="

# Censys
for net in 162.142.125.0/24 167.94.138.0/24 167.94.145.0/24 167.94.146.0/24 \
           167.248.133.0/24 66.132.0.0/16 185.247.137.0/24; do
    ipset add scanner_nets "$net" 2>/dev/null || true
done

# Shodan
for net in 71.6.146.0/24 71.6.147.0/24 71.6.158.0/24 71.6.165.0/24 \
           198.20.69.0/24 198.20.70.0/24 198.20.71.0/24 198.20.87.0/24 198.20.99.0/24; do
    ipset add scanner_nets "$net" 2>/dev/null || true
done

# Shadowserver
for net in 184.105.139.0/24 184.105.247.0/24 216.218.206.0/24 74.82.47.0/24 \
           204.42.253.0/24 204.42.254.0/24 212.102.45.0/24; do
    ipset add scanner_nets "$net" 2>/dev/null || true
done

# Internet-measurement (RWTH Aachen)
ipset add scanner_nets 87.236.176.0/24 2>/dev/null || true

echo "=== Adding iptables rules ==="

# Check if rules already exist before adding
iptables -C INPUT -m set --match-set abusive_ips src -j DROP 2>/dev/null || {
    iptables -A INPUT -m set --match-set abusive_ips src -j DROP
    echo "Added abusive_ips DROP rule"
}

iptables -C INPUT -m set --match-set scanner_nets src -j DROP 2>/dev/null || {
    iptables -A INPUT -m set --match-set scanner_nets src -j DROP
    echo "Added scanner_nets DROP rule"
}

iptables -C INPUT -m set --match-set blocked_countries src -j DROP 2>/dev/null || {
    iptables -A INPUT -m set --match-set blocked_countries src -j DROP
    echo "Added blocked_countries DROP rule"
}

echo "=== Persisting ==="

ipset save abusive_ips > /etc/ipset-abusive.conf
ipset save scanner_nets > /etc/ipset-scanners.conf
ipset save blocked_countries > /etc/ipset-countries.conf
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo "=== Done ==="
echo "Next steps:"
echo "  1. Populate blocked_countries with country CIDR ranges (see load-country-blocks.sh)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "  2. Add cron job: 0 */6 * * * $SCRIPT_DIR/block-scanner-ips.sh"
