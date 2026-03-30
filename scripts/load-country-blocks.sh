#!/usr/bin/env bash
# load-country-blocks.sh — Download and load country CIDR blocks into ipset
# Source: ipdeny.com aggregated zone files
# Usage: ./load-country-blocks.sh [country codes...]
# Example: ./load-country-blocks.sh ru by kz ir kp cn in br ph id vn ng

set -euo pipefail

IPSET_NAME="blocked_countries"
PERSIST="/etc/ipset-countries.conf"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <country_code> [country_code ...]"
    echo "Example: $0 ru by kz ir kp cn in br ph id vn ng"
    exit 1
fi

TOTAL=0
for cc in "$@"; do
    cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
    url="https://www.ipdeny.com/ipblocks/data/aggregated/${cc_lower}-aggregated.zone"

    echo -n "Downloading ${cc_lower}... "
    tmpfile=$(mktemp)
    if curl -sf "$url" -o "$tmpfile"; then
        count=$(wc -l < "$tmpfile")
        echo "${count} ranges"

        added=0
        while IFS= read -r net; do
            [ -z "$net" ] && continue
            ipset add "$IPSET_NAME" "$net" 2>/dev/null && added=$((added+1))
        done < "$tmpfile"
        echo "  Added ${added} new ranges for ${cc_lower}"
        TOTAL=$((TOTAL + added))
    else
        echo "FAILED (check country code)"
    fi
    rm -f "$tmpfile"
done

echo "=== Total new ranges: ${TOTAL} ==="
ipset save "$IPSET_NAME" > "$PERSIST"
echo "Persisted to ${PERSIST}"
