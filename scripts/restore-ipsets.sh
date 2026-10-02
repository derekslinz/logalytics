#!/usr/bin/env bash
# restore-ipsets.sh — Restore persisted ipsets and iptables rules at boot.
#
# ipsets are kernel state and are lost on every reboot. The persist files are
# written by enforce-ipset-blocks.sh (abusive_ips, scanner_nets) and
# load-country-blocks.sh (blocked_countries). Without this, a reboot leaves
# the sets empty, iptables rules gone, and enforce-ipset-blocks.sh aborting
# under `set -e` on the first `ipset save`.
#
# Runs from a systemd unit, so it must not depend on cron.

set -uo pipefail

LOG="/var/log/enforce-ipset-blocks.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "$(date -Iseconds) restore-ipsets: $*" >> "$LOG"; }

# Entry count for a set. `ipset count <name>` is not reliable across ipset
# versions, so parse the "Number of entries" field from `ipset list`.
count_entries() {
    ipset list "$1" 2>/dev/null | sed -n 's/^Number of entries: //p'
}

# Drop all set-based rules BEFORE restoring. A set that is still referenced by
# an iptables rule cannot be destroyed, which makes `ipset restore` fail with
# "set with the same name already exists".
for set_name in abusive_ips scanner_nets blocked_countries; do
    while iptables -C INPUT -m set --match-set "$set_name" src -j LOG 2>/dev/null; do
        iptables -D INPUT -m set --match-set "$set_name" src -j LOG 2>/dev/null || break
    done
    while iptables -C INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null; do
        iptables -D INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null || break
    done
done

# Restore any set that has a persist file.
# `ipset restore` re-creates the set from the "create" line in the dump and
# aborts with "set with the same name already exists" if it is present, so the
# existing set must be destroyed first. Entries are restored even if the set
# is currently in use, since we drop the referencing rules first.
restore_set() {
    local conf="$1" name="$2"
    [ -s "$conf" ] || return 0
    ipset destroy "$name" 2>/dev/null
    if ipset restore < "$conf" 2>>"$LOG"; then
        log "restored ipset $name ($(count_entries "$name") entries)"
    else
        log "WARN: failed to restore ipset $name from $conf"
    fi
}

restore_set /etc/ipset-abusive.conf abusive_ips
restore_set /etc/ipset-scanners.conf scanner_nets

# blocked_countries is NOT restored from a dump: log_update_countries.sh never
# calls `ipset save`, so /etc/ipset-countries.conf only holds the "create"
# line and restoring it would yield an empty set. That script is already
# self-healing (ipset create -exist + swap), so just run it to refetch CIDRs.
if [ -x /usr/local/bin/log_update_countries.sh ]; then
    /usr/local/bin/log_update_countries.sh >> "$LOG" 2>&1
    log "rebuilt blocked_countries ($(count_entries blocked_countries) entries)"
else
    log "WARN: log_update_countries.sh missing, blocked_countries left empty"
fi

# Run setup-ipsets.sh LAST. It ends with `ipset save`, which would overwrite
# the persist files with the current (empty, just-created) sets if it ran
# before restore_set read them. Here it only ensures the sets and iptables
# rules exist as a fallback for anything that failed to restore.
# shellcheck source=/dev/null
[ -f "$SCRIPT_DIR/setup-ipsets.sh" ] && bash "$SCRIPT_DIR/setup-ipsets.sh" >> "$LOG" 2>&1

# setup-ipsets.sh persists whatever is in memory, which is correct now that
# the entries are restored. Re-assert the DROP rules it may not have added.
for set_name in abusive_ips scanner_nets blocked_countries; do
    iptables -C INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null || \
        iptables -I INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null
done

# Re-assert the DROP rules. setup-ipsets.sh already added them, but restore
# them idempotently in case the ordering above replaced the table.
for set_name in abusive_ips scanner_nets blocked_countries; do
    iptables -C INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null || \
        iptables -I INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null
done

log "firewall restore complete"
