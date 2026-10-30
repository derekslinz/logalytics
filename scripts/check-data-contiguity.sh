#!/usr/bin/env bash
# check-data-contiguity.sh — Fail loudly if data.json develops a date gap.
#
# Context: in April 2026 the nginx logs stopped rotating for ~5 months. The
# analyzer kept running and kept producing valid output, so nothing errored —
# the dashboard just quietly showed two disjoint time periods (11 Apr, then
# 18 Sep onward) with a hole in between. This guard exists so that class of
# silent gap is caught instead of discovered by eye.
#
# Exits non-zero (and writes to $LOG) if there is more than MAX_GAP_DAYS
# between consecutive days that have sessions.

set -uo pipefail

DATA_JSON="${DATA_JSON:-/var/www/logalytics/html/data.json}"
LOG="${LOG:-/var/log/enforce-ipset-blocks.log}"
MAX_GAP_DAYS="${MAX_GAP_DAYS:-2}"

if [ ! -f "$DATA_JSON" ]; then
    echo "$(date -Iseconds) CONTIGUITY ERROR: $DATA_JSON not found" >> "$LOG"
    exit 1
fi

RESULT=$(python3 - "$DATA_JSON" "$MAX_GAP_DAYS" <<'PYEOF'
import json, sys, datetime

data_path, max_gap = sys.argv[1], int(sys.argv[2])
try:
    with open(data_path) as f:
        data = json.load(f)
except Exception as e:
    print(f"ERROR could not read data.json: {e}")
    sys.exit(1)

sessions = data.get('sessions') or []
if not sessions:
    print("WARN no sessions in data.json (analyzer may not have run yet)")
    sys.exit(0)

def parse_ts(s):
    v = s.get('last_seen_iso') or s.get('last_seen')
    if isinstance(v, (int, float)):
        return v / 1000 if v > 1e11 else v
    try:
        return datetime.datetime.fromisoformat(str(v).replace('Z', '+00:00')).timestamp()
    except Exception:
        return None

days = set()
for s in sessions:
    ts = parse_ts(s)
    if ts:
        days.add(datetime.date.fromtimestamp(ts))

if not days:
    print("WARN no parseable timestamps")
    sys.exit(0)

ordered = sorted(days)
gaps = []
for a, b in zip(ordered, ordered[1:]):
    delta = (b - a).days
    if delta > max_gap:
        gaps.append(f"{a} -> {b} ({delta}d)")

span = f"{ordered[0]} to {ordered[-1]} ({len(ordered)} active days)"
if gaps:
    print(f"GAPS [{span}]: " + "; ".join(gaps))
    sys.exit(1)

print(f"OK [{span}]")
PYEOF
)

STATUS=$?
echo "$(date -Iseconds) CONTIGUITY: $RESULT" >> "$LOG"

if [ "$STATUS" -ne 0 ]; then
    echo "data.json has date gaps: $RESULT"
    exit 1
fi

exit 0