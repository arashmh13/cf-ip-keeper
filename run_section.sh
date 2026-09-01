#!/bin/bash
# Run one section: continuous scanner (background) + keeper loop (every N min)
# Usage: bash run_section.sh <SectionName>
SEC="$1"
cd "$(dirname "$0")" || exit 1

# source keeper.env tolerantly: works even if the file has CRLF (Windows) endings
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')"; set +a
PY=$(command -v python3 || command -v python)

# pull per-section settings from sections_config.json
CFG_OUT=$("$PY" -c "
import json, sys
cfg = json.load(open('sections_config.json'))
s = cfg['sections'].get(sys.argv[1], {})
print(s.get('records',''), s.get('workers',2), s.get('check_interval_min',60), s.get('margin_ms',30), s.get('probe_timeout',6))
" "$SEC")
read -r RECORDS WORKERS INTERVAL MARGIN TIMEOUT <<<"$CFG_OUT"

export SECTION="$SEC" CF_RECORDS="$RECORDS" WORKERS="$WORKERS" MARGIN_MS="$MARGIN" PROBE_TIMEOUT="$TIMEOUT"
echo "$(date -Is) [$SEC] launch: records=$RECORDS workers=$WORKERS interval=${INTERVAL}min"

# continuous scanner
"$PY" -u scan_loop.py >> "scanner_$SEC.log" 2>&1 &
SCAN_PID=$!

# keeper loop: check every INTERVAL minutes (creates/updates this section's records)
while true; do
  sleep $((INTERVAL * 60))
  CHECK_ONLY=1 WORKERS=1 "$PY" -u cf_ip_keeper.py >> "checker_$SEC.log" 2>&1
done &
KEEP_PID=$!

trap "kill $SCAN_PID $KEEP_PID 2>/dev/null" EXIT
wait
