#!/bin/bash
# Run one section: continuous scanner only.
# DNS keeping for ALL sections is centralized in the 30-min systemd timer
# (cf-ip-check.service -> zima_keeper_pass.sh) so there is exactly ONE
# DNS writer cadence: every 30 minutes, recheck found IPs + live records.
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
print(s.get('records',''), s.get('workers',2), s.get('margin_ms',30), s.get('probe_timeout',6))
" "$SEC")
read -r RECORDS WORKERS MARGIN TIMEOUT <<<"$CFG_OUT"

export SECTION="$SEC" CF_RECORDS="$RECORDS" WORKERS="$WORKERS" MARGIN_MS="$MARGIN" PROBE_TIMEOUT="$TIMEOUT"
echo "$(date -Is) [$SEC] launch scanner: workers=$WORKERS"

# continuous scanner (keeper loop removed: see zima_keeper_pass.sh + cf-ip-check.timer)
"$PY" -u scan_loop.py >> "scanner_$SEC.log" 2>&1 &
SCAN_PID=$!
trap "kill $SCAN_PID 2>/dev/null" EXIT
wait
