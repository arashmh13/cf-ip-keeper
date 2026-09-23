#!/usr/bin/env bash
# Continuous scanner daemon: walks ranges_Iran.txt forever, appends to foundedIPs_Iran.txt.
# WORKERS/PROBE_TIMEOUT come from sections_config.json (section "Iran"), so GUI
# edits actually apply to the scanner. Fallbacks: 16 / 6.
cd "$(dirname "$0")" || exit 1
# source keeper.env tolerantly: works even if the file has CRLF (Windows) endings
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')" ; set +a
CFGW="$(python3 -c "import json;print(json.load(open('sections_config.json'))['sections'].get('Iran',{}).get('workers',16))" 2>/dev/null)"
CFGT="$(python3 -c "import json;print(json.load(open('sections_config.json'))['sections'].get('Iran',{}).get('probe_timeout',6))" 2>/dev/null)"
export WORKERS="${CFGW:-16}" PROBE_TIMEOUT="${CFGT:-6}"
# IR section: the CIDR list alone is not enough (host-announced ranges can be
# physically foreign), so every in-list find is country-verified and non-IR
# finds are redirected to EthernetServer instead of entering the IR pool.
# GEO_PROXY is REQUIRED on this box: its direct DNS resolution fails, so
# without the proxy the geo lookup returns nothing and the check no-ops.
export SECTION="Iran" REDIRECT_SECTION="EthernetServer"
export GEO_COUNTRY="IR" GEO_PROXY="http://127.0.0.1:20171"
while true; do
  python3 -u scan_loop.py >> scanner.log 2>&1
  echo "$(date -Is) loop exited, restarting in 5s" >> scanner.log
  sleep 5
done
