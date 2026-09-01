#!/usr/bin/env bash
# Continuous scanner daemon: walks ranges.txt forever, WORKERS=8, appends to foundedIPs.txt.
cd "$(dirname "$0")" || exit 1
# source keeper.env tolerantly: works even if the file has CRLF (Windows) endings
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')"; set +a
export WORKERS=8 PROBE_TIMEOUT=6
while true; do
  python3 -u scan_loop.py >> scanner.log 2>&1
  echo "$(date -Is) loop exited, restarting in 5s" >> scanner.log
  sleep 5
done
