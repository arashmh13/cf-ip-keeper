#!/bin/bash
# ONE keeper pass for ALL sections (called by cf-ip-check.timer every 30 min).
# Rechecks each section's found-IP pool + live DNS record; creates missing
# records, swaps dead ones. Iran (cn/cn2) runs FIRST.
cd /DATA/cf-ip-keeper || exit 1
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')"; set +a
PY=$(command -v python3 || command -v python)

echo "=== [Iran cn/cn2]"
CHECK_ONLY=1 WORKERS=1 "$PY" -u cf_ip_keeper.py >> checker.log 2>&1
tail -2 checker.log

for s in Hetzner AmazonAWS Aeza DigitalOcean EthernetServer IONOS; do
  R=$("$PY" -c "import json; print(json.load(open('sections_config.json'))['sections']['$s']['records'])")
  echo "=== [$s] records=$R"
  SECTION="$s" CF_RECORDS="$R" CHECK_ONLY=1 WORKERS=1 \
    "$PY" -u cf_ip_keeper.py >> "checker_$s.log" 2>&1
  tail -2 "checker_$s.log"
done
echo KEEPER-PASS-DONE
