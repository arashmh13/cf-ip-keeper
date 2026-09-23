#!/bin/bash
# ONE keeper pass for ALL sections (called by cf-ip-check.timer every 30 min).
# Rechecks each section's found-IP pool + live DNS records; creates missing
# records, swaps dead ones. Iran (cn/cn2) runs FIRST and is GEO-GATED to
# Iranian ranges (ir_gate.txt) — foreign IPs can never be assigned.
#
# The keeper enforces the hard invariant: a sibling record never receives an IP
# that another record in the same section already owns (cn != cn2, always).
cd /DATA/cf-ip-keeper || exit 1
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')" ; set +a
PY=$(command -v python3 || command -v python)

echo "=== [Iran cn/cn2] (geo-gated, strict)"
# GEO_STRICT=1: fail closed when the country cannot be resolved, so a foreign IP
# is never assigned just because the geo API blinked. GEO_PROXY is required on
# this box (direct DNS resolution fails).
SECTION=Iran CHECK_ONLY=1 WORKERS=1 GATE_FILE=ir_gate.txt GATE_COUNTRY=IR GEO_STRICT=1 \
  GEO_PROXY=http://127.0.0.1:20171 CF_API_PROXY=http://127.0.0.1:20171 \
  "$PY" -u cf_ip_keeper.py >> checker.log 2>&1
tail -3 checker.log

for s in Hetzner AmazonAWS Aeza DigitalOcean EthernetServer IONOS; do
  R=$("$PY" -c "import json; print(json.load(open('sections_config.json'))['sections']['$s']['records'])")
  echo "=== [$s] records=$R"
  SECTION="$s" CF_RECORDS="$R" CHECK_ONLY=1 WORKERS=1 \
    "$PY" -u cf_ip_keeper.py >> "checker_$s.log" 2>&1
  tail -2 "checker_$s.log"
done
echo KEEPER-PASS-DONE
