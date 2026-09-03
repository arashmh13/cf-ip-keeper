#!/bin/bash
# WSL final-stage test: run dashboard against a test project dir with synthetic
# state, verify HTTP + SSE + status API, WITHOUT touching real ZimaOS.
set -e
TD=/tmp/cfk-dash-test
rm -rf $TD && mkdir -p $TD
cd $TD

# synthetic project state (no real secrets, RFC5737 IPs)
echo '203.0.113.10 441' > foundedIPs.txt
echo '198.51.100.7 512' >> foundedIPs.txt
cat > cursor.json <<'EOF'
{"i": 165, "j": 100}
EOF
cat > state.json <<'EOF'
{"203.0.113.10": {"ms": 441, "ts": 1756900000}, "198.51.100.7": {"ms": 512, "ts": 1756900100}}
EOF
echo '{"203.0.113.0/24": 1, "198.51.100.0/24": 1}' > hits.json
cat > ranges.txt <<'EOF'
203.0.113.0/24
198.51.100.0/24
192.0.2.0/24
EOF
cat > sections_config.json <<'EOF'
{"global": {}, "sections": {"Iran": {"records": "cn.example.com,cn2.example.com", "workers": 8},
  "Hetzner": {"records": "hz.example.com", "workers": 4}}}
EOF
# logs: one with finds, one empty section
printf '2026-09-03 22:00:00 start: 3 nets [workers=8]\n2026-09-03 22:00:05 FOUND 203.0.113.10 441ms\n2026-09-03 22:00:09 FOUND 198.51.100.7 512ms\n' > scanner.log
printf '2026-09-03 22:05:00 [Hetzner] start: 91 nets [workers=4]\n' > scanner_Hetzner.log
printf '2026-09-03 22:10:00 keeping cn.example.com=203.0.113.10 (441ms); best alt 198.51.100.7 512ms\n' > checker.log
printf '2026-09-03 22:11:00 [Hetzner] no alive relay found; DNS untouched\n' > checker_Hetzner.log

cp /mnt/c/Users/arash/cf-ip-keeper/dashboard.py /mnt/c/Users/arash/cf-ip-keeper/dashboard.html /mnt/c/Users/arash/cf-ip-keeper/icon.svg .
python3 -m py_compile dashboard.py && echo COMPILE-OK

DASH_PORT=8787 python3 dashboard.py > dash.log 2>&1 &
DPID=$!
sleep 2

echo "== HTTP / =="
curl -s -o /dev/null -w "html:%{http_code}\n" http://localhost:8787/
echo "== API /api/status =="
curl -s http://localhost:8787/api/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('sections:', len(d['sections']), '| active:', d['active_services'], '/', d['total_services'])
for s in d['sections']:
    if s['name'] in ('Iran', 'Hetzner'):
        print(f\"{s['name']}: found={s['found']} cursor=#{s['cursor_i']}+{s['cursor_j']}/{s['nets']} record={s['record_ip']} ({s['record_ms']}ms) active={s['active']}\")
"
echo "== logs API =="
curl -s "http://localhost:8787/api/logs?file=scanner.log&n=10" | python3 -c "import sys,json; print('lines:', len(json.load(sys.stdin)['lines']))"
echo "== SSE stream (2s sample) =="
timeout 2 curl -sN http://localhost:8787/stream?file=scanner.log | head -4
echo "== SSE: appending a live line and checking it arrives =="
( sleep 1; printf '2026-09-03 22:12:00 FOUND 203.0.113.99 777ms\n' >> scanner.log ) &
timeout 4 curl -sN http://localhost:8787/stream?file=scanner.log | grep -m1 "203.0.113.99" && echo "SSE-LIVE-TAIL-OK"
echo "== bad file rejected =="
curl -s "http://localhost:8787/api/logs?file=keeper.env" | head -c 40; echo

kill $DPID 2>/dev/null || true
echo "TEST-COMPLETE"
