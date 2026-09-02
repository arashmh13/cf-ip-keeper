#!/bin/bash
# Boot network gate: wait until real internet connectivity exists (max ~5 min).
# Used as ExecStartPre so scanners never start against a dead network after
# power-restore boot. Plain bash /dev/tcp — no python, no quoting traps.
attempts=0
until (echo > /dev/tcp/1.1.1.1/53) 2>/dev/null; do
  attempts=$((attempts+1))
  [ $attempts -ge 150 ] && { echo "net-gate: giving up after 150 tries"; exit 1; }
  sleep 2
done
# secondary check: DNS resolution must also work (router fully up)
host_ok=0
python3 - <<'PY' 2>/dev/null && host_ok=1
import socket
try:
    socket.getaddrinfo("api.cloudflare.com", 443)
except Exception:
    raise SystemExit(1)
PY
if [ "$host_ok" != "1" ]; then
  # DNS not ready yet — wait a bit more, then proceed anyway (scanner retries)
  sleep 10
fi
echo "net-gate: network ready"
exit 0
