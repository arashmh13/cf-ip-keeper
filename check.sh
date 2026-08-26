#!/usr/bin/env bash
# Health checker: re-probes every found IP + the record's IP (thr=1 equivalent, -try 3),
# replaces the Cloudflare A record when current is dead or beaten by >30ms.
cd "$(dirname "$0")" || exit 1
set -a; source keeper.env; set +a
export WORKERS=1 PROBE_TIMEOUT=6 MARGIN_MS=30 CHECK_ONLY=1
exec python3 cf_ip_keeper.py "$@"
