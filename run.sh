#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
set -a; source keeper.env; set +a
exec python3 cf_ip_keeper.py "$@"
