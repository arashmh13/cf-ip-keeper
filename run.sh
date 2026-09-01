#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
# source keeper.env tolerantly: works even if the file has CRLF (Windows) endings
set -a; eval "$(tr -d '\r' < keeper.env | grep -E '^[A-Z_]+=')"; set +a
exec python3 cf_ip_keeper.py "$@"
