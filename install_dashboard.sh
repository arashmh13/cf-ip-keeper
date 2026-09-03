#!/bin/bash
# CF IP Keeper dashboard installer for generic Linux/Ubuntu (and ZimaOS-compatible).
# - copies dashboard.py + dashboard.html + icon.svg next to your project files
#   (default: /opt/cf-ip-keeper; override with $1)
# - installs cf-ip-dash.service (port 8787) enabled at boot
# - optional: passwordless sudoers so the UI control buttons work
# Usage: sudo bash install_dashboard.sh [project_dir]
set -e
DIR="${1:-/opt/cf-ip-keeper}"
SRC="$(cd "$(dirname "$0")" && pwd)"

[ -d "$DIR" ] || { echo "ERROR: project dir $DIR not found (create it first or pass a path)"; exit 1; }
for f in dashboard.py dashboard.html icon.svg; do
  [ -f "$SRC/$f" ] && cp "$SRC/$f" "$DIR/$f"
done
echo "copied dashboard files to $DIR"

UNIT=/etc/systemd/system/cf-ip-dash.service
cat > "$UNIT" <<EOF
[Unit]
Description=CF IP Keeper dashboard (glass control tower, port 8787)
After=network.target

[Service]
WorkingDirectory=$DIR
Environment=DASH_PORT=8787
ExecStart=/usr/bin/python3 $DIR/dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cf-ip-dash.service
sleep 2
systemctl is-active cf-ip-dash.service && echo "dashboard: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8787/ (also http://localhost:8787/)"

# optional: allow control buttons (start/stop/restart cf-ip-* units) without password
if [ -d /etc/sudoers.d ] && [ ! -f /etc/sudoers.d/cf-ip-keeper ]; then
  cat > /etc/sudoers.d/cf-ip-keeper <<'EOF'
# CF IP Keeper dashboard: control the cf-ip-* units without password prompt
ALL ALL=(root) NOPASSWD: /usr/bin/systemctl start cf-ip-*, /usr/bin/systemctl stop cf-ip-*, /usr/bin/systemctl restart cf-ip-*, /usr/bin/systemctl start cf-ip-check.service, /usr/bin/systemctl is-active cf-ip-*
EOF
  chmod 440 /etc/sudoers.d/cf-ip-keeper
  visudo -cf /etc/sudoers.d/cf-ip-keeper >/dev/null && echo "sudoers rule installed (UI control buttons enabled)"
fi
echo "DONE"
