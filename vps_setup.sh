#!/bin/bash
# One-time VPS setup: systemd scanner + cron checker
set -e
cd /opt/cf-ip-keeper
rm -f cursor.json state.json scanner.log checker.log

# Install systemd service
cp cf-ip-scan.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cf-ip-scan.service

# Install 30-min health-check cron
(crontab -l 2>/dev/null | grep -v cf-ip-keeper; echo '*/30 * * * * cd /opt/cf-ip-keeper && bash check.sh >> checker.log 2>&1') | crontab -

sleep 6
echo "--- service ---"
systemctl is-active cf-ip-scan
echo "--- cron ---"
crontab -l | grep cf-ip
echo "--- scanner log ---"
tail -3 /opt/cf-ip-keeper/scanner.log 2>/dev/null
echo "--- DONE ---"
