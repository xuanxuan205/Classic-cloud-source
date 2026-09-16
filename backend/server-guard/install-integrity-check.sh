#!/bin/bash
# ============================================================
# IronWall v1.25.1 - Free file integrity installer
# Usage: bash install-integrity-check.sh
# ============================================================
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Please run as root: bash install-integrity-check.sh"
  exit 1
fi

echo "[1/3] Installing integrity checker ..."
cp -f check-ironwall-integrity.sh /usr/local/bin/check-ironwall-integrity.sh
chmod 755 /usr/local/bin/check-ironwall-integrity.sh

echo "[2/3] Preparing state dir ..."
mkdir -p /www/wwwroot/jdy-cloud/logs
chown www:www /www/wwwroot/jdy-cloud/logs
chmod 755 /www/wwwroot/jdy-cloud/logs

echo "[3/3] Installing hourly cron ..."
CRON_LINE='0 * * * * /usr/local/bin/check-ironwall-integrity.sh >/dev/null 2>&1'
if crontab -l 2>/dev/null | grep -Fq "check-ironwall-integrity.sh"; then
  echo "cron already present, skip"
else
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "cron installed"
fi

/usr/local/bin/check-ironwall-integrity.sh

echo ""
echo "Done. Free integrity monitor enabled."
echo "Verify: cat /www/wwwroot/jdy-cloud/logs/integrity-state.json"