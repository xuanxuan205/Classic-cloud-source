#!/bin/bash
# ============================================================
# IronWall v1.26.0 - Server Shield installer (one-click)
# Installs the state collector + cron job so the admin panel
# can show the server-layer shield status.
#
# Usage: bash install-server-shield.sh
# ============================================================
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Please run as root: bash install-server-shield.sh"
  exit 1
fi

echo "[1/4] Installing collector to /usr/local/bin ..."
cp -f update-ironwall-shield.sh /usr/local/bin/update-ironwall-shield.sh
chmod 755 /usr/local/bin/update-ironwall-shield.sh

echo "[2/4] Preparing state dir /www/wwwroot/jdy-cloud/logs ..."
mkdir -p /www/wwwroot/jdy-cloud/logs
chown www:www /www/wwwroot/jdy-cloud/logs
chmod 755 /www/wwwroot/jdy-cloud/logs

echo "[3/4] Installing cron job (every minute) ..."
CRON_LINE='* * * * * /usr/local/bin/update-ironwall-shield.sh >/dev/null 2>&1'
if crontab -l 2>/dev/null | grep -Fq "update-ironwall-shield.sh"; then
  echo "cron already present, skip"
else
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "cron installed"
fi

echo "[4/4] Running collector once ..."
/usr/local/bin/update-ironwall-shield.sh

echo ""
echo "Done. The admin security panel will show the server shield status."
echo "Verify: cat /www/wwwroot/jdy-cloud/logs/server-shield-state.json"
echo ""
echo "Recommendations (BT panel):"
echo "  1. fail2ban plugin -> enable sshd and mysql protection"
echo "  2. Firewall -> allow only 80/443 (+ SSH port) for public, whitelist admin IP"
echo "  3. Enterprise tamper-proof -> protect /www/wwwroot/jdy-cloud and site dirs"
echo "  4. Schedule daily mysqldump backup"
echo "  5. Decoy traps -> bash install-decoy-ports.sh"
echo "  6. Port scan guard -> bash install-portscan-guard.sh"