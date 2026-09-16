#!/bin/bash
# ============================================================
# IronWall v1.25.1 - Free file integrity monitor
# Baseline + scheduled diff for critical files.
# Usage: bash check-ironwall-integrity.sh
# Cron: 0 * * * * /usr/local/bin/check-ironwall-integrity.sh >/dev/null 2>&1
# ============================================================
set -u

LOG_DIR="/www/wwwroot/jdy-cloud/logs"
BASE="$LOG_DIR/integrity-baseline.sha256"
STATE="$LOG_DIR/integrity-state.json"
FILES="/www/wwwroot/jdy-cloud/jdy-cloud.jar /www/wwwroot/jdy-cloud/.env /www/wwwroot/jdy-cloud/start.sh /www/wwwroot/jdy-cloud/application.yml /www/wwwroot/jdy-cloud/nginx.conf /etc/ssh/sshd_config /etc/my.cnf"

mkdir -p "$LOG_DIR"
chown www:www "$LOG_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR" 2>/dev/null || true

if [ ! -f "$BASE" ]; then
  sha256sum $FILES > "$BASE" 2>/dev/null
fi

CHANGED=""
while IFS= read -r line; do
  case "$line" in
    *": FAILED") CHANGED="$CHANGED${line%: FAILED}," ;;
  esac
done < <(sha256sum -c "$BASE" 2>/dev/null)

if command -v python3 >/dev/null 2>&1; then
  python3 - "$STATE" "$CHANGED" <<'PY'
import json, sys
from datetime import datetime, timezone, timedelta
state_path = sys.argv[1]
changed = [x.strip() for x in sys.argv[2].split(",") if x.strip()]
data = {
    "enabled": True,
    "last_check": datetime.now(timezone(timedelta(hours=8))).isoformat(),
    "changed": changed,
}
with open(state_path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
PY
  chown www:www "$STATE" 2>/dev/null || true
  chmod 644 "$STATE"
else
  echo '{"enabled":true,"changed":[]}' > "$STATE"
fi

exit 0