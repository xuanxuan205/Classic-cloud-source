#!/bin/bash
# ============================================================
# IronWall v1.26.0 - 动态管理员白名单工具
# 用法（SSH 登录后）：
# ironwall-allow-me # 自动取当前 SSH 客户端公网 IP
# ironwall-allow-me --ip 1.2.3.4 # 手动指定 IP
# ironwall-allow-me --hours 48 # 指定有效期（默认 24 小时）
# 说明：IP 不固定时，每次换 IP 后重新执行即可；
# 采集器会自动读取此动态白名单，过期自动失效。
# ============================================================
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

FILE="/www/wwwroot/jdy-cloud/logs/portscan-dynamic-whitelist.json"
HOURS=24
IP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="$2"; shift 2 ;;
    --hours) HOURS="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

if [ -z "$IP" ]; then
  IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $2}')
fi

if ! echo "$IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "无法确定当前公网 IP。请手动执行：ironwall-allow-me --ip <你的公网IP>"
  exit 1
fi

EXPIRY=$(( $(date +%s) + HOURS * 3600 ))

python3 - "$FILE" "$IP" "$EXPIRY" <<'PY'
import json, os, sys, time
path, ip, expiry = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
now = time.time()
data = {k: v for k, v in data.items() if isinstance(v, int) and v > now}
data[ip] = expiry
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False)
os.rename(tmp, path)
os.chmod(path, 0o644)
print("已白名单当前 IP:", ip)
print("有效期至:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry)))
PY