#!/bin/bash
# ============================================================
# IronWall v1.26.0 - 端口扫描检测与全链路守护安装脚本
# 功能：
# 1. 安装陷阱触碰采集器（仅读取假端口陷阱命中日志）
# 2. 安装 fail2ban ironwall-portscan 监狱（陷阱触碰 -> 全端口封禁）
# 3. 每分钟 cron 自动采集
# ============================================================
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行：bash install-portscan-guard.sh"
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="/www/wwwroot/jdy-cloud/logs"

mkdir -p "$LOG_DIR"
chown www:www "$LOG_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR"

echo "[1/5] 安装陷阱触碰采集器..."
cp -f "$SRC_DIR/ironwall-portscan-collector.py" /usr/local/bin/ironwall-portscan-collector.py
chmod 755 /usr/local/bin/ironwall-portscan-collector.py
cp -f "$SRC_DIR/ironwall-allow-me.sh" /usr/local/bin/ironwall-allow-me
chmod 755 /usr/local/bin/ironwall-allow-me
touch "$LOG_DIR/portscan-dynamic-whitelist.json" 2>/dev/null || true
chmod 644 "$LOG_DIR/portscan-dynamic-whitelist.json" 2>/dev/null || true

echo "[2/5] 安装 fail2ban 陷阱触碰联动监狱..."
if command -v fail2ban-client >/dev/null 2>&1; then
  cp -f "$SRC_DIR/fail2ban-filter-ironwall-portscan.conf" /etc/fail2ban/filter.d/ironwall-portscan.conf
  cp -f "$SRC_DIR/fail2ban-jail-ironwall-portscan.conf" /etc/fail2ban/jail.d/ironwall-portscan.conf
  fail2ban-client -t 2>&1 || true
  systemctl restart fail2ban 2>/dev/null || /etc/init.d/fail2ban restart 2>/dev/null || true
else
  echo "未检测到 fail2ban，跳过监狱安装（建议先在宝塔安装 fail2ban）"
fi

echo "[3/5] 尝试开启 firewalld 拒绝日志..."
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --set-log-denied=all 2>/dev/null || true
fi

echo "[4/5] 安装每分钟采集任务..."
CRON_LINE='* * * * * /usr/bin/python3 /usr/local/bin/ironwall-portscan-collector.py >/dev/null 2>&1'
if crontab -l 2>/dev/null | grep -Fq "ironwall-portscan-collector.py"; then
  echo "cron already present, skip"
else
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "cron installed"
fi

echo "[5/5] 立即执行一次采集..."
/usr/bin/python3 /usr/local/bin/ironwall-portscan-collector.py || true

echo ""
echo "陷阱触碰联动已安装（不再统计普通端口扫描）。"
echo "状态文件：$LOG_DIR/portscan-state.json"
echo "命中日志：$LOG_DIR/ironwall-portscan.log"
echo "查看监狱：fail2ban-client status ironwall-portscan"