#!/bin/bash
# ============================================================
# IronWall v1.26.0 - 五层假端口陷阱安装脚本（合法威慑，非攻击）
# 功能：把 decoy-port-manager.py 安装为 systemd 服务，
# 每层随机开放 3 个高段仿真端口，攻击者踩入即被吞没取证，
# 并联动 fail2ban 全端口封禁。
#
# 用法：bash install-decoy-ports.sh
# 卸载：bash install-decoy-ports.sh uninstall
# ============================================================
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SRC="$(cd "$(dirname "$0")" && pwd)/decoy-port-manager.py"
DEST="/usr/local/bin/ironwall-decoy-port-manager.py"
SERVICE="/etc/systemd/system/ironwall-decoy.service"
LOG_DIR="/www/wwwroot/jdy-cloud/logs"

if [ "${1:-}" = "uninstall" ]; then
  systemctl stop ironwall-decoy.service 2>/dev/null || true
  systemctl disable ironwall-decoy.service 2>/dev/null || true
  rm -f "$SERVICE" "$DEST"
  systemctl daemon-reload
  echo "IronWall decoy port traps uninstalled."
  exit 0
fi

if [ ! -f "$SRC" ]; then
  echo "找不到 decoy-port-manager.py，请把整个 server-guard 目录上传后再执行本脚本。" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
cp -f "$SRC" "$DEST"
chmod 755 "$DEST"

cat > "$SERVICE" <<'EOF'
[Unit]
Description=IronWall Decoy Port Trap Manager
After=network-online.target fail2ban.service
Wants=network-online.target

[Service]
Type=simple
# 若你的管理面板或 SSH 用了自定义端口，在这里补上（逗号分隔），
# 诱饵端口便会避开它们，不会与真实业务撞车。
# 例：Environment="IRONWALL_RESERVED_PORTS=888,2222"
Environment="IRONWALL_RESERVED_PORTS="
ExecStart=/usr/bin/python3 /usr/local/bin/ironwall-decoy-port-manager.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ironwall-decoy.service 2>/dev/null || true
systemctl restart ironwall-decoy.service 2>/dev/null || true

sleep 2
if systemctl is-active --quiet ironwall-decoy.service; then
  echo "IronWall decoy port traps installed and running."
else
  echo "警告：systemd 启动失败，尝试前台运行以查看错误："
  /usr/bin/python3 "$DEST"
fi
