#!/bin/bash
# ============================================================
# IronWall v1.26.0: 关闭静默开放的 21 端口
# 执行前请确认 FTP 业务确实不再使用：ss -ltnp | grep ':21'
# ============================================================
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo "[1/3] 停止并禁用 pure-ftpd / vsftpd..."
systemctl stop pure-ftpd 2>/dev/null || true
systemctl disable pure-ftpd 2>/dev/null || true
systemctl stop vsftpd 2>/dev/null || true
systemctl disable vsftpd 2>/dev/null || true

echo "[2/3] 防火墙移除 21/tcp..."
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --remove-port=21/tcp 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null || true
fi

echo "[3/3] 校验端口状态..."
ss -ltnp | grep ':21' || echo "OK: 21 端口已关闭"