#!/usr/bin/env bash
# ============================================================
# IronWall v1.44.0: 回滚 JA4（二进制 + 主配置）
# 用法：bash rollback-ja4.sh /www/server/nginx/ja4-backup-XXXXXX
# ============================================================
set -u
BK="${1:-}"
[ -n "$BK" ] && [ -d "$BK" ] || { echo "用法: bash rollback-ja4.sh <备份目录>"; exit 1; }
NGINX_BIN=/www/server/nginx/sbin/nginx
cp "$BK/nginx" "$NGINX_BIN"
[ -f "$BK/nginx.conf" ] && cp "$BK/nginx.conf" /www/server/nginx/conf/nginx.conf
# 移除反代中的 JA4 头（若已注入）
sed -i '/proxy_set_header X-TLS-JA4/d' /www/server/panel/vhost/nginx/proxy/example.com/*.conf 2>/dev/null || true
sed -i '/ja4-debug/d' /www/server/panel/vhost/nginx/example.com.conf 2>/dev/null || true
if nginx -t; then nginx -s reload; echo "已回滚并热加载"; else echo "校验失败，请手动检查"; exit 1; fi