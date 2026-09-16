#!/usr/bin/env bash
# ============================================================
# IronWall v1.44.0: 注入 X-TLS-JA4 转发头 + 临时自检端点
# 前置：build-ja4-module.sh 已成功（否则 $http_ssl_ja4 变量不存在）
# 用法：bash /root/ja4/apply-ja4-header.sh
# ============================================================
set -u
CONF_DIR=/www/server/panel/vhost/nginx/proxy/example.com
SITE_CONF=/www/server/panel/vhost/nginx/example.com.conf
BACKUP_DIR=/www/server/nginx/ja4-conf-backup-$(date +%m%d%H%M)
say() { echo "[JA4-HDR] $*"; }
fail() { echo "[JA4-HDR-ERROR] $*"; exit 1; }

grep -q 'load_module modules/ngx_http_ssl_ja4_module.so;' /www/server/nginx/conf/nginx.conf \
  || fail "JA4 模块未加载，请先成功执行 build 脚本"

[ -d "$CONF_DIR" ] || fail "未找到 $CONF_DIR"
FILES=$(grep -rl "proxy_pass" "$CONF_DIR" || true)
[ -n "$FILES" ] || fail "未找到 /api/ 反代配置"

mkdir -p "$BACKUP_DIR"
for f in $FILES; do
  if grep -q "X-TLS-JA4" "$f"; then
    say "已包含 X-TLS-JA4，跳过 $f"
    continue
  fi
  cp "$f" "$BACKUP_DIR/"
  sed -i '/proxy_set_header X-Real-IP/a\    proxy_set_header X-TLS-JA4 $http_ssl_ja4;' "$f"
  grep -q "X-TLS-JA4" "$f" || { cp "$BACKUP_DIR/$(basename "$f")" "$f"; fail "注入失败：$f（已还原）"; }
  say "已注入 $f"
done

if [ -f "$SITE_CONF" ] && ! grep -q "ja4-debug" "$SITE_CONF"; then
  cp "$SITE_CONF" "$BACKUP_DIR/site.conf"
  sed -i '/#REWRITE-END/a\location = /ja4-debug { allow 127.0.0.1; deny all; default_type text/plain; return 200 "JA4=$http_ssl_ja4"; }' "$SITE_CONF"
  say "已注入临时自检端点 /ja4-debug（仅本机可访问）"
fi

if nginx -t; then
  nginx -s reload
  say "成功。本机自检：curl -s --resolve example.com:443:127.0.0.1 https://example.com/ja4-debug"
  say "验证完成后请删除 /ja4-debug 段（见清理命令），备份在 $BACKUP_DIR"
else
  say "nginx -t 失败，自动回滚"
  for f in $FILES; do [ -f "$BACKUP_DIR/$(basename "$f")" ] && cp -f "$BACKUP_DIR/$(basename "$f")" "$f"; done
  [ -f "$BACKUP_DIR/site.conf" ] && cp -f "$BACKUP_DIR/site.conf" "$SITE_CONF"
  nginx -t && nginx -s reload || true
  fail "已回滚，请把报错发我"
fi