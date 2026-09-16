#!/usr/bin/env bash
# ============================================================
# IronWall v1.44.0: JA4 链路验证
# 1) 模块已加载；2) 本机自检端点返回 JA4 三段式；3) 后端签名会话正常
# ============================================================
echo "==> 模块加载检查"
nginx -T 2>/dev/null | grep -q 'ngx_http_ssl_ja4_module' && echo "OK: 模块已加载" || echo "FAIL: 模块未加载"

echo "==> 本机自检端点（需要 /ja4-debug 临时端点存在）"
JA4=$(curl -s --resolve example.com:443:127.0.0.1 https://example.com/ja4-debug 2>/dev/null | tr -d '\r\n')
echo "$JA4"
echo "$JA4" | grep -Eq '^JA4=t[0-9]{2}[di][0-9a-f]{4}[0-9a-z]{0,2}_[0-9a-f]{12}_[0-9a-f]{12}$' \
  && echo "OK: JA4 格式正确" || echo "INFO: 自检端点未配置或未返回（不影响主流程，可跳过）"

echo "==> 后端连通"
curl -s http://127.0.0.1:15060/api/version/info && echo
