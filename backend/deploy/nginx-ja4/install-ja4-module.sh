#!/bin/bash
# IronWall v1.41.0: 可选 nginx JA4 动态模块编译（实验性，失败即回滚，不改动既有配置）
# 用法：bash install-ja4-module.sh
set -u

NGX_BIN=/www/server/nginx/sbin/nginx
NGX_CONF=/www/server/nginx/conf/nginx.conf
[ -x "$NGX_BIN" ] || { echo "未找到 $NGX_BIN，退出"; exit 1; }

VER=$("$NGX_BIN" -v 2>&1 | sed -n 's#.*nginx/##p')
[ -n "$VER" ] || { echo "无法识别 nginx 版本，退出"; exit 1; }

# QUIC/第三方分支检测：官方 nginx 无 http_v3 编译项
"$NGX_BIN" -V 2>&1 | grep -qiE 'http_v3|quiche|boringssl' && {
  echo "检测到 HTTP/3(QUIC) 定制分支 nginx，官方 JA4 模块源码不保证兼容，为保护现网已安全退出。"
  echo "当前分支可继续使用三字段近似指纹（X-TLS-Profile），或手动评估分支源码后再编译。"
  exit 0
}

SRC_DIR=/usr/local/src/nginx-$VER
mkdir -p /usr/local/src
cd /usr/local/src || exit 1
if [ ! -d "$SRC_DIR" ]; then
  curl -fsSL "https://nginx.org/download/nginx-$VER.tar.gz" -o "nginx-$VER.tar.gz" || { echo "下载源码失败"; exit 1; }
  tar xzf "nginx-$VER.tar.gz"
fi

MOD_DIR="$SRC_DIR/ngx_http_ssl_ja4_module"
if [ ! -d "$MOD_DIR" ]; then
  git clone --depth 1 https://github.com/FoxIO-LLC/ja4.git ja4-src || { echo "克隆模块源码失败"; exit 1; }
  cp -r ja4-src/nginx/ngx_http_ssl_ja4_module "$MOD_DIR" || { echo "模块源码路径不符，退出"; exit 1; }
fi

cd "$SRC_DIR" || exit 1
CONFIGURE_ARGS=$("$NGX_BIN" -V 2>&1 | sed -n 's/configure arguments: //p')
eval ./configure $CONFIGURE_ARGS --add-dynamic-module="$MOD_DIR" >/tmp/ja4-configure.log 2>&1 || { echo "configure 失败，见 /tmp/ja4-configure.log"; exit 1; }
make modules -j"$(nproc)" >/tmp/ja4-make.log 2>&1 || { echo "make 失败，见 /tmp/ja4-make.log"; exit 1; }

SO=$(find objs -maxdepth 1 -name 'ngx_http_ssl_ja4_module.so' | head -1)
[ -n "$SO" ] || { echo "未找到编译产物，退出"; exit 1; }
mkdir -p /www/server/nginx/modules
cp "$SO" /www/server/nginx/modules/

if ! grep -q 'ngx_http_ssl_ja4_module.so' "$NGX_CONF"; then
  cp "$NGX_CONF" "$NGX_CONF.bak.ja4.$(date +%s)"
  sed -i '1i load_module /www/server/nginx/modules/ngx_http_ssl_ja4_module.so;' "$NGX_CONF"
fi

"$NGX_BIN" -t || { echo "nginx -t 失败，已保留备份 $NGX_CONF.bak.ja4.*，请手动检查"; exit 1; }
"$NGX_BIN" -s reload
echo "JA4 模块加载成功。确认：curl -sI https://example.com/ 正常后，查看后端日志 X-TLS-JA4 生效。"
