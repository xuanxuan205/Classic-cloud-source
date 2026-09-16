#!/usr/bin/env bash
# IronWall v1.44.0 JA4 dynamic module build v4 (auto-adapt LuaJIT)
set -u

NGINX_BIN=/www/server/nginx/sbin/nginx
NGINX_SRC=/www/server/nginx/src
MODULES_DIR=/www/server/nginx/modules
JA4_SRC="$NGINX_SRC/ja4-nginx-module"
BACKUP_DIR=/www/server/nginx/ja4-backup-$(date +%m%d%H%M)

say() { echo "[JA4] $*"; }
fail() { echo "[JA4-ERROR] $*"; exit 1; }

NGINX_VER=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')
[ -n "$NGINX_VER" ] || fail "no nginx version"
say "nginx version: $NGINX_VER"

# 1) restore full source if still incomplete (already done on this server, so skipped)
if [ ! -f "$NGINX_SRC/auto/options" ] || [ ! -d "$NGINX_SRC/src/core" ]; then
  say "source tree incomplete, restoring from official mirrors"
  TARBALL=/tmp/nginx-${NGINX_VER}.tar.gz
  rm -f "$TARBALL"
  DL_OK=0
  for URL in \
    "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" \
    "https://mirrors.huaweicloud.com/nginx/nginx-${NGINX_VER}.tar.gz" \
    "https://mirrors.tuna.tsinghua.edu.cn/nginx/nginx-${NGINX_VER}.tar.gz"; do
    say "try download: $URL"
    if curl -fsSL --connect-timeout 10 -m 600 -o "$TARBALL" "$URL" \
       && [ -s "$TARBALL" ] && gzip -t "$TARBALL" 2>/dev/null; then
      DL_OK=1
      break
    fi
    rm -f "$TARBALL"
  done
  [ "$DL_OK" = "1" ] || fail "download failed from all mirrors"
  rm -rf /tmp/nginx-src-restore && mkdir -p /tmp/nginx-src-restore
  tar -xzf "$TARBALL" -C /tmp/nginx-src-restore --strip-components=1 || fail "tar failed"
  for d in src auto conf contrib man; do
    [ -d "/tmp/nginx-src-restore/$d" ] && cp -a "/tmp/nginx-src-restore/$d" "$NGINX_SRC/"
  done
  for f in configure CHANGES CHANGES.ru LICENSE README; do
    [ -f "/tmp/nginx-src-restore/$f" ] && cp -f "/tmp/nginx-src-restore/$f" "$NGINX_SRC/$f"
  done
  say "source restored"
fi

[ -d "$JA4_SRC" ] || fail "missing ja4-nginx-module dir"

CONFIGURE_ARGS=$(nginx -V 2>&1 | grep 'configure arguments:' | sed 's/^.*configure arguments: //')
[ -n "$CONFIGURE_ARGS" ] || fail "cannot parse configure args"

# 2) auto-adapt LuaJIT: export env if LuaJIT 2.1 found, otherwise drop lua/ndk
# add-modules for THIS build only (no impact on the JA4 dynamic module ABI)
LJ_HDR=$(find /usr/local /usr /www /opt /root -maxdepth 8 -name luajit.h 2>/dev/null | grep -E 'luajit-2\.1|LuaJIT' | head -1)
LJ_LIB=$(find /usr/local /usr /www /opt /root -maxdepth 8 -name 'libluajit-5.1.so*' 2>/dev/null | head -1)
if [ -n "$LJ_HDR" ] && [ -n "$LJ_LIB" ]; then
  export LUAJIT_INC=$(dirname "$LJ_HDR")
  export LUAJIT_LIB=$(dirname "$LJ_LIB")
  say "use LuaJIT: inc=$LUAJIT_INC lib=$LUAJIT_LIB"
else
  say "LuaJIT 2.1 not found, drop lua/ndk add-modules for this build"
  CONFIGURE_ARGS=$(echo "$CONFIGURE_ARGS" | sed 's#--add-module=/www/server/nginx/src/lua_nginx_module##; s#--add-module=/www/server/nginx/src/ngx_devel_kit##')
fi

cd "$NGINX_SRC"
rm -rf objs
say "run configure"
./configure $CONFIGURE_ARGS --add-dynamic-module=$JA4_SRC || fail "configure failed, send me the error above"

say "run make modules (10-25 min, do not interrupt)"
if ! make -j"$(nproc)" modules; then
  say "first build failed, retry without -ljemalloc"
  sed -i 's/-ljemalloc//g' objs/Makefile
  make -j"$(nproc)" modules || fail "make modules failed again, send me the error above"
fi

SO_FILE=$(find objs -name '*ja4*.so' | head -1)
[ -n "$SO_FILE" ] || fail "no ja4 .so generated"
say "generated: $SO_FILE"

mkdir -p "$BACKUP_DIR" "$MODULES_DIR"
cp -f "$NGINX_BIN" "$BACKUP_DIR/nginx"
cp -f /www/server/nginx/conf/nginx.conf "$BACKUP_DIR/nginx.conf"
cp -f "$SO_FILE" "$MODULES_DIR/ngx_http_ssl_ja4_module.so"
say "backup: $BACKUP_DIR"

if ! grep -q 'ngx_http_ssl_ja4_module' /www/server/nginx/conf/nginx.conf; then
  sed -i '1i load_module modules/ngx_http_ssl_ja4_module.so;' /www/server/nginx/conf/nginx.conf
fi

if "$NGINX_BIN" -t; then
  nginx -s reload
  say "SUCCESS: module loaded and nginx reloaded"
  say "next: run the apply block to inject X-TLS-JA4"
else
  say "nginx -t failed, rollback"
  cp -f "$BACKUP_DIR/nginx" "$NGINX_BIN"
  cp -f "$BACKUP_DIR/nginx.conf" /www/server/nginx/conf/nginx.conf
  "$NGINX_BIN" -t && nginx -s reload || true
  fail "rolled back, send me the error above"
fi