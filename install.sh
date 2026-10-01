#!/usr/bin/env bash
# =============================================================================
# 经典云网盘 (Classic Cloud) · 全自动安装器
# -----------------------------------------------------------------------------
# 一条命令装好整套系统：JDK 21 + MySQL + nginx + 后端守护 + 前端静态站
#
#   全自动（无人值守）：
#     sudo bash install.sh --yes --domain drive.example.com \
#          --admin-user admin --admin-pass '你的管理员密码' \
#          --db-name jdy_cloud --db-user jdy_cloud --db-pass '你的数据库密码'
#
#   图形向导（浏览器里填空，推荐）：
#     sudo bash install.sh --web
#
#   只打印计划、不动服务器：
#     sudo bash install.sh --dry-run --admin-pass 'Xxxx1234'
#
# 支持：Debian / Ubuntu、CentOS / RHEL / Rocky / AlmaLinux、宝塔面板
# 完成后写出 /etc/jdy-cloud/install-result.json（首页地址 / 后台地址 / 管理员），
# 网页向导的「完成」页读的就是这份文件。
# =============================================================================
set -Eeuo pipefail

INSTALLER_VERSION="1.0.0"
APP_SLUG="jdy-cloud"
GITHUB_REPO="xuanxuan205/Classic-cloud-source"
DEFAULT_JAR_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/jdy-cloud.jar"
DEFAULT_PREBUILD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/frontend.zip"
DEFAULT_JDK_URL="https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jre/hotspot/normal/eclipse"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JDY_ETC="${JDY_ETC:-/etc/jdy-cloud}"

ASSUME_YES=0
DRY_RUN=0
NO_DEPS=0
WEB_MODE=0

HAS_DOMAIN=0
DOMAIN=""
SITE_NAME="经典云网盘"
SITE_SHORT="经典云"
CONTACT_EMAIL=""

ADMIN_USER="admin"
ADMIN_PASS=""
ADMIN_EMAIL=""

DB_NAME="jdy_cloud"
DB_USER="jdy_cloud"
DB_PASS=""

SERVER_PORT="15060"
MAX_FILE_MB="850"
ENABLE_SSL=1

SKIP_FRONTEND=0
USE_PREBUILD=0

BT_MODE=0
BT_JAVA=0

JAR_SRC=""
JAR_URL=""
PREBUILD_URL=""
JDK_URL=""
JAVA_HOME_OVERRIDE=""

WEB_ROOT=""
APP_DIR=""
CONFIG_FILE=""
JAVA_BIN=""
JAVA_MAJOR=""
NGINX_BIN=""
MYSQL_CLI=""
NGINX_CONF=""
SERVICE_MODE="systemd"
PKG=""

log()  { printf '%s\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    [ok] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    [!] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m    [x] %s\033[0m\n' "$*" >&2; exit 1; }

on_error() {
    local code="$1" line="$2"
    printf '\n安装中断：第 %s 行命令失败（退出码 %s）\n' "$line" "$code" >&2
    printf '把上面的报错复制出来，到 GitHub 提 Issue 即可。\n' >&2
    exit "$code"
}
trap 'on_error "$?" "$LINENO"' ERR

have() { command -v "$1" >/dev/null 2>&1; }

run() {
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] $*"
        return 0
    fi
    "$@"
}

# 写文件；试运行时只允许写进配置目录（网页向导仍能看到安装结果）
put_file() {
    local path="$1"
    if [ "$DRY_RUN" = 1 ] && [ "${path#"$JDY_ETC"/}" = "$path" ]; then
        log "    [试运行] 写入 $path"
        cat >/dev/null
        return 0
    fi
    mkdir -p "$(dirname "$path")"
    cat >"$path"
}

rand_hex() {
    local n="${1:-32}"
    if have openssl; then
        openssl rand -hex "$n"
    elif [ -r /dev/urandom ] && have od; then
        od -An -tx1 -N "$n" /dev/urandom | tr -d ' \n'
    else
        printf '%s%s%s' "$(date +%s%N)" "$$" "$RANDOM" | (have md5sum && md5sum || cksum) | tr -d ' -'
    fi
}

# 配置文件的值：双引号 + 转义；systemd EnvironmentFile 与 shell source 都能正确读
env_val() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/\\$/g' -e 's/`/\\`/g')"
}

jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }

usage() {
    cat <<'USAGE'
经典云网盘 · 全自动安装器

  bash install.sh --web                        图形向导（浏览器里填空）
  bash install.sh --yes --domain <域名> ...     全自动无人值守
  bash install.sh --dry-run ...                只打印计划，不动服务器

  --yes                 不再逐项询问（网页向导走的就是这条路）
  --dry-run             试运行：不装依赖、不改服务，只写配置与结果文件
  --no-deps             不安装系统依赖（已自备 JDK21 / MySQL / nginx）
  --web                 装好环境后启动网页安装向导
  --domain <域名>        站点域名，不含 https://
  --no-domain           没有域名，用服务器 IP 访问
  --site-name <名字>     站点全称（默认：经典云网盘）
  --site-short <简称>    站点简称，2-6 个字（默认：经典云）
  --contact-email <邮箱> 对外联系邮箱，可留空
  --admin-user <账号>    管理员账号（默认：admin）
  --admin-pass <密码>    管理员密码，至少 8 位（必填）
  --admin-email <邮箱>   管理员邮箱，可留空
  --db-name <库名>       数据库名（默认：jdy_cloud）
  --db-user <账号>       数据库账号（默认：jdy_cloud）
  --db-pass <密码>       数据库密码（留空自动生成并写进配置文件）
  --mysql-root-pass <密码> MySQL root 密码（root 没设密码就别填）
  --port <端口>          后端端口（默认 15060，只监听本机）
  --max-file-size <MB>   单个文件上限 MB（默认 850）
  --no-ssl               先不上 HTTPS
  --skip-frontend        只装后端，不部署前端
  --use-prebuild         用编译好的前端，不在服务器上装 Node 编译
  --bt                   宝塔面板模式（按 /www 目录结构部署）
  --bt-java              宝塔「Java 项目管理器」托管（不写 systemd）
  --jar <文件>           用本地的 jdy-cloud.jar
  --jar-url <地址>       从指定地址下载 jar（默认取 GitHub Releases）
  --prebuild-url <地址>  从指定地址下载前端压缩包
  --jdk-url <地址>       没有 JDK 21 时从指定地址下载
  --java-home <目录>     指定 JDK 21 安装目录
  --web-root <目录>      前端站点目录
  --app-dir <目录>       后端程序目录
  --repo <目录>          源码目录（默认：本脚本所在目录）
  -h, --help             显示这份帮助
USAGE
}

need_value() { [ "$#" -ge 2 ] || die "$1 后面要跟一个值"; }

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --yes|-y)          ASSUME_YES=1 ;;
            --dry-run)         DRY_RUN=1 ;;
            --no-deps)         NO_DEPS=1 ;;
            --web)             WEB_MODE=1 ;;
            --domain)          need_value "$@"; DOMAIN="$2"; HAS_DOMAIN=1; shift ;;
            --no-domain)       HAS_DOMAIN=0; DOMAIN="" ;;
            --site-name)       need_value "$@"; SITE_NAME="$2"; shift ;;
            --site-short)      need_value "$@"; SITE_SHORT="$2"; shift ;;
            --contact-email)   need_value "$@"; CONTACT_EMAIL="$2"; shift ;;
            --admin-user)      need_value "$@"; ADMIN_USER="$2"; shift ;;
            --admin-pass)      need_value "$@"; ADMIN_PASS="$2"; shift ;;
            --admin-email)     need_value "$@"; ADMIN_EMAIL="$2"; shift ;;
            --db-name)         need_value "$@"; DB_NAME="$2"; shift ;;
            --db-user)         need_value "$@"; DB_USER="$2"; shift ;;
            --db-pass)         need_value "$@"; DB_PASS="$2"; shift ;;
            --mysql-root-pass) need_value "$@"; MYSQL_ROOT_PASSWORD="${2:-}"; shift ;;
            --port)            need_value "$@"; SERVER_PORT="$2"; shift ;;
            --max-file-size)   need_value "$@"; MAX_FILE_MB="$2"; shift ;;
            --ssl)             ENABLE_SSL=1 ;;
            --no-ssl)          ENABLE_SSL=0 ;;
            --skip-frontend)   SKIP_FRONTEND=1 ;;
            --use-prebuild)    USE_PREBUILD=1 ;;
            --bt)              BT_MODE=1 ;;
            --bt-java)         BT_MODE=1; BT_JAVA=1 ;;
            --jar)             need_value "$@"; JAR_SRC="$2"; shift ;;
            --jar-url)         need_value "$@"; JAR_URL="$2"; shift ;;
            --prebuild-url)    need_value "$@"; PREBUILD_URL="$2"; shift ;;
            --jdk-url)         need_value "$@"; JDK_URL="$2"; shift ;;
            --java-home)       need_value "$@"; JAVA_HOME_OVERRIDE="$2"; shift ;;
            --web-root)        need_value "$@"; WEB_ROOT="$2"; shift ;;
            --app-dir)         need_value "$@"; APP_DIR="$2"; shift ;;
            --repo)            need_value "$@"; REPO="$(cd "$2" && pwd)"; shift ;;
            --version)         log "install.sh $INSTALLER_VERSION"; exit 0 ;;
            -h|--help)         usage; exit 0 ;;
            *)                 die "不认识的参数：$1（用 --help 看用法）" ;;
        esac
        shift
    done
}

validate() {
    [ -f "$REPO/backend/pom.xml" ] || die "源码目录不对：$REPO 下没有 backend/pom.xml（用 --repo 指定）"
    [ -f "$REPO/backend/src/main/resources/db/init.sql" ] || die "源码里缺少 init.sql，仓库不完整"
    if [ "$HAS_DOMAIN" = 1 ]; then
        printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' \
            || die "域名格式不对：$DOMAIN（不要带 https:// 和结尾斜杠）"
    fi
    printf '%s' "$ADMIN_USER" | grep -Eq '^[A-Za-z0-9_.-]{3,30}$' \
        || die "管理员账号只能用字母、数字、下划线、点、横线，长度 3-30"
    [ -n "$ADMIN_PASS" ] || die "缺少管理员密码：加 --admin-pass '你的密码'（至少 8 位）"
    [ "${#ADMIN_PASS}" -ge 8 ] || die "管理员密码至少 8 位"
    printf '%s' "$DB_NAME" | grep -Eq '^[A-Za-z0-9_]{1,40}$' || die "数据库名只能用字母数字下划线"
    printf '%s' "$DB_USER" | grep -Eq '^[A-Za-z0-9_]{1,32}$' || die "数据库账号只能用字母数字下划线"
    printf '%s' "$SERVER_PORT" | grep -Eq '^[0-9]{2,5}$' || die "端口必须是数字：$SERVER_PORT"
    printf '%s' "$MAX_FILE_MB" | grep -Eq '^[0-9]{1,5}$' || die "文件上限必须是数字（MB）：$MAX_FILE_MB"
    [ -n "$DB_PASS" ] || DB_PASS="$(rand_hex 12)"
    [ -n "$ADMIN_EMAIL" ] || ADMIN_EMAIL="${ADMIN_USER}@${DOMAIN:-localhost}"
}

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    printf '\n按回车开始安装（Ctrl+C 取消）：'
    read -r _ || true
}

# -------------------------------------------------------------------- 环境探测 ---
detect_system() {
    if have apt-get; then PKG="apt"
    elif have dnf;   then PKG="dnf"
    elif have yum;   then PKG="yum"
    else PKG=""
    fi
    if [ -d /www/server/panel ]; then
        BT_MODE=1
        [ -x /www/server/nginx/sbin/nginx ] && NGINX_BIN="/www/server/nginx/sbin/nginx"
        [ -x /www/server/mysql/bin/mysql ]  && MYSQL_CLI="/www/server/mysql/bin/mysql"
    fi
    [ -n "$NGINX_BIN" ] || NGINX_BIN="$(command -v nginx || true)"
    if [ -z "$MYSQL_CLI" ]; then
        if have mysql; then MYSQL_CLI="mysql"
        elif have mariadb; then MYSQL_CLI="mariadb"
        fi
    fi
    log "    包管理器：${PKG:-未知}"
    if [ "$BT_MODE" = 1 ]; then ok "识别到宝塔面板，按 /www 目录结构部署"; fi
    if [ "$BT_JAVA" = 1 ]; then ok "宝塔 Java 项目管理器托管（不写 systemd）"; fi
}

java_major_of() {
    local bin="$1"
    [ -x "$bin" ] || return 1
    "$bin" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -n1
}

detect_java() {
    local cands=() bin major
    if [ -n "$JAVA_HOME_OVERRIDE" ]; then cands+=("$JAVA_HOME_OVERRIDE/bin/java"); fi
    for d in /www/server/java/jdk-21* /www/server/java/jdk21* /www/server/java/*; do
        [ -x "$d/bin/java" ] && cands+=("$d/bin/java")
    done
    for d in /usr/lib/jvm/*21*/bin/java /usr/lib/jvm/java-21*/bin/java \
             /usr/local/java/*/bin/java /opt/jdk-21*/bin/java "$APP_DIR/jdk21/bin/java"; do
        [ -x "$d" ] && cands+=("$d")
    done
    have java && cands+=("$(command -v java)")
    for bin in ${cands[@]+"${cands[@]}"}; do
        major="$(java_major_of "$bin" || true)"
        if [ "$major" = "21" ]; then
            JAVA_BIN="$bin"; JAVA_MAJOR="21"
            ok "使用 JDK 21：$bin"
            return 0
        fi
    done
    warn "没有找到 JDK 21，安装阶段会自动装一个"
    return 1
}

# ------------------------------------------------------------------ 1. 系统依赖 ---
apt_install() { run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"; }

pkg_install() {
    case "$PKG" in
        apt) apt_install "$@" ;;
        dnf) run dnf install -y "$@" ;;
        yum) run yum install -y "$@" ;;
        *)   return 1 ;;
    esac
}

step_deps() {
    step "1/9 系统依赖（JDK 21 / MySQL / nginx / 基础工具）"
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] 跳过依赖安装"
        return 0
    fi
    if [ "$NO_DEPS" = 1 ]; then
        ok "已指定 --no-deps，跳过"
        return 0
    fi
    [ -n "$PKG" ] || warn "没识别出包管理器，依赖请自行确认"
    case "$PKG" in
        apt) run apt-get update || warn "apt-get update 失败，继续尝试安装" ;;
    esac

    if [ "$JAVA_MAJOR" != "21" ]; then
        pkg_install openjdk-21-jre-headless || pkg_install java-21-openjdk-headless || true
        detect_java || true
    fi
    if [ "$JAVA_MAJOR" != "21" ]; then
        local tarball d
        tarball="$(mktemp)"
        ok "从 Adoptium 下载 JDK 21（$(uname -m)）"
        run mkdir -p "$APP_DIR"
        if run curl -fsSL --retry 2 -o "$tarball" "${JDK_URL:-$DEFAULT_JDK_URL}"; then
            run tar -xzf "$tarball" -C "$APP_DIR"
            run rm -f "$tarball"
            for d in "$APP_DIR"/jdk-21*; do
                if [ -x "$d/bin/java" ]; then JAVA_BIN="$d/bin/java"; JAVA_MAJOR=21; fi
            done
        else
            warn "JDK 下载失败：请手动装好 JDK 21 后重跑（或用 --jdk-url 指定镜像）"
        fi
    fi

    if [ -d /www/server/mysql ]; then
        ok "使用宝塔自带 MySQL"
    elif have mysql || have mysqld || have mariadbd || [ -x /usr/sbin/mysqld ]; then
        ok "已有 MySQL / MariaDB"
    else
        pkg_install mysql-server || pkg_install default-mysql-server || pkg_install mariadb-server || \
            warn "MySQL 自动安装失败，请在面板里装好 MySQL 8 / MariaDB 10.6+"
    fi

    if [ -z "$NGINX_BIN" ]; then
        pkg_install nginx || warn "nginx 自动安装失败"
        NGINX_BIN="$(command -v nginx || true)"
    else
        ok "已有 nginx：$NGINX_BIN"
    fi

    local t
    for t in curl unzip tar; do
        have "$t" || pkg_install "$t" || true
    done
    have openssl || pkg_install openssl || true

    if [ "$SKIP_FRONTEND" = 0 ] && [ "$USE_PREBUILD" = 0 ]; then
        have node || pkg_install nodejs npm || warn "Node.js 自动安装失败：可改用 --use-prebuild"
        if have node; then
            local major
            major="$(node -v 2>/dev/null | sed -n 's/^v\([0-9]*\).*/\1/p')"
            if [ -n "$major" ] && [ "$major" -lt 18 ]; then
                warn "Node.js 版本偏低（$(node -v)）：建议 --use-prebuild 或升级到 18+"
            fi
        fi
    fi

    if [ "$HAS_DOMAIN" = 1 ] && [ "$ENABLE_SSL" = 1 ] && ! have certbot; then
        pkg_install certbot python3-certbot-nginx || \
            warn "certbot 没装上：装完后执行 certbot --nginx -d $DOMAIN 即可上 HTTPS"
    fi
    ok "依赖检查完成"
}

# -------------------------------------------------------------------- 2. 目录 ---
detect_public_ip() {
    local ip=""
    if [ "$DRY_RUN" = 0 ] && have curl; then
        ip="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [ -z "$ip" ] && have hostname; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    printf '%s' "$ip"
}

resolve_paths() {
    local suffix
    if [ "$HAS_DOMAIN" = 1 ]; then suffix="$DOMAIN"; else suffix="$(detect_public_ip)"; fi
    [ -n "$suffix" ] || suffix="default"
    if [ -z "$WEB_ROOT" ]; then
        if [ "$BT_MODE" = 1 ]; then WEB_ROOT="/www/wwwroot/$suffix"
        else WEB_ROOT="/var/www/$APP_SLUG"
        fi
    fi
    if [ -z "$APP_DIR" ]; then
        if [ "$BT_MODE" = 1 ]; then APP_DIR="/www/wwwroot/$APP_SLUG"
        else APP_DIR="/opt/$APP_SLUG"
        fi
    fi
    if [ "$BT_JAVA" = 1 ]; then
        CONFIG_FILE="$APP_DIR/start.env"
        SERVICE_MODE="bt-java"
    else
        CONFIG_FILE="$JDY_ETC/$APP_SLUG.env"
        SERVICE_MODE="systemd"
    fi
    if [ "$BT_MODE" = 1 ]; then
        if [ "$HAS_DOMAIN" = 1 ]; then NGINX_CONF="/www/server/panel/vhost/nginx/${DOMAIN}.conf"
        else NGINX_CONF="/www/server/panel/vhost/nginx/${APP_SLUG}.conf"
        fi
    else
        NGINX_CONF="/etc/nginx/conf.d/${APP_SLUG}.conf"
    fi
}

step_dirs() {
    step "2/9 创建目录"
    local d
    for d in "$APP_DIR" "$APP_DIR/config" "$APP_DIR/logs" "$APP_DIR/uploads" \
             "$APP_DIR/releases" "$WEB_ROOT" "$JDY_ETC"; do
        run mkdir -p "$d"
        log "    $d"
    done
    ok "目录就绪"
}

# ---------------------------------------------------------------- 3. 后端程序 ---
resolve_jar() {
    local out="$APP_DIR/$APP_SLUG.jar"
    if [ -n "$JAR_SRC" ] && [ -f "$JAR_SRC" ]; then
        ok "使用本地 jar：$JAR_SRC"
        run cp -f "$JAR_SRC" "$out"
        return 0
    fi
    if [ -f "$REPO/backend/target/$APP_SLUG.jar" ]; then
        ok "使用仓库里已编译好的 backend/target/$APP_SLUG.jar"
        run cp -f "$REPO/backend/target/$APP_SLUG.jar" "$out"
        return 0
    fi
    local f
    for f in "$REPO/release/$APP_SLUG.jar" "$REPO/$APP_SLUG.jar"; do
        if [ -f "$f" ]; then
            ok "使用随仓库带来的 $f"
            run cp -f "$f" "$out"
            return 0
        fi
    done
    local url="${JAR_URL:-$DEFAULT_JAR_URL}"
    if have curl && run curl -fsSL --retry 2 -o "$out" "$url"; then
        ok "已下载 jdy-cloud.jar（$url）"
        return 0
    fi
    if have mvn; then
        ok "没有现成 jar，改用服务器上的 Maven 编译（第一次会久一点）"
        ( cd "$REPO/backend" && run mvn -B -q clean package -DskipTests )
        if [ -f "$REPO/backend/target/$APP_SLUG.jar" ]; then
            run cp -f "$REPO/backend/target/$APP_SLUG.jar" "$out"
            return 0
        fi
    fi
    die "没有拿到 jdy-cloud.jar：请用 --jar 指定本地文件，或用 --jar-url 指定下载地址"
}

step_backend() {
    step "3/9 部署后端程序"
    resolve_jar
    run chmod 644 "$APP_DIR/$APP_SLUG.jar" || true
    ok "程序就位：$APP_DIR/$APP_SLUG.jar"
}

# ------------------------------------------------------------------ 4. 配置 ---
write_config() {
    local req_mb=$(( MAX_FILE_MB + 170 ))
    local site_base=""
    if [ "$HAS_DOMAIN" = 1 ]; then
        if [ "$ENABLE_SSL" = 1 ]; then site_base="https://$DOMAIN"; else site_base="http://$DOMAIN"; fi
    fi
    put_file "$CONFIG_FILE" <<EOF
# =============================================================================
# 经典云网盘 · 运行配置（install.sh 于 $(date '+%Y-%m-%d %H:%M:%S') 生成）
# 含数据库密码与密钥，权限 600，请一并备份。
# =============================================================================
SERVER_PORT=$(env_val "$SERVER_PORT")

# ---- 站点身份 ----
SITE_DOMAIN=$(env_val "$DOMAIN")
SITE_BASE_URL=$(env_val "$site_base")
SITE_CONTACT_EMAIL=$(env_val "$CONTACT_EMAIL")
SITE_CONTACT_QQ=""

# ---- 数据库 ----
DB_URL=$(env_val "jdbc:mysql://127.0.0.1:3306/$DB_NAME?useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true&characterEncoding=UTF-8")
DB_USERNAME=$(env_val "$DB_USER")
DB_PASSWORD=$(env_val "$DB_PASS")

# ---- 密钥（随机生成，改掉会让所有人掉线）----
JWT_SECRET=$(env_val "$(rand_hex 32)")
JWT_EXPIRATION=$(env_val "86400000")
SHARE_LINK_SECRET=$(env_val "$(rand_hex 32)")
CANARY_TOKEN=$(env_val "$(rand_hex 8)")

# ---- 文件存储 ----
UPLOAD_DIR=$(env_val "$APP_DIR/uploads")
RELEASES_DIR=$(env_val "$APP_DIR/releases")
MAX_FILE_SIZE=$(env_val "${MAX_FILE_MB}MB")
MAX_REQUEST_SIZE=$(env_val "${req_mb}MB")

# ---- 初始管理员（库里还没有管理员时才创建）----
ADMIN_USERNAME=$(env_val "$ADMIN_USER")
ADMIN_PASSWORD=$(env_val "$ADMIN_PASS")
ADMIN_EMAIL=$(env_val "$ADMIN_EMAIL")

# ---- nginx 就在本机，只信任本机代理 ----
TRUSTED_PROXIES=$(env_val "127.0.0.1,::1")

# ---- 登录与限流 ----
MAX_LOGIN_ATTEMPTS=$(env_val "5")
LOGIN_LOCK_MINUTES=$(env_val "30")
RATE_LIMIT_ENABLED=$(env_val "true")
RATE_LIMIT_RPM=$(env_val "60")
RATE_LIMIT_AUTH_RPM=$(env_val "10")
CODE_SEND_INTERVAL=$(env_val "60")
ADMIN_IP_WHITELIST=""

# ---- IronWall 安全引擎 ----
IRONWALL_RULES_FILE=$(env_val "$APP_DIR/config/ironwall-rules.json")
IRONWALL_RESERVED_PORTS=""
ATTACK_GUARD_LOGIN_HONEYPOT_ENABLED=$(env_val "true")
ATTACK_GUARD_LOGIN_HONEYPOT_USERNAMES=$(env_val "administrator_backup,support_root")
BAN_SYNC_ENABLED=$(env_val "true")
BAN_SYNC_INTERVAL_MS=$(env_val "30000")
ALERTS_ENABLED=$(env_val "true")
ALERTS_EMAIL_ENABLED=$(env_val "false")
ALERTS_WEBHOOK_URL=""
STORAGE_ENCRYPTION_ENABLED=$(env_val "true")
IRONWALL_STORAGE_KEY=""
STORAGE_ENCRYPTION_KEY_FILE=$(env_val "$JDY_ETC/storage-master.key")
TOTP_STATE_FILE=$(env_val "$APP_DIR/config/totp-state.json")
ATTACK_GUARD_DDOS_LOG_PATH=$(env_val "$APP_DIR/logs/ddos.log")
SERVER_SHIELD_STATE_FILE=$(env_val "$APP_DIR/config/server-shield.state")
ATTACK_GUARD_MOBILE_CARRIER_ENABLED=$(env_val "true")

# ---- 日志 ----
F2B_LOG_FILE=$(env_val "$APP_DIR/logs/ironwall-attacks.log")
LOG_LEVEL=$(env_val "INFO")
SHOW_SQL=$(env_val "false")

# ---- 邮件（留空则站内不发信；要验证码再填）----
MAIL_HOST=""
MAIL_PORT=$(env_val "587")
MAIL_USERNAME=""
MAIL_PASSWORD=""
EOF
    if [ "$DRY_RUN" = 0 ]; then
        chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    fi
    ok "配置文件：$CONFIG_FILE"
}

step_config() {
    step "4/9 写配置（数据库、密钥、管理员、安全引擎）"
    write_config
    if [ "$CONFIG_FILE" != "$JDY_ETC/$APP_SLUG.env" ]; then
        run cp -f "$CONFIG_FILE" "$JDY_ETC/$APP_SLUG.env" || true
    fi
}

# ---------------------------------------------------------------- 5. 安全规则 ---
step_rules() {
    step "5/9 安全引擎规则"
    local rules="$APP_DIR/config/ironwall-rules.json"
    local sample="$REPO/backend/config/ironwall-rules.sample.json"
    if [ -f "$rules" ]; then
        ok "已存在规则文件，保留不动：$rules"
        return 0
    fi
    if [ -f "$sample" ]; then
        run cp -f "$sample" "$rules"
        ok "已从样例生成：$rules（可按需修改，热生效）"
    else
        warn "源码里没有 ironwall-rules.sample.json：引擎会退回内置默认规则"
    fi
}

# ------------------------------------------------------------------- 6. 数据库 ---
mysql_exec() {
    local pass="$1"; shift
    if [ -n "$pass" ]; then
        "$MYSQL_CLI" -uroot -p"$pass" "$@"
    else
        "$MYSQL_CLI" -uroot "$@"
    fi
}

step_database() {
    step "6/9 建库、建账号、导入表结构"
    local root_pw="${MYSQL_ROOT_PASSWORD:-}"
    local sql="CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;"
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] 建库 $DB_NAME、账号 $DB_USER"
        log "    [试运行] 导入 backend/src/main/resources/db/init.sql（8 张表）"
        return 0
    fi
    [ -n "$MYSQL_CLI" ] || die "找不到 mysql 客户端：请确认 MySQL 已安装并启动"
    if have systemctl; then
        local svc
        for svc in mysqld mysql mariadb; do
            systemctl is-active --quiet "$svc" 2>/dev/null && break
            systemctl start "$svc" >/dev/null 2>&1 && break
        done
    fi
    if [ -x /etc/init.d/mysqld ]; then /etc/init.d/mysqld start >/dev/null 2>&1 || true; fi
    if ! mysql_exec "$root_pw" -e "SELECT 1;" >/dev/null 2>&1; then
        if [ -n "$root_pw" ]; then
            die "MySQL root 密码不对：核对后用 --mysql-root-pass 指定重跑"
        fi
        warn "root 免密连不上：若面板环境用的是 /root/.my.cnf 里的凭据，请手动导入 init.sql"
    fi
    mysql_exec "$root_pw" -e "$sql" || die "建库失败：请检查 MySQL 是否正常运行"
    ok "数据库就绪：$DB_NAME（账号 $DB_USER）"
    sed -e "s/^CREATE DATABASE IF NOT EXISTS jdy_cloud/CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`/" \
        -e "s/^USE jdy_cloud;/USE \`$DB_NAME\`;/" \
        "$REPO/backend/src/main/resources/db/init.sql" | mysql_exec "$root_pw" || die "导入表结构失败"
    ok "表结构导入完成：users / files / folders / shares / announcements / login_history / notification_settings / system_config"
}

# -------------------------------------------------------------------- 7. 前端 ---
build_frontend() {
    local dist_src="" zip="" tmp="" f
    local site_base=""
    if [ "$HAS_DOMAIN" = 1 ]; then
        if [ "$ENABLE_SSL" = 1 ]; then site_base="https://$DOMAIN"; else site_base="http://$DOMAIN"; fi
    fi
    if [ -f "$REPO/frontend/dist/index.html" ]; then
        dist_src="$REPO/frontend/dist"
        ok "使用仓库里的 frontend/dist"
    else
        for f in "$REPO/release/前端.zip" "$REPO/release/frontend.zip" "$REPO/前端.zip" "$REPO/frontend.zip"; do
            if [ -f "$f" ]; then zip="$f"; break; fi
        done
        if [ -z "$zip" ] && have curl; then
            zip="$(mktemp -u).zip"
            if run curl -fsSL --retry 2 -o "$zip" "${PREBUILD_URL:-$DEFAULT_PREBUILD_URL}"; then
                ok "已下载编译好的前端压缩包"
            else
                rm -f "$zip"; zip=""
            fi
        fi
        if [ -n "$zip" ]; then
            tmp="$(mktemp -d)"
            run unzip -q -o "$zip" -d "$tmp"
            if [ -f "$tmp/index.html" ]; then
                dist_src="$tmp"
            else
                dist_src="$(dirname "$(find "$tmp" -name index.html -print -quit 2>/dev/null)")"
            fi
        fi
    fi

    if [ -z "$dist_src" ] || [ ! -f "$dist_src/index.html" ]; then
        if [ "$USE_PREBUILD" = 1 ]; then warn "没找到预编译前端，改为在服务器上编译"; fi
        have node || die "服务器上没有 Node.js：请装 Node 18+，或先用 --use-prebuild"
        put_file "$REPO/frontend/.env.local" <<EOF
VITE_SITE_NAME=$SITE_NAME
VITE_SITE_SHORT_NAME=$SITE_SHORT
VITE_SITE_DOMAIN=$DOMAIN
VITE_SITE_URL=$site_base
VITE_CONTACT_EMAIL=$CONTACT_EMAIL
EOF
        ok "编译前端（npm ci + npm run build，第一次要几分钟）"
        ( cd "$REPO/frontend" && run npm ci --no-audit --no-fund && run npm run build )
        dist_src="$REPO/frontend/dist"
    fi
    [ -n "$dist_src" ] && [ -f "$dist_src/index.html" ] || die "前端产物不完整，缺 index.html"
    run mkdir -p "$WEB_ROOT"
    if [ "$DRY_RUN" = 0 ]; then
        cp -rf "$dist_src"/. "$WEB_ROOT"/
    else
        log "    [试运行] 复制 $dist_src/* -> $WEB_ROOT"
    fi
    ok "前端已就位：$WEB_ROOT"
}

step_frontend() {
    step "7/9 部署前端"
    if [ "$SKIP_FRONTEND" = 1 ]; then
        warn "已指定 --skip-frontend：只装了后端"
        return 0
    fi
    build_frontend
}

# -------------------------------------------------------------------- 8. 网关 ---
render_nginx_conf() {
    local req_mb=$(( MAX_FILE_MB + 170 ))
    local server_name="_"
    if [ "$HAS_DOMAIN" = 1 ]; then server_name="$DOMAIN www.$DOMAIN"; fi
    put_file "$NGINX_CONF" <<EOF
# 经典云网盘 · nginx 站点配置（install.sh 生成）
server {
    listen 80;
    listen [::]:80;
    server_name $server_name;

    root $WEB_ROOT;
    index index.html;
    charset utf-8;

    server_tokens off;
    client_max_body_size ${req_mb}m;
    client_body_timeout 60s;

    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf)\$ {
        expires 7d;
        add_header Cache-Control "public, max-age=604800";
        access_log off;
    }

    location ^~ /api/ {
        proxy_pass http://127.0.0.1:$SERVER_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";

        client_max_body_size ${req_mb}m;
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
        proxy_request_buffering off;
    }

    location ~ ^/(\.env|\.git|node_modules|package\.json|package-lock\.json|vite\.config\.ts) {
        return 404;
    }
    location ~* \.(sh|jar|sql|log|bak|example)\$ {
        return 404;
    }
}
EOF
    ok "网关配置：$NGINX_CONF"
}

step_nginx() {
    step "8/9 配置 nginx"
    render_nginx_conf
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] 跳过 nginx 校验与重载"
        return 0
    fi
    if [ -n "$NGINX_BIN" ]; then
        if "$NGINX_BIN" -t >/dev/null 2>&1; then
            "$NGINX_BIN" -s reload >/dev/null 2>&1 || warn "nginx 重载失败：请到面板里重启 nginx"
            ok "nginx 已加载站点配置"
        else
            warn "nginx 配置检查不通过，执行 $NGINX_BIN -t 看详情"
        fi
    else
        warn "没找到 nginx：配置已生成在 $NGINX_CONF，装好后 reload 即可"
    fi
}

# ------------------------------------------------------------ 9. 守护与完成 ---
write_run_script() {
    put_file "$APP_DIR/$APP_SLUG-run.sh" <<EOF
#!/usr/bin/env bash
# 由 install.sh 生成：前台运行后端（环境变量由 systemd EnvironmentFile 注入）
set -e
cd "$APP_DIR"
mkdir -p logs
exec "$JAVA_BIN" -Xmx1024M -XX:+UseG1GC -Dfile.encoding=UTF-8 \\
    -jar "$APP_DIR/$APP_SLUG.jar" >>"$APP_DIR/logs/app.log" 2>&1
EOF
    run chmod +x "$APP_DIR/$APP_SLUG-run.sh"
}

write_bt_scripts() {
    put_file "$APP_DIR/bt-start.sh" <<EOF
#!/usr/bin/env bash
# 宝塔「Java 项目管理器」专用：前台运行，把进程交给面板守护
set -e
cd "$APP_DIR"
mkdir -p logs
. "$APP_DIR/start.env"
exec "$JAVA_BIN" -Xmx1024M -XX:+UseG1GC -Dfile.encoding=UTF-8 -jar "$APP_DIR/$APP_SLUG.jar"
EOF
    run chmod +x "$APP_DIR/bt-start.sh"
    ok "宝塔启动脚本：$APP_DIR/bt-start.sh"
}

install_systemd() {
    put_file "/etc/systemd/system/$APP_SLUG.service" <<EOF
[Unit]
Description=Classic Cloud ($APP_SLUG) backend
Documentation=https://github.com/$GITHUB_REPO
After=network-online.target mysqld.service mysql.service mariadb.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONFIG_FILE
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/$APP_SLUG-run.sh
Restart=always
RestartSec=5
LimitNOFILE=65535
SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
EOF
    run systemctl daemon-reload
    run systemctl enable --now "$APP_SLUG.service"
}

step_service() {
    step "9/9 启动与开机自启"
    if [ "$SERVICE_MODE" = "bt-java" ]; then
        write_bt_scripts
        warn "宝塔托管模式：后端由面板启动，见下面「面板里怎么填」"
        return 0
    fi
    write_run_script
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] 跳过 systemd 安装与启动"
        return 0
    fi
    if have systemctl; then
        install_systemd
        sleep 3
        if systemctl is-active --quiet "$APP_SLUG.service"; then
            ok "后端已启动，并已设为开机自启"
        else
            warn "服务没起来：看日志 tail -100 $APP_DIR/logs/app.log"
        fi
    else
        warn "这台机器没有 systemd：手动运行 $APP_DIR/$APP_SLUG-run.sh &"
    fi
}

step_ssl() {
    if [ "$HAS_DOMAIN" = 0 ] || [ "$ENABLE_SSL" = 0 ]; then return 0; fi
    step "附加：申请 HTTPS 证书"
    if [ "$DRY_RUN" = 1 ]; then
        log "    [试运行] 跳过 certbot"
        return 0
    fi
    if have certbot; then
        if certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos \
                -m "${CONTACT_EMAIL:-$ADMIN_EMAIL}" --redirect >/dev/null 2>&1; then
            ok "HTTPS 已生效：https://$DOMAIN"
        else
            warn "证书没申请成功（域名解析未生效时属正常）：稍后执行 certbot --nginx -d $DOMAIN"
        fi
    else
        warn "没装 certbot：装好后执行 certbot --nginx -d $DOMAIN"
    fi
}

write_result() {
    local host="$DOMAIN" scheme="http" site_url admin_url ssl_json="false" bt_json="null"
    if [ "$HAS_DOMAIN" = 0 ]; then
        host="$(detect_public_ip)"
        [ -n "$host" ] || host="127.0.0.1"
    fi
    site_url="$scheme://$host"
    if [ "$HAS_DOMAIN" = 1 ] && [ "$ENABLE_SSL" = 1 ]; then
        site_url="https://$host"
        ssl_json="true"
    fi
    admin_url="$site_url/admin"

    put_file "$JDY_ETC/install.conf" <<EOF
# 本次安装的输入参数（重装时可直接照抄）
DOMAIN=$(env_val "$DOMAIN")
SITE_NAME=$(env_val "$SITE_NAME")
SITE_SHORT=$(env_val "$SITE_SHORT")
CONTACT_EMAIL=$(env_val "$CONTACT_EMAIL")
ADMIN_USER=$(env_val "$ADMIN_USER")
DB_NAME=$(env_val "$DB_NAME")
DB_USER=$(env_val "$DB_USER")
SERVER_PORT=$(env_val "$SERVER_PORT")
MAX_FILE_MB=$(env_val "$MAX_FILE_MB")
WEB_ROOT=$(env_val "$WEB_ROOT")
APP_DIR=$(env_val "$APP_DIR")
CONFIG_FILE=$(env_val "$CONFIG_FILE")
BT_JAVA=$(env_val "$BT_JAVA")
EOF

    if [ "$BT_JAVA" = 1 ]; then
        local jdk_dir
        jdk_dir="$(dirname "$(dirname "$JAVA_BIN")")"
        bt_json=$(cat <<EOF
{
    "enabled": true,
    "panel_path": "网站 → Java 项目 → 添加 Java 项目",
    "project_type": "SpringBoot",
    "project_path": "$(jesc "$(dirname "$APP_DIR")")",
    "takeover": "不勾选（这是新项目，不是接管原项目）",
    "project_name": "$(jesc "$(basename "$APP_DIR")")",
    "jdk": "$(jesc "$(basename "$jdk_dir")")（完整路径 $(jesc "$jdk_dir")）",
    "start_command": "bash $APP_DIR/bt-start.sh",
    "port": "$(jesc "$SERVER_PORT")",
    "domain_field": "$(jesc "$DOMAIN")",
    "env": [
        "面板若要求逐条填环境变量，照抄 $CONFIG_FILE 的内容即可；启动命令保持 bash $APP_DIR/bt-start.sh"
    ],
    "fallback_command": "只用 java 命令时：把 $CONFIG_FILE 逐条填进面板「环境变量」，再填 $JAVA_BIN -jar $APP_DIR/$APP_SLUG.jar",
    "why_start_script": "启动命令一定要用 bt-start.sh：直接 java -jar 会缺数据库密码与密钥，后端起不来"
}
EOF
)
    fi

    put_file "$JDY_ETC/install-result.json" <<EOF
{
    "installer_version": "$(jesc "$INSTALLER_VERSION")",
    "installed_at": "$(date -Is)",
    "dry_run": $([ "$DRY_RUN" = 1 ] && echo true || echo false),
    "site_url": "$(jesc "$site_url")",
    "admin_url": "$(jesc "$admin_url")",
    "admin_username": "$(jesc "$ADMIN_USER")",
    "admin_password": "$(jesc "$ADMIN_PASS")",
    "web_root": "$(jesc "$WEB_ROOT")",
    "config_file": "$(jesc "$CONFIG_FILE")",
    "app_dir": "$(jesc "$APP_DIR")",
    "domain": "$(jesc "$DOMAIN")",
    "ssl": $ssl_json,
    "backend_port": "$(jesc "$SERVER_PORT")",
    "database": "$(jesc "$DB_NAME")",
    "db_user": "$(jesc "$DB_USER")",
    "service": "$(jesc "$SERVICE_MODE")",
    "bt_java": $bt_json
}
EOF
    if [ "$DRY_RUN" = 0 ]; then
        chmod 600 "$JDY_ETC/install-result.json" "$JDY_ETC/install.conf" 2>/dev/null || true
    fi
    ok "安装结果：$JDY_ETC/install-result.json"
}

step_summary() {
    local host="$DOMAIN" scheme="http"
    if [ "$HAS_DOMAIN" = 0 ]; then
        host="$(detect_public_ip)"
        [ -n "$host" ] || host="<服务器IP>"
    fi
    if [ "$HAS_DOMAIN" = 1 ] && [ "$ENABLE_SSL" = 1 ]; then scheme="https"; fi
    printf '\n============================================================\n'
    if [ "$DRY_RUN" = 1 ]; then
        printf '   试运行结束：计划已生成，服务器没有改动\n'
    else
        printf '   安装完成，站点已经跑起来了\n'
    fi
    printf '============================================================\n'
    printf '  首页地址   %s://%s\n' "$scheme" "$host"
    printf '  后台地址   %s://%s/admin\n' "$scheme" "$host"
    printf '  管理员     %s / %s\n' "$ADMIN_USER" "$ADMIN_PASS"
    printf '  站点目录   %s\n' "$WEB_ROOT"
    printf '  配置文件   %s\n' "$CONFIG_FILE"
    printf '  程序目录   %s\n' "$APP_DIR"
    printf '  数据库     %s（账号 %s）\n' "$DB_NAME" "$DB_USER"
    printf '\n'
    if [ "$SERVICE_MODE" = "bt-java" ]; then
        printf '  还差一步：宝塔「网站 → Java 项目 → 添加 Java 项目」按下面填，然后点启动\n'
        printf '    项目类型   SpringBoot\n'
        printf '    项目路径   %s\n' "$(dirname "$APP_DIR")"
        printf '    项目名称   %s\n' "$(basename "$APP_DIR")"
        printf '    项目 JDK   %s\n' "$(dirname "$(dirname "$JAVA_BIN")")"
        printf '    启动命令   bash %s/bt-start.sh\n' "$APP_DIR"
        printf '    项目端口   %s\n' "$SERVER_PORT"
        printf '    记得把「开机自启」勾上\n\n'
    fi
    printf '  常用命令：\n'
    printf '    看日志     tail -f %s/logs/app.log\n' "$APP_DIR"
    printf '    重启后端   systemctl restart %s\n' "$APP_SLUG"
    printf '    升级版本   替换 %s/%s.jar 后重启\n\n' "$APP_DIR" "$APP_SLUG"
    printf '  请把管理员账号密码存到安全的地方。\n\n'
}

# -------------------------------------------------------------------- 主流程 ---
main() {
    parse_args "$@"
    validate
    printf '\n经典云网盘 · 全自动安装器 v%s\n' "$INSTALLER_VERSION"
    printf '源码目录   %s\n' "$REPO"
    printf '域名       %s\n' "${DOMAIN:-（无，用 IP 访问）}"
    printf '站点名称   %s（%s）\n' "$SITE_NAME" "$SITE_SHORT"
    printf '管理员     %s\n' "$ADMIN_USER"
    printf '数据库     %s / %s\n' "$DB_NAME" "$DB_USER"
    printf '后端端口   %s\n' "$SERVER_PORT"
    printf '文件上限   %s MB\n' "$MAX_FILE_MB"
    printf 'HTTPS      %s\n' "$([ "$ENABLE_SSL" = 1 ] && echo 是 || echo 否)"
    printf '前端       %s\n' "$([ "$SKIP_FRONTEND" = 1 ] && echo 跳过 || echo 部署)"
    printf '托管方式   %s\n' "$([ "$BT_JAVA" = 1 ] && echo '宝塔 Java 项目管理器' || echo 'systemd 守护')"
    if [ "$DRY_RUN" = 1 ]; then printf '试运行模式：不会改动服务器\n'; fi
    if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" != "0" ]; then
        die "需要 root 权限：前面加 sudo 再跑一次"
    fi
    confirm
    detect_system
    resolve_paths
    detect_java || true
    step_deps
    resolve_paths
    detect_java || true
    [ -n "$JAVA_BIN" ] || die "没有可用的 JDK 21：装好后重跑（或用 --jdk-url / --java-home 指定）"
    step_dirs
    step_backend
    step_config
    step_rules
    step_database
    step_frontend
    step_nginx
    step_service
    step_ssl
    write_result
    step_summary
    if [ "$WEB_MODE" = 1 ]; then
        step "环境就绪，接着启动网页安装向导"
        have python3 || pkg_install python3 || die "没有 python3，无法启动网页向导"
        exec python3 "$REPO/installer/web-install.py" --repo "$REPO"
    fi
}

main "$@"
