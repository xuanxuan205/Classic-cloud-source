#!/bin/bash
# ============================================================
# 经典云铁壁安全引擎 IronWall v1.23.0
# 网站层 -> 服务器层 联动桥 一键安装脚本（宝塔/CentOS/RHEL 系）
# 用法： bash install-ironwall-f2b.sh
# ============================================================
set -e

if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行：bash install-ironwall-f2b.sh"
  exit 1
fi

command -v fail2ban-client >/dev/null 2>&1 || {
  echo "未检测到 fail2ban，请先在宝塔面板【软件商店】安装 fail2ban 防爆破插件"
  exit 1
}

echo "[1/4] 安装过滤器与监狱配置..."
cp -f fail2ban-filter-ironwall.conf /etc/fail2ban/filter.d/ironwall.conf
cp -f fail2ban-jail-ironwall.conf /etc/fail2ban/jail.d/ironwall.conf

echo "[2/4] 校验配置语法..."
fail2ban-client -t 2>&1 || true

echo "[3/4] 重启 fail2ban..."
if systemctl list-unit-files | grep -q fail2ban; then
  systemctl restart fail2ban
else
  /etc/init.d/fail2ban restart
fi

echo "[4/4] 查看 IronWall 监狱状态..."
sleep 2
fail2ban-client status ironwall || echo "监狱状态查询失败，请检查 /var/log/fail2ban.log"

echo ""
echo "安装完成。IronWall 一旦封禁攻击者 IP，fail2ban 将自动全端口封禁该 IP。"
echo "封禁记录：fail2ban-client status ironwall"
echo "解封：fail2ban-client set ironwall unbanip <IP>"