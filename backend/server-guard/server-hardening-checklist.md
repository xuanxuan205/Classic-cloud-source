# 服务器层防护加固清单（经典云铁壁安全引擎 v1.26.0 配套）

> 原则：网站层（IronWall）负责「识别与阻断攻击」，服务器层负责「让攻击者连门都摸不到」。
> 两者通过 fail2ban 联动桥衔接：网站层封禁 -> 服务器层全端口封禁。

## 1. 入口收敛（防火墙）
- 对外只开放：80 / 443（网站），22 改为高位端口（如 22022），宝塔面板端口仅管理员 IP 可访问。
- 宝塔面板 -> 安全：放行 80/443、SSH 新端口；MySQL 3306、Redis 6379、Java 15060 一律不对外。
- 建议：`systemctl enable firewalld && systemctl start firewalld` 或使用宝塔系统防火墙。
- 你放行的管理端口要告诉采集脚本，否则会被当成「超出白名单」告警：
  编辑 `update-ironwall-shield.sh` 顶部的 `IRONWALL_ADMIN_PORTS`（逗号分隔，默认 `888`）。

## 2. SSH 加固
- 禁止 root 密码登录：`PermitRootLogin prohibit-password`，改用密钥登录。
- 修改默认端口；安装 fail2ban 的 sshd 监狱（宝塔 fail2ban 插件自带）。
- 关闭密码登录：`PasswordAuthentication no`（确认已配置密钥后执行）。

## 3. 数据库安全
- MySQL 只监听内网：`/etc/my.cnf` 增加 `bind-address = 127.0.0.1`，重启 MySQL。
- 应用账号最小权限：jdy_cloud 账号只授 jdy_cloud 库，禁止 FILE/SUPER 权限。
- 每周自动备份：宝塔计划任务 mysqldump + 异地转存。

## 4. 文件与权限
- 站点目录 `/www/wwwroot/example.com`、后端 `/www/wwwroot/jdy-cloud` 均属 www 用户，目录 755 / 文件 644。
- 开启宝塔【企业级防篡改】保护后端目录（jar、.env、start.sh、logs）。
- 上传目录 uploads 禁止执行权限；nginx 已 404 拦截敏感文件。

## 5. 主机入侵检测
- 已装插件：bt_hids（主机入侵检测）、bt_clamav（病毒扫描）、btwaf（宝塔 WAF）——保持开启并每月全盘扫描。
- fail2ban：新增 ironwall 监狱（本目录 install-ironwall-f2b.sh）。

## 6. nginx 运维接口收敛
- 默认站点 / default_server 中 `/nginx_status` 与 `/server-status` 必须 `allow 127.0.0.1; deny all;`。
- 修复文件：`server-guard/nginx_status_fix.conf`，粘贴后 `nginx -t && nginx -s reload`。
- `update-ironwall-shield.sh` 已加入 nginx_status 暴露检测，面板会显示告警。

## 7. 假端口陷阱（新增）
- 执行 `bash server-guard/install-decoy-ports.sh` 安装五层随机假端口陷阱。
- 每层 3 个高段端口随机生成，攻击者踩入即被吞没取证，并联动 fail2ban 全端口封禁。
- 状态：`/www/wwwroot/jdy-cloud/logs/decoy-port-state.json`，命中：`decoy-port-hits.log`。
- 诱饵端口默认只避开常见服务端口。你若用了自定义面板 / SSH 端口，把它们写进
  `/etc/systemd/system/ironwall-decoy.service` 的 `Environment="IRONWALL_RESERVED_PORTS=888,22022"`，
  改完执行 `systemctl daemon-reload && systemctl restart ironwall-decoy.service`；
  同一条清单也填进 `start.sh`（或 `.env`）的后端侧，管理面板显示的端口才与实际一致。

## 8. 端口扫描检测（新增）
- 执行 `bash server-guard/install-portscan-guard.sh` 安装端口扫描采集与全端口封禁监狱。
- 攻击者短时间探测多个端口，即触发 `ironwall-portscan` 全端口封禁。
- 状态：`/www/wwwroot/jdy-cloud/logs/portscan-state.json`，命中：`ironwall-portscan.log`。

## 9. 备份与应急
- 每日：数据库 + uploads 增量 + nginx/应用配置。
- 应急流程：确认攻击 -> fail2ban-client status ironwall 查看封禁 -> 需要时全站维护页 -> 从备份恢复 -> 复盘攻击流水（IronWall 管理后台）。
