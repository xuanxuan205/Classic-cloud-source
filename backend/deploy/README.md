# nginx / 部署模板

本目录是**模板**，不是可直接执行的配置。

| 文件 | 用途 |
| --- | --- |
| `site-full-v1472.conf` | 站点完整 server 块（HTTP/HTTPS/QUIC 监听、SSL、SPA 回退、缓存） |
| `nginx-sensitive-paths-v1479.conf` | 敏感路径拦截段，粘到 server{} 内、SPA 回退之前 |
| `nginx-response-headers-v1479.conf` | 安全响应头 |
| `nginx-http-zones-v1477.conf` | `limit_req_zone` / `limit_conn_zone` 定义，缺此段 `nginx -t` 会报 zone 未定义 |
| `proxy-api-template-v1477.conf` | `/api/` 反代段 |
| `logrotate-jdy-cloud.conf` | 日志轮转 |
| `nginx-ja4/` | JA4 TLS 指纹模块编译与接入 |

## 使用前必须替换

- **域名**：模板中统一为 `example.com`，替换成你自己的域名。
- **证书路径**：`ssl_certificate` / `ssl_certificate_key` 指向你的证书。
- **站点根目录与日志目录**：模板按 `/www/wwwroot/<域名>`、`/www/wwwlogs/` 的宝塔面板结构书写，
  非面板环境请按实际路径调整。
- **后端端口**：模板默认 `127.0.0.1:15060`，与 `SERVER_PORT` 保持一致。

全局替换示例：

```bash
cd deploy
grep -rl "example.com" . | xargs sed -i 's/example\.com/你的域名/g'
```

## 下线提醒

`nginx-sensitive-paths-*.conf` 拦截的是常见扫描器探测路径。若你的站点本身
在 `/api/` 下提供同名路径（例如自建 `phpmyadmin`），请先在预发环境 `nginx -t` 并回归，
避免把正常业务一起拦掉。
