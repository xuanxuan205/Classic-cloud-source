# 边缘 TLS 指纹（JA4）部署包

## 一、部署前提
- 需要一套可自行编译动态模块的 nginx + OpenSSL 环境；本包提供原生 nginx 探测式补丁，
  编译产物为 `ngx_http_ssl_ja4_module.so`，通过 `load_module` 加载。
  构建脚本见 `server-guard/ja4/build-ja4-module.sh`。
- 模块注册变量名为 `http_ssl_ja4`（不是 `$ssl_ja4`），反代配置注入：

```
proxy_set_header X-TLS-JA4 $http_ssl_ja4;
```

- 自检方式：`curl -sk --resolve 你的域名:443:127.0.0.1 https://你的域名/ja4-debug`
  预期返回形如 `JA4=t12d280000_<客户端哈希>_<扩展哈希>` 的字符串。

## 二、后端消费
- `TlsProfileResolver` 优先采信 `X-TLS-JA4`；`JA4_SHAPE` 接受 ALPN 段 0~2 位
  （客户端未发 ALPN 时省略该段，符合 JA4 规范）。
- 归一键 `tls:sha256[:32]`，供跨 IP 攻击证据聚合与账号级 TLS 绑定
  （默认关闭：`API_CRYPTO_TLS_BIND_ENABLED=false`，启用后指纹不一致只 403 重握手、不计分）。

## 三、已知局限（原生 nginx，零误伤原则下的取舍）
- 扩展段计数 `0000`、扩展哈希 `000000000000`（OpenSSL 无公开的扩展枚举接口）；
  密码套件段哈希真实有效、随客户端密码集变化。
- HTTP/3(QUIC) 连接不产生 TLS 变量 -> 头为空 -> 后端自动回退忽略，绝不误封。
- FOXIO 官方 nginx 分支仓库不可用，整树替换路线已放弃；兼容补丁记录见
  `server-guard/ja4/vanilla-nginx-compat.patch.sh`（v3）。

## 四、运维
- 构建 / 注入 / 自检：`server-guard/ja4/{build-ja4-module.sh, apply-ja4-header.sh, verify-ja4.sh}`
- 回滚：`bash rollback-ja4.sh <备份目录>`；二进制与配置备份 `nginx.bak.ja4` / `nginx.conf.bak.ja4`
- 验收完成后删除临时端点 `/ja4-debug`（站点配置内 `location = /ja4-debug` 段）。
- 旧回退方案：njs 形指纹 `ja4.conf` + `ja4.js`（模块不可用时再启用）。
