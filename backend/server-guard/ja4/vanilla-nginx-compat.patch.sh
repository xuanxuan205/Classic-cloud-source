# IronWall JA4 兼容性修正记录（v2，修正上一版误判）
# ============================================================
# 关键更正：首次编译日志只看到 tail，误判为“仅 3 处 fork 字段”。
# 完整编译错误显示 FOXIO ja4-nginx-module 依赖其 nginx 分支的字段共 5 组：
# 1) c->ssl->first_alpn (L146)
# 2) c->ssl->highest_supported_tls_client_version (L152)
# 3) c->ssl->extensions / extensions_sz (L279-315)
# 4) c->ssl->sigalgs_hash_values / sigalgs_sz (L367-406)
# 5) c->ssl->handshake_roundtrip_microseconds / ttl (L1801-1802)
# 另：gcc4.8 默认 gnu90，需 -std=gnu99 编译该模块。
# 结论：该模块为 FOXIO nginx 分支量身定做，原生 nginx 移植需要重写数据采集层。
# 两条路线：
# A) 用 FOXIO-LLC/nginx 分支整体编译并替换 nginx 二进制（官方语义，需备份回滚）
# B) 原生 nginx + 补丁：扩展枚举改“已知扩展清单探测”(SSL_client_hello_get0_ext)，
# ALPN(ext16)/版本(ext43) 从 ClientHello 扩展解析，JA4L 置 0，加 -std=gnu99。
# （原生 OpenSSL 无枚举全部扩展的公开接口，属近似实现）
# 服务器当前状态：模块源码为“半补丁”状态（sigalgs 两处与 ttl 已替换，
# 静态变量声明与 handshake_roundtrip 替换因粘贴换行失败未生效）。
# 备份：/tmp/ngx_http_ssl_ja4_module.c.bak.ja4（原始文件）