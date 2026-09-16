package com.jdy.cloud.config;

import com.jdy.cloud.util.ClientIpUtils;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * IronWall v1.6: 将可信反向代理列表注入 ClientIpUtils。
 * 默认信任本机回环（nginx 与后端同机部署），可通过 app.security.trusted-proxies 扩展分机部署场景。
 */
@Configuration
public class ClientIpConfig {

    @Value("${app.security.trusted-proxies:127.0.0.1,::1,0:0:0:0:0:0:0:1}")
    private String trustedProxies;

    @PostConstruct
    public void init() {
        ClientIpUtils.configureTrustedProxies(trustedProxies);
    }
}