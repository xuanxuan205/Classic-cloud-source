package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * IronWall v1.17 蜜标令牌（Canary Token）服务。
 *
 * 蜜罐接口返回的假配置/假凭据中内嵌唯一令牌；攻击者一旦把这些"偷到的凭据"
 * 回放进请求头（Authorization / X-Admin-Token / token 参数），立即触发
 * 高置信度告警与快速封禁升级——不进行任何反向攻击，只记录并拦截。
 */
@Slf4j
@Service
public class CanaryService {

    public static final String PREFIX = "IronWall.Canary.";

    private final String token;

    public CanaryService(@Value("${app.security.canary-token:}") String configuredToken) {
        this.token = (configuredToken == null || configuredToken.isBlank())
                ? PREFIX + UUID.randomUUID().toString().replace("-", "")
                : PREFIX + configuredToken.trim();
    }

    public String token() {
        return token;
    }

    public boolean isCanaryValue(String value) {
        return value != null && value.contains(token);
    }

    public boolean isCanaryPresent(HttpServletRequest request) {
        if (request == null) return false;
        return isCanaryValue(request.getHeader("Authorization"))
                || isCanaryValue(request.getHeader("X-Admin-Token"))
                || isCanaryValue(request.getParameter("token"));
    }
}
