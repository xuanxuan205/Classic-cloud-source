package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.security.ApiCryptoService;
import com.jdy.cloud.security.ApiRouteTable;
import com.jdy.cloud.security.CrawlerDefenseFilter;
import com.jdy.cloud.security.DeviceIdentityResolver;
import com.jdy.cloud.security.JwtTokenProvider;
import com.jdy.cloud.security.TlsProfileResolver;
import com.jdy.cloud.util.ClientIpUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.40.0: 接口加密层密钥签发入口。
 *
 * 签发门槛（三者缺一不可）：
 * 1) 已通过爬虫 JS 挑战（iw_ok HMAC 签名 cookie 有效）；
 * 2) 携带浏览器设备指纹（X-IronWall-FP）；
 * 3) 单 IP 限频（默认 10 次/分）。
 *
 * 返回：会话密钥 + AES-GCM 加密的路由地图（真实接口路径只在运行时解密到内存，
 * 不出现在前端包与静态流量中；任何未带有效签名的 /api 请求被 ApiCryptoFilter 拒绝）。
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class BootstrapController {

    private final ApiCryptoService apiCryptoService;
    private final ApiRouteTable apiRouteTable;
    private final CrawlerDefenseFilter crawlerDefenseFilter;
    private final DeviceIdentityResolver deviceIdentityResolver;
    private final TlsProfileResolver tlsProfileResolver;
    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, Window> ipWindows = new ConcurrentHashMap<>();

    @Value("${app.security.api-crypto.bootstrap-max-per-minute:10}")
    private int bootstrapMaxPerMinute;

    @PostMapping("/bootstrap")
    public ResponseEntity<ApiResponse<Map<String, Object>>> bootstrap(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        if (!allow(ip)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(CrawlerDefenseFilter.CHALLENGE_HEADER, "1")
                    .body(ApiResponse.error(429, "握手过于频繁，请稍后再试"));
        }
        if (crawlerDefenseFilter.isChallengeEnabled() && !crawlerDefenseFilter.hasValidChallengeProof(request)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(CrawlerDefenseFilter.CHALLENGE_HEADER, "1")
                    .body(ApiResponse.error(429, "请先完成浏览器安全验证"));
        }
        DeviceIdentityResolver.Identity identity = deviceIdentityResolver.resolve(request);
        if (identity.fingerprint() == null || identity.fingerprint().isBlank()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(ApiResponse.error(403, "缺少设备指纹"));
        }

        // IronWall v1.41.0: 会话绑定边缘 TLS 指纹（无边缘头时为 null，比对自动跳过）
        // IronWall v1.42.1 -HOTFIX: 分级下发暂缓——前端 bootstrap 未携带 Authorization，
        // 登录后仍使用匿名地图，files/admin 路由码不在其中，签名还原失败造成 403 误伤。
        // 恢复全量下发（权限边界由 Spring Security 保证）；待前端实现
        // 「登录/登出强制重握手 + bootstrap 携带 Authorization」后重新启用 resolveTier。
        String tlsProfile = tlsProfileResolver.resolve(request);
        ApiCryptoService.Session session = apiCryptoService.issueSession(tlsProfile);
        String routeMap;
        String codeMap;
        try {
            // IronWall v1.41.0: 路由地图键为路由码（当期盐+无盐双键），值含 {n} 动态占位符
            routeMap = apiCryptoService.encryptRouteMap(session.key(),
                    objectMapper.writeValueAsString(apiRouteTable.routeMap(ApiRouteTable.TIER_ADMIN)));
            // IronWall v1.42.0: 无盐旧码 -> 当期码 翻译表（老前端无该字段自动忽略）
            codeMap = apiCryptoService.encryptRouteMap(session.key(),
                    objectMapper.writeValueAsString(apiRouteTable.codeMap(ApiRouteTable.TIER_ADMIN)));
        } catch (Exception e) {
            log.error("[IronWall] bootstrap route map failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(500, "握手失败，请稍后再试"));
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("session_id", session.sid());
        data.put("key", hex(session.key()));
        data.put("expires_at", session.createdAt() + apiCryptoService.getSessionTtlHours() * 3600_000L);
        data.put("route_map", routeMap);
        data.put("code_map", codeMap);
        data.put("ts", System.currentTimeMillis());
        log.info("[IronWall] api crypto session issued ip={} sid={}", ip, session.sid());
        return ResponseEntity.ok(ApiResponse.ok("ok", data));
    }

    /**
     * IronWall v1.42.0: 按携带的 JWT 确定地图层级。
     * 无效/过期令牌按匿名处理（JwtAuthenticationFilter 对无效令牌不拦截，此处仅读取角色）；
     * 校验失败绝不影响握手，只会得到更小的路由地图。
     */
    private int resolveTier(HttpServletRequest request) {
        try {
            String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7).trim();
                if (token.length() >= 16 && jwtTokenProvider.validateToken(token)
                        && !jwtTokenProvider.isTwoFactorToken(token)) {
                    String role = jwtTokenProvider.getRoleFromToken(token);
                    if ("admin".equalsIgnoreCase(role)) {
                        return ApiRouteTable.TIER_ADMIN;
                    }
                    return ApiRouteTable.TIER_USER;
                }
            }
        } catch (Exception e) {
            log.warn("[IronWall] bootstrap tier resolve failed: {}", e.getMessage());
        }
        return ApiRouteTable.TIER_ANON;
    }

    private boolean allow(String ip) {
        long now = System.currentTimeMillis();
        Window window = ipWindows.computeIfAbsent(ip, k -> new Window());
        synchronized (window) {
            if (now - window.resetAt >= 60_000L) {
                window.resetAt = now;
                window.count = 0;
            }
            if (window.count >= bootstrapMaxPerMinute) {
                return false;
            }
            window.count++;
            return true;
        }
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static class Window {
        long resetAt = System.currentTimeMillis();
        int count = 0;
    }
}
