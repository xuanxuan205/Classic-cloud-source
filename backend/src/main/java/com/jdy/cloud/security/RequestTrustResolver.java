package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * IronWall v1.15: unified trust-level resolution shared by all rate/block filters.
 *
 * Round-15 finding: the same strict IP bucket was applied to normal logged-in users and
 * admins, so a few routine operations (or a NAT exit shared with an attacker) hard-blocked
 * the whole IP - admins even locked themselves out of their own console.
 *
 * Levels:
 * WHITELISTED - configured admin/ops IPs, full bypass of rate limits and IP blocks
 * ADMIN - request carries a valid JWT with role=admin, never hard-blocked
 * AUTHENTICATED - request carries a valid JWT, gets relaxed (10x) limits and never 4441
 * ANONYMOUS - strict limits and IP scoring/blocking as before
 */
@Component
public class RequestTrustResolver {

    public enum Level { ANONYMOUS, AUTHENTICATED, ADMIN, WHITELISTED }

    private final JwtTokenProvider jwtTokenProvider;
    private volatile Set<String> whitelist = Collections.emptySet();

    public RequestTrustResolver(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Value("${app.security.admin-ip-whitelist:}")
    public void setAdminIpWhitelist(String csv) {
        if (csv == null || csv.isBlank()) {
            this.whitelist = Collections.emptySet();
            return;
        }
        this.whitelist = Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    public boolean isWhitelisted(String ip) {
        if (ip == null) {
            return false;
        }
        // IronWall v1.38.1: 服务器自身健康检查（nginx 回环/本机 curl）永不记分，避免自封。
        if (isLoopback(ip)) {
            return true;
        }
        return whitelist.contains(ip);
    }

    private boolean isLoopback(String ip) {
        return "127.0.0.1".equals(ip) || ip.startsWith("127.") || "::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip);
    }

    public Level resolve(HttpServletRequest request, String clientIp) {
        if (isWhitelisted(clientIp)) {
            return Level.WHITELISTED;
        }
        String token = bearerToken(request);
        if (token != null) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    String role = jwtTokenProvider.getRoleFromToken(token);
                    return "admin".equalsIgnoreCase(role) ? Level.ADMIN : Level.AUTHENTICATED;
                }
            } catch (Exception ignored) {
                // invalid/expired token -> anonymous
            }
        }
        return Level.ANONYMOUS;
    }

    public Long userId(HttpServletRequest request) {
        String token = bearerToken(request);
        if (token == null) {
            return null;
        }
        try {
            if (jwtTokenProvider.validateToken(token)) {
                return jwtTokenProvider.getUserIdFromToken(token);
            }
        } catch (Exception ignored) {
            // fall through
        }
        return null;
    }

    private String bearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }
}
