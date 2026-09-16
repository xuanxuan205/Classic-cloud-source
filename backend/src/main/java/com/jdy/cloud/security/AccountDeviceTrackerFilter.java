package com.jdy.cloud.security;

import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * IronWall v1.45.0: 账号级指纹追踪过滤器（JWT 认证之后）。
 *
 * 对已认证的 /api/ 请求聚合 userId -> {设备指纹, TLS 画像, IP} 的多维信号，
 * 供 AccountDeviceTracker 统计。观察模式：绝不拦截、绝不抛异常、不写库、不联动封禁。
 */
@Slf4j
@Component
public class AccountDeviceTrackerFilter extends OncePerRequestFilter {

    private final AccountDeviceTracker tracker;
    private final DeviceIdentityResolver deviceIdentityResolver;
    private final TlsProfileResolver tlsProfileResolver;

    public AccountDeviceTrackerFilter(AccountDeviceTracker tracker,
                                      DeviceIdentityResolver deviceIdentityResolver,
                                      TlsProfileResolver tlsProfileResolver) {
        this.tracker = tracker;
        this.deviceIdentityResolver = deviceIdentityResolver;
        this.tlsProfileResolver = tlsProfileResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            String uri = request.getRequestURI();
            if (uri != null && uri.startsWith("/api/") && !uri.startsWith("/api/blocked-page")) {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
                    DeviceIdentityResolver.Identity identity = deviceIdentityResolver.resolve(request);
                    tracker.observe(
                            principal.getUserId(),
                            principal.getUsername(),
                            identity.fingerprint(),
                            tlsProfileResolver.resolve(request),
                            ClientIpUtils.getClientIp(request));
                }
            }
        } catch (Exception e) {
            log.debug("[IronWall] account device tracking skipped: {}", e.getMessage());
        }
        chain.doFilter(request, response);
    }
}