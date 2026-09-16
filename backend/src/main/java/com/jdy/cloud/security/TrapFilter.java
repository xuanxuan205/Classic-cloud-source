package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * IronWall v1.21 五层黑洞陷阱过滤器。
 *
 * 已入陷阱的 IP：除封禁警示页（让攻击者看到警告）外的所有请求一律吞没——
 * 延时 + 429 + 无任何业务数据，只有入口没有出口，直到陷阱期满自动释放。
 * 白名单/登录态豁免；陷阱响应并发有上限，异常一律 fail-open。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class TrapFilter extends OncePerRequestFilter {

    private final TrapService trapService;
    private final AttackGuardService attackGuardService;
    private final RequestTrustResolver trustResolver;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AtomicInteger activeTraps = new AtomicInteger();

    @Value("${app.security.defense-engine.trap.delay-ms:1500}")
    private long trapDelayMs;

    @Value("${app.security.defense-engine.trap.max-concurrent:16}")
    private int maxConcurrent;

    public TrapFilter(TrapService trapService, AttackGuardService attackGuardService,
                      RequestTrustResolver trustResolver) {
        this.trapService = trapService;
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!trapService.isEnabled() || !attackGuardService.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        try {
            String ip = ClientIpUtils.getClientIp(request);
            String path = request.getRequestURI();
            if (path == null || !trapService.isTrapped(ip)) {
                chain.doFilter(request, response);
                return;
            }
            RequestTrustResolver.Level trust = trustResolver.resolve(request, ip);
            if (trust == RequestTrustResolver.Level.WHITELISTED
                    || trust == RequestTrustResolver.Level.AUTHENTICATED) {
                chain.doFilter(request, response);
                return;
            }
            if (BlockedIpPageFilter.BLOCKED_PAGE_PATH.equals(path)) {
                chain.doFilter(request, response);
                return;
            }
            // IronWall v1.25.0: 陷阱区人机验证逃生口（仅 POST 验证端点放行）
            if (BlockedIpPageFilter.VERIFY_PATH.equals(path) && "POST".equalsIgnoreCase(request.getMethod())) {
                chain.doFilter(request, response);
                return;
            }
            // IronWall v1.21.2: 公开头像为纯静态资源，陷阱期放行，避免正常浏览被吞
            if ("GET".equalsIgnoreCase(request.getMethod()) && path.startsWith("/api/files/avatar/")) {
                chain.doFilter(request, response);
                return;
            }
            // 陷阱延时消耗攻击者资源；超过并发上限则直接吞没，绝不放行
            int active = activeTraps.incrementAndGet();
            try {
                if (active <= Math.max(1, maxConcurrent) && trapDelayMs > 0 && trapDelayMs <= 5000) {
                    Thread.sleep(trapDelayMs);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                activeTraps.decrementAndGet();
            }
            response.setStatus(429);
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Retry-After", "300");
            response.setHeader(TrapService.TRAP_HEADER, "true");
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false,
                    "code", 429,
                    "trapped", true,
                    "message", "该来源已进入经典云网盘铁壁安全引擎陷阱区：只进不出，所有访问均被吞没，请停止攻击行为",
                    "engine", AttackGuardService.ENGINE_NAME)));
        } catch (Exception e) {
            log.error("[IronWall] trap filter failed, fail-open: {}", e.getMessage());
            chain.doFilter(request, response);
        }
    }
}
