package com.jdy.cloud.security;

import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.util.ClientIpUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, SlidingWindow> counters = new ConcurrentHashMap<>();
    private final Map<String, OverLimitState> overLimitStates = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RequestTrustResolver trustResolver;
    private final AttackGuardService attackGuardService;
    private final TrapService trapService;
    private final DdosDefenseService ddosDefenseService;

    public RateLimitFilter(RequestTrustResolver trustResolver, AttackGuardService attackGuardService,
                           TrapService trapService, DdosDefenseService ddosDefenseService) {
        this.trustResolver = trustResolver;
        this.attackGuardService = attackGuardService;
        this.trapService = trapService;
        this.ddosDefenseService = ddosDefenseService;
    }

    @Value("${app.security.rate-limit.enabled:true}")
    private boolean enabled;

    @Value("${app.security.rate-limit.requests-per-minute:60}")
    private int requestsPerMinute;

    @Value("${app.security.rate-limit.auth-requests-per-minute:10}")
    private int authRequestsPerMinute;

    // IronWall v1.21.2: 认证后接口专用额度（按用户分桶），不再用匿名额度 10 倍
    // IronWall v1.22.0: 默认收紧到 60 次/分，并叠加短窗突发上限，防批量爬取
    @Value("${app.security.rate-limit.authenticated-requests-per-minute:60}")
    private int authenticatedRequestsPerMinute;

    // IronWall v1.22.0: 登录态短窗突发上限（突发秒数内最多 N 次）
    @Value("${app.security.rate-limit.authenticated-burst:20}")
    private int authenticatedBurst;

    @Value("${app.security.rate-limit.authenticated-burst-seconds:10}")
    private int authenticatedBurstSeconds;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        if (!enabled) {
            chain.doFilter(request, response);
            return;
        }

        try {
        String clientIp = getClientIp(request);
        String path = request.getRequestURI();

        // IronWall v1.35.0: DDoS 观测层——全部流量先记录在案（秒级聚合），
        // 处置（记分/封禁/集群证据）在服务内按阈值+去重+周期配额执行，热路径零 I/O。
        RequestTrustResolver.Level trust = trustResolver.resolve(request, clientIp);
        boolean trustedSession = trust != RequestTrustResolver.Level.ANONYMOUS;
        boolean blockedNow = attackGuardService.isBlocked(clientIp) || attackGuardService.isBlockedSegment(clientIp);
        ddosDefenseService.observe(request, clientIp, trustedSession, blockedNow);

        // IronWall v1.17.4: 已封禁 IP 直接放行到封禁警示页过滤器，不再限流计数
        if (blockedNow) {
            chain.doFilter(request, response);
            return;
        }

        // IronWall v1.15: 信任分级。白名单 IP 完全放行；登录态阈值放宽 10 倍并按用户 ID 分桶，
        // 避免公网 NAT / 公司出口同一 IP 下正常用户互相挤占限流额度或被误伤。
        if (trust == RequestTrustResolver.Level.WHITELISTED) {
            chain.doFilter(request, response);
            return;
        }

        int limit = isAuthEndpoint(path) ? authRequestsPerMinute : requestsPerMinute;
        if (trustedSession) {
            limit = authenticatedRequestsPerMinute > 0 ? authenticatedRequestsPerMinute : 60;
        }
        // IronWall v1.28.4: 分片上传通道放宽额度（850MB=85 片，正常续传需要高并发请求数），
        // 且不参与短窗突发限制，避免大文件上传被 429 打断；未登录调用仍走通用额度。
        boolean chunkTransport = path.startsWith("/api/files/upload/chunk");
        if (chunkTransport && trustedSession) {
            limit = Math.max(limit, 600);
        }
        Long userId = trustResolver.userId(request);
        String key = (trustedSession && userId != null ? "u" + userId : clientIp) + ":" + path;

        SlidingWindow window = counters.computeIfAbsent(key, k -> new SlidingWindow());
        synchronized (window) {
            long now = System.currentTimeMillis();
            window.lastActivity = now;

            // IronWall v1.22.0: 真滑动窗口计数；登录态先查短窗突发，再查 60s 总窗
            boolean over = window.currentCount(now) >= limit;
            if (!over && trustedSession && !chunkTransport && authenticatedBurst > 0 && authenticatedBurstSeconds > 0) {
                over = window.countSince(now, authenticatedBurstSeconds * 1000L) >= authenticatedBurst;
            }

            if (over) {
                log.warn("Rate limit exceeded for IP: {} on path: {}", clientIp, path);
                // IronWall v1.26.1: 普通浏览器只返回 429；仅“明显自动化流量”在 5 分钟内累计 5 次超限才投入 L3 黑洞陷阱
                OverLimitState overState = overLimitStates.compute(clientIp, (k, old) -> {
                    long nowMs = System.currentTimeMillis();
                    if (old == null || nowMs - old.firstHitAt > 300_000L) {
                        return new OverLimitState();
                    }
                    old.hits++;
                    return old;
                });
                if (overState.hits >= 5 && !trustedSession && looksAutomated(request)) {
                    overLimitStates.remove(clientIp);
                    trapService.trap(clientIp, 3, "反复限流对抗(" + overState.hits + "次)", path, request.getHeader("User-Agent"), request.getMethod(), trustedSession);
                }
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setCharacterEncoding("UTF-8");
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write(objectMapper.writeValueAsString(
                        Map.of("code", ErrorCode.TOO_MANY_REQUESTS.getCode(),
                               "message", ErrorCode.TOO_MANY_REQUESTS.getMessage())
                ));
                return;
            }

            window.record(now);
        }

        chain.doFilter(request, response);
        } catch (Exception e) {
            // IronWall v1.10: limiter failure must never turn legitimate traffic into 500
            log.error("Rate limit check failed, fail-open: {}", e.getMessage());
            chain.doFilter(request, response);
        }
    }

    /**
     * 识别明显自动化流量：只有“无 UA / 爬虫 UA / 浏览器伪装且缺 Accept-Language”时才可升级陷阱；
     * 普通浏览器即使短时超过限流额度也只返回 429，不投入黑洞陷阱，避免弱网刷新误封。
     */
    private boolean looksAutomated(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        if (ua == null || ua.isBlank()) {
            return true;
        }
        if (AttackGuardService.isCrawlerUa(ua)) {
            return true;
        }
        String accept = request.getHeader("Accept");
        String lang = request.getHeader("Accept-Language");
        return ("*/*".equals(accept) || accept == null) && (lang == null || lang.isBlank());
    }

    private boolean isAuthEndpoint(String path) {
        return path.startsWith("/api/auth/login")
                || path.startsWith("/api/auth/register")
                || path.startsWith("/api/auth/send-code")
                || path.startsWith("/api/auth/reset-password")
                || path.startsWith("/api/auth/verify-email")
                || path.startsWith("/api/auth/check-email")
                // IronWall v1.20: 验证码校验与封禁状态探测同样纳入严格限流（防穷举/防状态探测）
                || path.startsWith("/api/auth/verify-code")
                // IronWall v1.28.1: 两步验证登录第二步同属认证敏感端点，严格限流防动态码穷举
                || path.startsWith("/api/auth/2fa")
                // IronWall v1.28.14: 封禁页仅人机验证提交与申诉保持严格桶；/status 是无副作用的
                // 探测接口，前端封禁守卫每 10 秒轮询一次，多标签页会误触严格桶导致间歇 429
                || path.startsWith("/api/blocked-page/verify")
                || path.startsWith("/api/blocked-page/appeal");
    }

    /** IronWall v1.6: 统一真实 IP 解析。可信代理（本机 nginx）取 X-Real-IP / XFF 末跳，直连忽略代理头。 */
    private String getClientIp(HttpServletRequest request) {
        return ClientIpUtils.getClientIp(request);
    }

    /**
     * IronWall v1.28.1: 周期性清理闲置计数窗口，防止攻击者以随机 IP×路径刷键导致内存无限增长。
     */
    @Scheduled(fixedDelay = 600_000L, initialDelay = 600_000L)
    public void cleanupIdleWindows() {
        long now = System.currentTimeMillis();
        counters.entrySet().removeIf(e -> {
            SlidingWindow w = e.getValue();
            synchronized (w) {
                return now - w.lastActivity > 600_000L && w.timestamps.isEmpty();
            }
        });
        overLimitStates.entrySet().removeIf(e -> now - e.getValue().firstHitAt > 600_000L);
    }
    private static final class OverLimitState {
        long firstHitAt = System.currentTimeMillis();
        int hits = 1;
    }

    /** IronWall v1.22.0: 真滑动窗口（60s 时间戳队列），替换整分钟重置的伪窗口 */
    private static class SlidingWindow {
        private final java.util.ArrayDeque<Long> timestamps = new java.util.ArrayDeque<>();
        volatile long lastActivity = System.currentTimeMillis();

        int currentCount(long now) {
            evictOld(now);
            return timestamps.size();
        }

        int countSince(long now, long windowMs) {
            evictOld(now);
            int n = 0;
            java.util.Iterator<Long> it = timestamps.descendingIterator();
            while (it.hasNext()) {
                if (now - it.next() <= windowMs) {
                    n++;
                } else {
                    break;
                }
            }
            return n;
        }

        void record(long now) {
            timestamps.addLast(now);
        }

        private void evictOld(long now) {
            while (!timestamps.isEmpty() && now - timestamps.peekFirst() > 60_000L) {
                timestamps.pollFirst();
            }
        }
    }
}
