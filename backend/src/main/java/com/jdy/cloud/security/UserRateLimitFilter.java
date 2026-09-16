package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * IronWall v1.44.0: 认证用户级 API 限速（防令牌泄露批量拉取）。
 *
 * 定位：IP 维限速可被代理池绕过；令牌一旦泄露，攻击者可多 IP 并发拉取用户数据。
 * 本过滤器对「已认证请求」按 userId 做滑动窗口限速，换 IP 无效（挂靠账号而非来源）。
 *
 * 零误伤设计：
 * 默认 60s / 1800 次（约 30r/s），高于 nginx 20r/s 的 IP 维限速，正常界面零感知；
 * 管理员豁免；/api/blocked-page 系列豁免（封禁页轮询不受限）；
 * 超限仅返回 429 + Retry-After，不联动攻击计分、不封禁、不写攻击日志；
 * 未认证请求（登录/注册/分享公开页）不参与，由现有 IP 维限速负责。
 */
@Slf4j
@Component
public class UserRateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 60_000L;

    @Value("${app.security.user-rate-limit.enabled:true}")
    private boolean enabled;

    @Value("${app.security.user-rate-limit.max-requests-per-minute:1800}")
    private int maxPerMinute;

    @Value("${app.security.user-rate-limit.retry-after-seconds:30}")
    private int retryAfterSeconds;

    private final Map<Long, Window> windows = new ConcurrentHashMap<>();
    private final AtomicLong limitedTotal = new AtomicLong();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!enabled) {
            chain.doFilter(request, response);
            return;
        }
        String uri = request.getRequestURI();
        if (uri == null || !uri.startsWith("/api/") || uri.startsWith("/api/blocked-page")) {
            chain.doFilter(request, response);
            return;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof UserPrincipal principal)) {
            chain.doFilter(request, response);
            return;
        }
        if (principal.isAdmin()) {
            chain.doFilter(request, response);
            return;
        }
        Long userId = principal.getUserId();
        if (userId == null) {
            chain.doFilter(request, response);
            return;
        }
        long now = System.currentTimeMillis();
        Window w = windows.computeIfAbsent(userId, k -> new Window(now));
        synchronized (w) {
            if (now - w.windowStart >= WINDOW_MS) {
                w.windowStart = now;
                w.count = 0;
            }
            w.count++;
            if (w.count > maxPerMinute) {
                limitedTotal.incrementAndGet();
                writeLimited(response);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private void writeLimited(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Retry-After", String.valueOf(Math.max(1, retryAfterSeconds)));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 429);
        body.put("message", "请求过于频繁，请稍后再试");
        body.put("retry_after", Math.max(1, retryAfterSeconds));
        body.put("success", false);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }

    /** 面板统计：当前被限速的账号数与累计超限次数。 */
    public Map<String, Object> stats() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", enabled);
        out.put("max_requests_per_minute", maxPerMinute);
        out.put("active_windows", windows.size());
        out.put("limited_total", limitedTotal.get());
        return out;
    }

    /** 惰性回收过期窗口，防止长在线账号堆积累计窗口。 */
    @Scheduled(fixedDelay = 10 * 60_000L)
    public void cleanup() {
        long now = System.currentTimeMillis();
        windows.entrySet().removeIf(e -> {
            Window w = e.getValue();
            synchronized (w) {
                return now - w.windowStart >= WINDOW_MS;
            }
        });
    }

    private static final class Window {
        volatile long windowStart;
        long count;

        Window(long start) {
            this.windowStart = start;
        }
    }
}
