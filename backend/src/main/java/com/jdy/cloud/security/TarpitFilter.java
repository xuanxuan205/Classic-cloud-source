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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Semaphore;

/**
 * IronWall v1.17 Tarpit 拖延消耗过滤器（合法威慑，非攻击）。
 *
 * 对已记分/已封禁的匿名攻击者与蜜罐路径的触碰者，把其请求拖慢一段可配置时间，
 * 让扫描器与爆破工具卡死在慢响应上、消耗其自身资源；并发量受信号量上限约束，
 * 超出立即 429，绝不影响正常用户线程池。白名单/登录态请求永不拖延。
 * 任何异常 fail-open。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 6)
public class TarpitFilter extends OncePerRequestFilter {

    /** IronWall v1.37.0: 单请求 tarpit 超时硬上限（防配置失误无限占线程）。 */
    private static final long HARD_MAX_DELAY_MS = 60_000L;

    private final AttackGuardService attackGuardService;
    private final RequestTrustResolver trustResolver;
    private final SystemHealthProbe healthProbe;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Semaphore semaphore;

    @Value("${app.security.defense-engine.enabled:true}")
    private boolean defenseEngineEnabled;

    @Value("${app.security.defense-engine.tarpit.enabled:true}")
    private boolean tarpitEnabled;

    @Value("${app.security.defense-engine.tarpit.delay-ms:15000}")
    private long delayMs;

    @Value("${app.security.defense-engine.tarpit.max-delay-ms:30000}")
    private long maxDelayMs;

    @Value("${app.security.defense-engine.tarpit.max-concurrent:8}")
    private int maxConcurrent;

    public TarpitFilter(AttackGuardService attackGuardService, RequestTrustResolver trustResolver,
                        SystemHealthProbe healthProbe,
                        @Value("${app.security.defense-engine.tarpit.max-concurrent:8}") int maxConcurrent) {
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
        this.healthProbe = healthProbe;
        this.semaphore = new Semaphore(Math.max(1, maxConcurrent));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!defenseEngineEnabled || !tarpitEnabled || !attackGuardService.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        try {
            String method = request.getMethod();
            String path = request.getRequestURI();
            if ("OPTIONS".equalsIgnoreCase(method) || isStaticAsset(path)) {
                chain.doFilter(request, response);
                return;
            }

            String ip = ClientIpUtils.getClientIp(request);
            RequestTrustResolver.Level trust = trustResolver.resolve(request, ip);
            if (trust != RequestTrustResolver.Level.ANONYMOUS) {
                chain.doFilter(request, response);
                return;
            }

            boolean honeypotPath = HoneypotPaths.isHoneypot(path);
            boolean downloadPath = path != null && path.startsWith("/api/shares/download");
            if (!honeypotPath && !attackGuardService.shouldTarpit(ip)) {
                chain.doFilter(request, response);
                return;
            }

            // IronWall v1.47.2: 下载分级限速——真封禁才 429（Retry-After 与剩余封禁时长一致），
            // 仅记分未封禁（共享 IP 误伤面）短延迟后放行，由 ShareDownloadLimiter 继续兜底。
            if (downloadPath) {
                long remaining = attackGuardService.blockRemainingSeconds(ip);
                if (remaining > 0) {
                    respondRateLimited(response, remaining);
                    return;
                }
                long shortDelay = Math.min(effectiveDelayMs(delayMs, maxDelayMs), 5_000L);
                if (!semaphore.tryAcquire()) {
                    respondBusy(response);
                    return;
                }
                try {
                    Thread.sleep(shortDelay);
                    chain.doFilter(request, response);
                } finally {
                    semaphore.release();
                }
                return;
            }

            // IronWall v1.37.0: CPU/堆水位熔断——高压时立即 429，绝不继续占线程睡眠
            if (healthProbe.isUnderPressure()) {
                respondRateLimited(response, Math.max(1L, delayMs / 1000L));
                return;
            }

            if (!semaphore.tryAcquire()) {
                respondBusy(response);
                return;
            }
            try {
                long delay = effectiveDelayMs(delayMs, maxDelayMs);
                Thread.sleep(delay);
                if (honeypotPath && response.isCommitted()) {
                    return;
                }
                chain.doFilter(request, response);
            } finally {
                semaphore.release();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            chain.doFilter(request, response);
        } catch (Exception e) {
            log.error("[IronWall] tarpit failed, fail-open: {}", e.getMessage());
            chain.doFilter(request, response);
        }
    }

    private boolean isStaticAsset(String path) {
        return path != null && path.matches(".*\\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map|txt)$");
    }

    /** IronWall v1.37.0: min(配置延迟, 配置上限, 60 秒硬上限)，下限 1ms。 */
    static long effectiveDelayMs(long delayMs, long maxDelayMs) {
        return Math.min(Math.max(1, delayMs),
                Math.min(Math.max(1, maxDelayMs), HARD_MAX_DELAY_MS));
    }

    /** IronWall v1.47.2: 429 + 与真实冷却时长一致的 Retry-After（上限 1 小时），无静默排队。 */
    private void respondRateLimited(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        long retryAfter = Math.max(1L, Math.min(retryAfterSeconds, 3600L));
        String message = retryAfter >= 60
                ? "访问频率过高，请约" + ((retryAfter + 59) / 60) + "分钟后再试"
                : "访问频率过高，请稍后重试";
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false, "code", 429,
                        "message", message,
                        "engine", AttackGuardService.ENGINE_NAME)));
    }

    private void respondBusy(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false, "code", 429,
                        "message", "\u670d\u52a1\u5668\u7e41\u5fd9\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5",
                        "engine", AttackGuardService.ENGINE_NAME)));
    }
}
