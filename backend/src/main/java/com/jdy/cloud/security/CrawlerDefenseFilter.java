package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.21 银行级爬虫防御过滤器（L2 挑战签名化 + 黑洞陷阱联动）。
 *
 * 1) 可疑自动化 UA 逐请求记分 + 单 IP 每分钟次数上限；
 * 2) 行为指纹：浏览器 UA 伪装 + 脚本化请求头组合 / 高频节拍记分；
 * 3) JS 挑战链（HMAC 签名化，伪造即入陷阱）：
 * /api/crawler-challenge 下发一次性 nonce；/api/crawler-verify 校验后
 * 种下 iw_ok = exp.hmac(ip|exp) 签名 cookie——明文 iw_ok=1 已不可伪造；
 * 4) 单 IP 对全部 /api/ 的高频访问记分并返回 429；
 * 5) 记分达到阈值后由 AttackGuardService 统一升级封禁。
 *
 * 设计原则：真实浏览器永远无感（前端静默完成挑战），任何异常 fail-open。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class CrawlerDefenseFilter extends OncePerRequestFilter {

    public static final String CHALLENGE_PATH = "/api/crawler-challenge";
    public static final String VERIFY_PATH = "/api/crawler-verify";
    public static final String CHALLENGE_HEADER = "X-IronWall-Challenge";
    public static final String JS_OK_COOKIE = "iw_ok";
    public static final String JS_NONCE_COOKIE = "iw_n";

    private static final long CHALLENGE_TTL_MS = 5 * 60_000L;
    private static final long JS_OK_MAX_AGE_SECONDS = 7 * 24 * 3600L;
    private static final int FINGERPRINT_CHALLENGE_HITS = 2;
    private static final int BURST_HITS_THRESHOLD = 8;

    // IronWall v1.25.0: 并发/批量上传属正常业务节拍，不参与 IP 级高频记分（仍受速率限流约束）
    private boolean isUploadRequest(HttpServletRequest request) {
        if (request == null) return false;
        if (!"POST".equalsIgnoreCase(request.getMethod()) && !"PUT".equalsIgnoreCase(request.getMethod())) return false;
        String ct = request.getContentType();
        boolean multipart = ct != null && ct.toLowerCase().startsWith("multipart/form-data");
        String path = request.getRequestURI();
        return multipart && path != null && (path.endsWith("/upload") || path.contains("/upload/"));
    }
    private static final long BURST_INTERVAL_MS = 30L;

    private final AttackGuardService attackGuardService;
    private final TrapService trapService;
    private final RequestTrustResolver trustResolver;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Map<String, Window> crawlerUaWindows = new ConcurrentHashMap<>();
    private final Map<String, Long> burstScoredAt = new ConcurrentHashMap<>();
    private final Map<String, FingerprintState> fingerprintStates = new ConcurrentHashMap<>();
    private final Map<String, PendingChallenge> pendingChallenges = new ConcurrentHashMap<>();

    @Value("${app.security.crawler-guard.enabled:true}")
    private boolean enabled;

    @Value("${app.security.crawler-guard.max-api-rpm:300}")
    private int maxApiRpm;

    @Value("${app.security.crawler-guard.max-crawler-rpm:10}")
    private int maxCrawlerRpm;

    @Value("${app.security.crawler-guard.burst-score-interval-ms:5000}")
    private long burstScoreIntervalMs;

    @Value("${app.security.crawler-guard.behavior-fingerprint.enabled:true}")
    private boolean fingerprintEnabled;

    @Value("${app.security.crawler-guard.challenge.enabled:true}")
    private boolean challengeEnabled;

    @Value("${app.security.crawler-guard.require-js-proof-for-sensitive:true}")
    private boolean requireJsProofForSensitive;

    @Value("${app.security.crawler-guard.pow-difficulty:4}")
    private int powDifficulty;

    // IronWall v1.28.13: PoW 动态难度——按 IP 信誉分上调（新 IP 基线、可疑 IP 提高、封顶保护体验）。
    @Value("${app.security.crawler-guard.pow-difficulty-max:6}")
    private int powDifficultyMax;

    @Value("${app.security.crawler-guard.pow-reputation-threshold:10}")
    private int powReputationThreshold;

    @Value("${app.security.crawler-guard.pow-reputation-boost:2}")
    private int powReputationBoost;

    @Value("${app.jwt.secret}")
    private String challengeSecret;

    public CrawlerDefenseFilter(AttackGuardService attackGuardService, RequestTrustResolver trustResolver,
                                TrapService trapService) {
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
        this.trapService = trapService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        if (!enabled || !attackGuardService.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        try {
            String ip = ClientIpUtils.getClientIp(request);
            String path = request.getRequestURI();
            String method = request.getMethod();
            String userAgent = request.getHeader("User-Agent");

            if ("OPTIONS".equalsIgnoreCase(method) || isStaticAsset(path)) {
                chain.doFilter(request, response);
                return;
            }

            if (CHALLENGE_PATH.equals(path) && challengeEnabled) {
                handleChallenge(response, ip);
                return;
            }
            if (VERIFY_PATH.equals(path) && challengeEnabled) {
                handleVerify(request, response, ip);
                return;
            }

            RequestTrustResolver.Level trust = trustResolver.resolve(request, ip);
            if (trust == RequestTrustResolver.Level.WHITELISTED) {
                chain.doFilter(request, response);
                return;
            }
            boolean trustedSession = trust != RequestTrustResolver.Level.ANONYMOUS;
            int apiLimit = trustedSession ? maxApiRpm * 10 : maxApiRpm;
            int crawlerLimit = trustedSession ? maxCrawlerRpm * 10 : maxCrawlerRpm;

            if ((attackGuardService.isBlocked(ip) || attackGuardService.isBlockedSegment(ip)) && !trustedSession) {
                respondCrawlerBlocked(response, ip);
                return;
            }

            // IronWall v1.21 L2: iw_ok 签名校验。0=无 1=有效 2=伪造；
            // v1.21.1 修复：首犯只记分并重新挑战（旧版明文 Cookie 升级残留由前端静默换发），
            // 反复伪造且记分升级为 BLOCKED 时才投入 L2 黑洞陷阱，避免误锁真实用户。
            int jsProof = jsProofState(request);
            if (jsProof == 2 && !trustedSession) {
                AttackGuardService.AttackRecord forged = attackGuardService.recordAttack(
                        ip, AttackGuardService.TYPE_CRAWLER, "挑战cookie伪造", path, userAgent, method, false);
                if (forged != null && "BLOCKED".equals(forged.action)) {
                    trapService.trap(ip, 2, "反复挑战cookie伪造", path, userAgent, method, false);
                }
                respondChallenge(response);
                return;
            }
            boolean hasJsProof = jsProof == 1;

            // IronWall v1.28.9: 高危写接口在 API 层强制 JS 证明（PoW 不再是前端表演）。
            // 前端启动时已静默完成挑战并持有 HMAC 签名 iw_ok，真实浏览器无感；
            // 匿名脚本不带 iw_ok 直接调登录/注册/上传等接口一律返回 429 挑战。
            if (challengeEnabled && requireJsProofForSensitive && !hasJsProof && !trustedSession
                    && isSensitiveMutation(request)) {
                respondChallenge(response);
                return;
            }

            // 1) 可疑自动化客户端
            if (AttackGuardService.isCrawlerUa(userAgent)) {
                Window uaWindow = crawlerUaWindows.computeIfAbsent(ip, k -> new Window());
                boolean uaBurst;
                long uaCount;
                synchronized (uaWindow) {
                    long now = System.currentTimeMillis();
                    if (now - uaWindow.windowStart > 60_000L) {
                        uaWindow.windowStart = now;
                        uaWindow.count = 0;
                    }
                    uaWindow.count++;
                    uaCount = uaWindow.count;
                    uaBurst = uaCount > crawlerLimit;
                }
                AttackGuardService.AttackRecord record = attackGuardService.recordAttack(
                        ip, AttackGuardService.TYPE_CRAWLER,
                        "自动化客户端访问: " + truncate(userAgent), path, userAgent, method, trustedSession || isUploadRequest(request));
                log.warn("[IronWall] crawler UA detected: ip={} ua={} score={} action={}", ip, truncate(userAgent), record != null ? record.score : 0, record != null ? record.action : "UNKNOWN");
                if (record != null && "BLOCKED".equals(record.action)) {
                    respondCrawlerBlocked(response, ip);
                    return;
                }
                if (uaBurst) {
                    if (!trustedSession) {
                        long nowMs = System.currentTimeMillis();
                        Long lastBurstScore = burstScoredAt.get(ip);
                        if (lastBurstScore == null || nowMs - lastBurstScore >= Math.max(1000, burstScoreIntervalMs)) {
                            burstScoredAt.put(ip, nowMs);
                            AttackGuardService.AttackRecord burst = attackGuardService.recordAttack(
                                    ip, AttackGuardService.TYPE_CRAWLER,
                                    "自动化客户端高频超限: " + uaCount + "次/分钟", path, userAgent, method, false);
                            if (burst != null && "BLOCKED".equals(burst.action)) {
                                respondCrawlerBlocked(response, ip);
                                return;
                            }
                        }
                    }
                    respondCrawlerBlocked(response, ip);
                    return;
                }
                chain.doFilter(request, response);
                return;
            }

            // 2) 行为指纹（仅匿名、未通过挑战）
            if (fingerprintEnabled && !trustedSession && !hasJsProof && !isUploadRequest(request)) {
                boolean scriptedHeaders = isBrowserUa(userAgent)
                        && ("*/*".equals(request.getHeader("Accept"))
                            || request.getHeader("Accept") == null)
                        && request.getHeader("Accept-Language") == null;
                FingerprintState fp = fingerprintStates.computeIfAbsent(ip, k -> new FingerprintState());
                long now = System.currentTimeMillis();
                synchronized (fp) {
                    if (now - fp.windowStart > 30_000L) {
                        fp.windowStart = now;
                        fp.hits = 0;
                    }
                    if (scriptedHeaders) {
                        fp.hits++;
                        AttackGuardService.AttackRecord rec = attackGuardService.recordAttack(
                                ip, AttackGuardService.TYPE_CRAWLER,
                                "浏览器UA伪装+脚本化请求头: Accept=" + truncate(request.getHeader("Accept"))
                                        + " 无Accept-Language", path, userAgent, method, false);
                        log.warn("[IronWall] browser-UA-mimic fingerprint: ip={} hits={} score={}", ip, fp.hits, rec != null ? rec.score : 0);
                    }
                    if (fp.lastRequestAt > 0 && now - fp.lastRequestAt < BURST_INTERVAL_MS) {
                        fp.burstCount++;
                        if (fp.burstCount >= BURST_HITS_THRESHOLD) {
                            fp.burstCount = 0;
                            attackGuardService.recordAttack(
                                    ip, AttackGuardService.TYPE_CRAWLER,
                                    "高频节拍请求: 连续" + BURST_HITS_THRESHOLD + "次间隔<" + BURST_INTERVAL_MS + "ms",
                                    path, userAgent, method, false);
                        }
                    } else {
                        fp.burstCount = 0;
                    }
                    fp.lastRequestAt = now;
                    if (fp.hits >= FINGERPRINT_CHALLENGE_HITS) {
                        respondChallenge(response);
                        return;
                    }
                }
            }

            // 3) 高频访问检测
            Window window = windows.computeIfAbsent(ip, k -> new Window());
            boolean overLimit;
            long count;
            synchronized (window) {
                long now = System.currentTimeMillis();
                if (now - window.windowStart > 60_000L) {
                    window.windowStart = now;
                    window.count = 0;
                }
                window.count++;
                count = window.count;
                overLimit = count > apiLimit;
            }
            if (overLimit) {
                AttackGuardService.AttackRecord record = attackGuardService.recordAttack(
                        ip, AttackGuardService.TYPE_CRAWLER,
                        "高频API访问: " + count + "次/分钟", path, userAgent, method, trustedSession);
                log.warn("[IronWall] high-frequency API access: ip={} count={} trusted={} action={}", ip, count, trustedSession, record != null ? record.action : "UNKNOWN");
                respondCrawlerBlocked(response, ip);
                return;
            }

            cleanupWindowsIfNeeded();
            chain.doFilter(request, response);
        } catch (Exception e) {
            log.error("[IronWall] crawler defense failed, fail-open: {}", e.getMessage());
            chain.doFilter(request, response);
        }
    }

    /** 挑战入口：下发一次性 nonce（Cookie iw_n + 响应体）。 */
    private void handleChallenge(HttpServletResponse response, String ip) throws IOException {
        String nonce = randomHex(32);
        int effectiveMax = powDifficultyMax > 0 ? powDifficultyMax : 6;
        int difficulty = Math.max(0, Math.min(effectiveMax, powDifficulty));
        if (powReputationBoost > 0
                && powReputationThreshold > 0
                && attackGuardService.scoreOf(ip) >= powReputationThreshold) {
            difficulty = Math.min(effectiveMax, difficulty + powReputationBoost);
        }
        pendingChallenges.put(ip, new PendingChallenge(nonce, System.currentTimeMillis() + CHALLENGE_TTL_MS, difficulty));
        response.setStatus(HttpStatus.OK.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        setCookie(response, JS_NONCE_COOKIE, nonce, 600L, false);
        response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                "success", true, "nonce", nonce, "difficulty", difficulty,
                "verify", VERIFY_PATH + "?n=" + nonce)));
    }

    /** 校验 nonce：Cookie iw_n 与请求参数 n 双匹配且未过期 -> 种下签名 iw_ok。失败即挑战对抗入陷阱。 */
    private void handleVerify(HttpServletRequest request, HttpServletResponse response, String ip) throws IOException {
        String nonceParam = request.getParameter("n");
        String solution = request.getParameter("s");
        String cookieNonce = cookieValue(request, JS_NONCE_COOKIE);
        PendingChallenge pending = pendingChallenges.get(ip);
        boolean nonceOk = pending != null
                && pending.expiresAt > System.currentTimeMillis()
                && pending.nonce != null && pending.nonce.equals(nonceParam)
                && pending.nonce.equals(cookieNonce);
        boolean ok = nonceOk && (pending == null || pending.difficulty <= 0
                || (solution != null && validPow(pending.nonce, solution, pending.difficulty)));
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        if (!ok) {
            // IronWall v1.21.1: nonce 错配/过期/PoW 无效首犯记分 + 400，记分升级 BLOCKED 才入陷阱
            AttackGuardService.AttackRecord nonceForged = attackGuardService.recordAttack(ip, AttackGuardService.TYPE_CRAWLER,
                    "挑战伪造: nonce错配或PoW无效", request.getRequestURI(), request.getHeader("User-Agent"), request.getMethod(), false);
            if (nonceForged != null && "BLOCKED".equals(nonceForged.action)) {
                trapService.trap(ip, 2, "反复挑战nonce/PoW伪造", request.getRequestURI(), request.getHeader("User-Agent"), request.getMethod(), false);
            }
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false, "message", "challenge failed")));
            return;
        }
        pendingChallenges.remove(ip);
        setCookie(response, JS_OK_COOKIE, signOkCookie(ip), JS_OK_MAX_AGE_SECONDS, true);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(objectMapper.writeValueAsString(Map.of("success", true)));
    }

    private boolean validPow(String nonce, String solution, int difficulty) {
        if (nonce == null || solution == null || difficulty <= 0) return false;
        String prefix = "0".repeat(difficulty);
        return sha256Hex(nonce + "|" + solution).startsWith(prefix);
    }

    private String sha256Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("sha256 failure", e);
        }
    }

    private void respondChallenge(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader(CHALLENGE_HEADER, "true");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false,
                       "code", 429,
                       "message", "请完成浏览器验证后重试",
                       "challenge", CHALLENGE_PATH,
                       "engine", AttackGuardService.ENGINE_NAME)
        ));
    }

    private void setCookie(HttpServletResponse response, String name, String value, long maxAgeSeconds, boolean httpOnly) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append('=').append(value)
          .append("; Path=/; Max-Age=").append(maxAgeSeconds)
          .append("; SameSite=Lax");
        if (httpOnly) sb.append("; HttpOnly");
        response.addHeader("Set-Cookie", sb.toString());
    }

    /** IronWall v1.21 L2: iw_ok 必须通过 HMAC 签名校验（0 无 / 1 有效 / 2 伪造）。 */
    private int jsProofState(HttpServletRequest request) {
        String value = cookieValue(request, JS_OK_COOKIE);
        if (value == null) return 0;
        return isValidOkCookie(request, value) ? 1 : 2;
    }

    /** IronWall v1.40.0: 供 /api/bootstrap 使用的挑战证明校验（仅返回通过/不通过，不泄露伪造状态）。 */
    public boolean hasValidChallengeProof(HttpServletRequest request) {
        try {
            return jsProofState(request) == 1;
        } catch (Exception e) {
            return false;
        }
    }

    /** IronWall v1.40.0: 爬虫挑战开关状态（关闭时 /api/bootstrap 不再要求挑战证明）。 */
    public boolean isChallengeEnabled() {
        return challengeEnabled;
    }

    /** iw_ok = expSeconds.hmacHex(ip|exp)。明文 iw_ok=1 已不可伪造。 */
    private String signOkCookie(String ip) {
        long exp = System.currentTimeMillis() / 1000L + JS_OK_MAX_AGE_SECONDS;
        return exp + "." + hmacHex(ip + "|" + exp);
    }

    private boolean isValidOkCookie(HttpServletRequest request, String value) {
        try {
            int dot = value.indexOf('.');
            if (dot <= 0 || dot >= value.length() - 1) return false;
            long exp = Long.parseLong(value.substring(0, dot));
            if (exp < System.currentTimeMillis() / 1000L) return false;
            String expected = hmacHex(ClientIpUtils.getClientIp(request) + "|" + exp);
            return MessageDigest.isEqual(
                    value.substring(dot + 1).getBytes(StandardCharsets.UTF_8),
                    expected.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // IronWall v1.47.7: fail-closed，绝不回退固定密钥
            if (challengeSecret == null || challengeSecret.isBlank()) {
                throw new IllegalStateException("[IronWall] crawler challenge secret unavailable");
            }
            String key = challengeSecret;
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("hmac failure", e);
        }
    }

    private String cookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private boolean isBrowserUa(String userAgent) {
        if (userAgent == null) return false;
        String ua = userAgent.toLowerCase();
        return ua.contains("mozilla") && (ua.contains("chrome") || ua.contains("safari")
                || ua.contains("firefox") || ua.contains("edg"));
    }

    /** IronWall v1.28.9: 登录/注册/上传/分享创建/反馈等高危写接口。 */
    private boolean isSensitiveMutation(HttpServletRequest request) {
        if (request == null) return false;
        String method = request.getMethod();
        if (!"POST".equalsIgnoreCase(method) && !"PUT".equalsIgnoreCase(method)) return false;
        String path = request.getRequestURI();
        if (path == null) return false;
        if (path.startsWith("/api/files/upload/chunk")) {
            // XHR 分片通道：入口 /upload/check 已强制 JS 证明，分片本身豁免避免无重试机制中断大文件上传
            return false;
        }
        return path.startsWith("/api/auth/login")
                || path.startsWith("/api/auth/register")
                || path.startsWith("/api/auth/verify-code")
                || path.startsWith("/api/auth/send-code")
                || path.startsWith("/api/auth/reset-password")
                || path.startsWith("/api/auth/change-password")
                || path.startsWith("/api/files/upload")
                || path.startsWith("/api/shares/create")
                || path.startsWith("/api/feedback");
    }

    private String randomHex(int length) {
        byte[] bytes = new byte[length / 2];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(length);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean isStaticAsset(String path) {
        return path != null && path.matches(".*\\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map|txt)$");
    }

    private String truncate(String value) {
        if (value == null) return "";
        return value.length() > 200 ? value.substring(0, 200) : value;
    }

    private void respondCrawlerBlocked(HttpServletResponse response, String ip) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false,
                       "code", 429,
                       "message", "检测到自动化爬虫访问，请稍后再试",
                       "engine", AttackGuardService.ENGINE_NAME,
                       "ip", ip)
        ));
    }

    private void cleanupWindowsIfNeeded() {
        if (windows.size() <= 10_000 && burstScoredAt.size() <= 10_000
                && fingerprintStates.size() <= 10_000 && pendingChallenges.size() <= 10_000) return;
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Window> entry = it.next();
            synchronized (entry.getValue()) {
                if (now - entry.getValue().windowStart > 300_000L) {
                    it.remove();
                }
            }
        }
        if (burstScoredAt.size() > 10_000) {
            burstScoredAt.entrySet().removeIf(e -> now - e.getValue() > 300_000L);
        }
        fingerprintStates.entrySet().removeIf(e -> now - e.getValue().windowStart > 600_000L);
        pendingChallenges.entrySet().removeIf(e -> now > e.getValue().expiresAt);
    }

    private static class Window {
        long windowStart = System.currentTimeMillis();
        long count = 0;
    }

    private static final class FingerprintState {
        long windowStart = System.currentTimeMillis();
        int hits = 0;
        long lastRequestAt = 0;
        int burstCount = 0;
    }

    private static final class PendingChallenge {
        final String nonce;
        final long expiresAt;
        final int difficulty;
        PendingChallenge(String nonce, long expiresAt, int difficulty) {
            this.nonce = nonce;
            this.expiresAt = expiresAt;
            this.difficulty = difficulty;
        }
    }
}
