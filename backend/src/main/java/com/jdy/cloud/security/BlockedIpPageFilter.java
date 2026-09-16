package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.service.AppealCenterService;
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

/**
 * IronWall v1.17.4: 封禁专属警示页过滤器（合法威慑，非攻击）。
 * 被自动封禁（IP 或 /24 网段）的匿名 IP：
 * /api/blocked-page：返回专属警示页（引擎触发状态 + 威慑引擎内容记录 + 解封倒计时）；
 * 其余所有 /api/ 请求：403 + X-IronWall-Blocked 头，前端据此整页跳转到警示页。
 * 白名单 IP（WHITELISTED）唯一豁免；登录态与匿名同权受封禁约束。任何异常 fail-open。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class BlockedIpPageFilter extends OncePerRequestFilter {

    public static final String BLOCKED_PAGE_PATH = "/api/blocked-page";
    public static final String VERIFY_PATH = "/api/blocked-page/verify";
    public static final String STATUS_PATH = "/api/blocked-page/status";
    public static final String APPEAL_PATH = "/api/blocked-page/appeal";
    public static final String BLOCKED_HEADER = "X-IronWall-Blocked";

    private final AttackGuardService attackGuardService;
    private final RequestTrustResolver trustResolver;
    private final BlockedIpPageService blockedIpPageService;
    private final DeviceIdentityResolver deviceIdentityResolver;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AppealCenterService appealCenterService;

    @Value("${app.security.defense-engine.blocked-page.enabled:true}")
    private boolean enabled;

    /** 站点域名由配置提供（{@code app.site.domain}）。 */
    @Value("${app.site.domain:}")
    private String siteDomain;

    public BlockedIpPageFilter(AttackGuardService attackGuardService,
                               RequestTrustResolver trustResolver,
                               BlockedIpPageService blockedIpPageService,
                               AppealCenterService appealCenterService,
                               DeviceIdentityResolver deviceIdentityResolver) {
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
        this.blockedIpPageService = blockedIpPageService;
        this.deviceIdentityResolver = deviceIdentityResolver;
        this.appealCenterService = appealCenterService;
    }

    /**
     * IronWall v1.24.0: 人机验证提交端点。
     * 仅「IP 级站内封禁」的 POST 可受理；通过后 302 回首页，失败回警示页并附原因。
     */
    private void handleVerify(HttpServletRequest request, HttpServletResponse response, String ip) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            // IronWall v1.26.2: 明确方法契约，避免复查时把端点误判为“未实现”
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            response.setHeader("Allow", "POST");
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false, "code", 405, "message", "人机验证仅支持 POST 提交")));
            return;
        }
        if (!blockedIpPageService.isChallengeEligible(ip)) {
            // IronWall v1.26.2: 未封禁/网段封禁态返回 403 明确语义（原 404 易被误判为端点缺失）
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false, "code", 403, "message", "当前状态无需人机验证")));
            return;
        }
        String token = request.getParameter("token");
        String answer = request.getParameter("answer");
        if ((token == null || answer == null) && request.getContentType() != null
                && request.getContentType().toLowerCase().contains("json")) {
            // IronWall v1.26.2: 兼容 JSON 提交的自动化客户端，避免参数取空导致挑战失效
            try {
                Map<?, ?> body = objectMapper.readValue(request.getInputStream(), Map.class);
                token = asString(body.get("token"));
                answer = asString(body.get("answer"));
            } catch (Exception ignored) {
                // 解析失败按空参数处理，走“expired”分支并计失败次数
            }
        }
        String result = attackGuardService.verifyChallenge(ip, token, answer);
        if (result == null) {
            // IronWall v1.25.0: 验证通过同时释放陷阱（再犯立即重新入阱并升级处置）
            blockedIpPageService.releaseTrap(ip);
            // IronWall v1.28.16: 人机验证通过同步解除设备身份锁（防误封逃生通道）
            releaseIdentities(request);
            redirect(request, response, "/");
            return;
        }
        redirect(request, response, BLOCKED_PAGE_PATH + "?r=" + result);
    }

    /**
     * IronWall v1.28.9: 302 跳转显式使用 https 绝对地址。
     * 后端经 nginx 反代时原始 scheme 为 http，sendRedirect 会生成 http:// 明文跳转；
     * 此处优先取 X-Forwarded-Proto，杜绝 HTTP 降级。
     */
    private void redirect(HttpServletRequest request, HttpServletResponse response, String target) throws IOException {
        // IronWall v1.28.11: 302 一律 https，绝不回退 request.getScheme()
        // （nginx 反代下后端看到的 scheme 是 http，回退会泄露明文跳转）；
        // 站点域名由 app.site.domain 提供。
        // 已配置时 Host 仅接受白名单，其余统一回落配置域名，杜绝投毒；
        // 未配置时沿用请求 Host，站点仍可正常工作。
        String scheme = "https";
        String host = request.getHeader("Host");
        String configured = siteDomain == null ? "" : siteDomain.trim();
        if (host == null || host.isBlank()) {
            host = configured.isEmpty() ? "localhost" : configured;
        } else if (!configured.isEmpty()
                && !(host.equalsIgnoreCase(configured)
                     || host.equalsIgnoreCase("www." + configured)
                     || host.startsWith("127.0.0.1")
                     || host.startsWith("localhost"))) {
            host = configured;
        }
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", scheme + "://" + host + target);
        response.setHeader("Cache-Control", "no-store");
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private void handleAppeal(HttpServletRequest request, HttpServletResponse response, String ip) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        if (!"POST".equalsIgnoreCase(request.getMethod()) || !blockedIpPageService.isActiveLockdown(ip)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false, "code", 404, "message", "资源不存在")));
            return;
        }
        String contact = safeParam(request.getParameter("contact"), 64);
        String reason = safeParam(request.getParameter("reason"), 240);
        log.warn("[IronWall] unblock appeal received: ip={} contact={} reason={}", ip, contact, reason);
        // IronWall v1.26.1: 申诉端点限流，防止单个攻击者刷屏淹没人工审核队列
        AppealCenterService.AppealSubmitResult result = appealCenterService.submit(ip, contact, reason);
        if (!"ACCEPTED".equals(result.code)) {
            String message = "TOO_MANY_PENDING".equals(result.code)
                    ? "您已有待处理的申诉，请勿重复提交，等待管理员复核。"
                    : "申诉提交过于频繁，请稍后再试。";
            response.setStatus(429);
            response.setHeader("Retry-After", "3600");
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false, "code", 429, "message", message)));
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                "success", true,
                "message", "申诉已记录，管理员将人工复核；请保持当前网络环境，耐心等待处理结果。")));
    }

    private String safeParam(String value, int max) {
        if (value == null) return "";
        String v = value.trim().replaceAll("[\\x00-\\x1f\\x7f]", "");
        return v.length() > max ? v.substring(0, max) : v;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!enabled || !attackGuardService.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        try {
            String path = request.getRequestURI();
            String ip = ClientIpUtils.getClientIp(request);
            // IronWall v1.26.2: 归一化尾部斜杠，/verify/ 等变体与正式路径同等受理
            String normalizedPath = path != null && path.length() > 1 && path.endsWith("/")
                    ? path.substring(0, path.length() - 1) : path;

            if (VERIFY_PATH.equals(normalizedPath)) {
                handleVerify(request, response, ip);
                return;
            }

            if (APPEAL_PATH.equals(normalizedPath)) {
                handleAppeal(request, response, ip);
                return;
            }

            if (BLOCKED_PAGE_PATH.equals(normalizedPath)) {
                // IronWall v1.19: 仅对被封禁 IP 渲染警示页，未封禁一律 404，杜绝流水泄露
                boolean pageBlocked = blockedIpPageService.isActiveLockdown(ip);
                // IronWall v1.28.16: 设备指纹锁定的设备渲染专属警示页（换代理IP后仍被锁定）
                boolean identityBlocked = !pageBlocked && identityJailed(request);
                if (!pageBlocked) {
                    if (!identityBlocked) {
                        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                        response.setCharacterEncoding("UTF-8");
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
                        response.setHeader("Cache-Control", "no-store");
                        response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                                "success", false, "code", 404, "message", "资源不存在")));
                        return;
                    }
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setCharacterEncoding("UTF-8");
                    response.setContentType(MediaType.TEXT_HTML_VALUE + ";charset=UTF-8");
                    response.setHeader("Cache-Control", "no-store");
                    response.setHeader("Content-Security-Policy",
                            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; " +
                            "style-src 'unsafe-inline'; script-src 'unsafe-inline'");
                    response.getWriter().write(renderDeviceLockPage(ip, identityRemainingSeconds(request)));
                    return;
                }
                response.setStatus(HttpServletResponse.SC_OK);
                response.setCharacterEncoding("UTF-8");
                response.setContentType(MediaType.TEXT_HTML_VALUE + ";charset=UTF-8");
                response.setHeader("Cache-Control", "no-store");
                // IronWall v1.26.1: 页面级 CSP，允许本页静态内联样式/脚本与同源表单/申诉请求
                response.setHeader("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; " +
                        "form-action 'self'; connect-src 'self'; img-src 'self' data:; " +
                        "style-src 'unsafe-inline'; script-src 'unsafe-inline'");
                response.getWriter().write(blockedIpPageService.render(ip, request.getParameter("r")));
                return;
            }

            // IronWall v1.18.2: 封禁状态探测端点。前端全局守卫与 nginx auth_request 共用：
            // 被封禁（匿名）返回 403 + 标识头，未封禁返回 200，供页面级/网关级全站锁定。
            if (STATUS_PATH.equals(normalizedPath)) {
                boolean locked = blockedIpPageService.isActiveLockdown(ip)
                        && trustResolver.resolve(request, ip) != RequestTrustResolver.Level.WHITELISTED;
                // IronWall v1.28.16: 指纹锁定的设备同样上报锁定状态
                if (!locked && trustResolver.resolve(request, ip) != RequestTrustResolver.Level.WHITELISTED) {
                    locked = identityJailed(request);
                }
                response.setCharacterEncoding("UTF-8");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
                response.setHeader("Cache-Control", "no-store");
                if (locked) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setHeader(BLOCKED_HEADER, "true");
                    response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                            "blocked", true, "page", BLOCKED_PAGE_PATH)));
                } else {
                    // IronWall v1.36.0: 未封禁来源统一 404 标准体，
                    // 与警示页 404 完全一致——批量探测无法区分"端点不存在"与"未封禁"。
                    // 前端 blockedGuard 按 body.blocked 判读，404 即视为未封禁，无需改前端。
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                            "success", false, "code", 404, "message", "资源不存在")));
                }
                return;
            }

            // IronWall v1.28.16: IP/网段未封禁但设备身份被锁定，同样拦截（换代理IP无效）
            if (!attackGuardService.isBlocked(ip) && !attackGuardService.isBlockedSegment(ip)
                    && !identityJailed(request)) {
                chain.doFilter(request, response);
                return;
            }

            // IronWall v1.19: 仅白名单 IP 豁免封禁，登录态与匿名同权
            RequestTrustResolver.Level trust = trustResolver.resolve(request, ip);
            if (trust == RequestTrustResolver.Level.WHITELISTED) {
                chain.doFilter(request, response);
                return;
            }

            // IronWall v1.21.2: 公开头像静态资源封禁期同样放行（公开无业务数据，仅降低误伤面）
            if ("GET".equalsIgnoreCase(request.getMethod()) && path.startsWith("/api/files/avatar/")) {
                chain.doFilter(request, response);
                return;
            }

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setHeader(BLOCKED_HEADER, "true");
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "success", false,
                    "code", 403,
                    "message", "该来源已被安全策略封禁，仅可访问封禁警示页",
                    "blocked_page", BLOCKED_PAGE_PATH)));
        } catch (Exception e) {
            log.error("[IronWall] blocked page filter failed, fail-open: {}", e.getMessage());
            chain.doFilter(request, response);
        }
    }

    // ========== IronWall v1.28.16: 设备身份锁定 ==========

    private String resolveFingerprint(HttpServletRequest request) {
        return deviceIdentityResolver.resolve(request).fingerprint();
    }

    private String resolveDeviceId(HttpServletRequest request) {
        return deviceIdentityResolver.resolve(request).deviceId();
    }

    private boolean identityJailed(HttpServletRequest request) {
        // IronWall v1.43.0: 指纹锁定与 UA 联合判定，仅轮换自报指纹无法绕过。
        return attackGuardService.isIdentityJailed(resolveFingerprint(request),
                attackGuardService.hashUserAgent(request.getHeader("User-Agent")))
                || attackGuardService.isIdentityJailed(resolveDeviceId(request));
    }

    private long identityRemainingSeconds(HttpServletRequest request) {
        long fp = attackGuardService.identityJailRemainingSeconds(resolveFingerprint(request));
        long did = attackGuardService.identityJailRemainingSeconds(resolveDeviceId(request));
        return Math.max(fp, did);
    }

    private void releaseIdentities(HttpServletRequest request) {
        attackGuardService.releaseIdentity(resolveFingerprint(request));
        attackGuardService.releaseIdentity(resolveDeviceId(request));
    }

    /** 设备指纹锁定专属警示页（IP 未封禁时使用）：不泄露内部画像，仅提示锁定与剩余时间。 */
    private String renderDeviceLockPage(String ip, long remainSeconds) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">")
          .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
          .append("<meta name=\"robots\" content=\"noindex,nofollow\">")
          .append("<title>设备已锁定 · 安全访问控制</title>")
          .append("<style>")
          .append("*{margin:0;padding:0;box-sizing:border-box}")
          .append("body{background:#0a0d12;color:#e2e8f0;font-family:'Segoe UI','Microsoft YaHei',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}")
          .append(".card{width:100%;max-width:640px;background:#11151d;border:1px solid #272e3b;border-radius:20px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.55)}")
          .append(".head{background:linear-gradient(135deg,#7f1d1d,#450a0a);padding:28px 32px;display:flex;align-items:center;gap:16px}")
          .append(".shield{width:52px;height:52px;border-radius:14px;background:rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;font-size:30px}")
          .append(".head h1{font-size:20px;font-weight:700;color:#fff}.head p{font-size:13px;color:#fca5a5;margin-top:4px}")
          .append(".body{padding:28px 32px}")
          .append(".banner{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);border-radius:12px;padding:14px 18px;font-size:14px;color:#fecaca;line-height:1.8;margin-bottom:22px}")
          .append(".box{background:#0d1117;border:1px solid #1f2733;border-radius:12px;padding:14px 16px}")
          .append(".box .k{font-size:11px;color:#64748b;margin-bottom:6px}.box .v{font-size:17px;font-weight:700;color:#34d399}")
          .append(".foot{padding:16px 32px;border-top:1px solid #1f2733;font-size:12px;color:#475569}")
          .append("@media(max-width:560px){.head{padding:20px}.body{padding:18px}.foot{padding:14px 18px}}")
          .append("</style></head><body><div class=\"card\">")
          .append("<div class=\"head\"><div class=\"shield\">\uD83D\uDEE1\uFE0F</div><div><h1>设备已锁定</h1>")
          .append("<p>本设备已触发安全访问控制</p></div></div>")
          .append("<div class=\"body\">")
          .append("<div class=\"banner\">\u26A0\uFE0F <b>访问已被拦截：</b>该设备的历史访问行为已触发安全策略，")
          .append("更换网络或代理不会解除本次锁定。请立即停止异常访问行为；相关记录已留存，继续尝试将升级处置。</div>")
          .append("<div class=\"box\"><div class=\"k\">预计解除倒计时</div><div class=\"v\" id=\"cd\">")
          .append(formatRemain(remainSeconds)).append("</div></div>")
          .append("<p style=\"font-size:12px;color:#64748b;line-height:1.7;margin-top:18px\">如系误判，请停止当前操作并稍后再试；设备锁定到期后自动解除。</p>")
          .append("</div>")
          .append("<div class=\"foot\"><span>安全访问控制 · 经典云网盘铁壁安全引擎</span></div>")
          .append("</div></body></html>");
        return sb.toString();
    }

    private String formatRemain(long seconds) {
        // IronWall v1.36.0: 设备锁页只给模糊档位，不下发精确解封秒数（泄露面收敛）。
        if (seconds <= 0) return "自动解除中，请刷新页面";
        if (seconds < 3600) return "1 小时内自动解除";
        if (seconds < 86400) return "24 小时内自动解除";
        if (seconds < 7 * 86400L) return "数日内自动解除";
        return "按安全策略周期自动解除";
    }
}
