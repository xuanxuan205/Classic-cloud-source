package com.jdy.cloud.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponseWrapper;
import com.jdy.cloud.util.ClientIpUtils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final AttackGuardService attackGuardService;
    private final DeviceIdentityResolver deviceIdentityResolver;

    public SecurityHeadersFilter(AttackGuardService attackGuardService,
                                 DeviceIdentityResolver deviceIdentityResolver) {
        this.attackGuardService = attackGuardService;
        this.deviceIdentityResolver = deviceIdentityResolver;
    }

    /** 测试兼容构造：不签发设备 ID。 */
    SecurityHeadersFilter() {
        this(null, null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        // ---- 基础防护 ----
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        // IronWall v1.21.2: 分享下载链接携带凭据，收紧为 no-referrer 杜绝经 Referer 外泄
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        response.setHeader("Pragma", "no-cache");

        // IronWall v1.28.16: 首次访问签发服务端签名设备ID（换代理IP仍可锁定同一设备）。
        // 签名校验防伪造；仅首次签发，后续请求复用既有 Cookie。
        if (attackGuardService != null) {
            try {
                boolean hasValidDid = false;
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    for (Cookie cookie : cookies) {
                        if ("iw_did".equals(cookie.getName())
                                && attackGuardService.isValidDeviceId(cookie.getValue())) {
                            hasValidDid = true;
                            break;
                        }
                    }
                }
                if (!hasValidDid) {
                    response.addHeader("Set-Cookie", "iw_did=" + attackGuardService.issueDeviceId()
                            + "; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax");
                }
            } catch (Exception e) {
                // 设备ID签发失败不影响主链路（fail-open）
            }
        }
        // IronWall v1.29.0: 观察设备指纹（轮换过快即锁定设备），并签发指纹绑定签名 Cookie
        if (attackGuardService != null && deviceIdentityResolver != null) {
            try {
                DeviceIdentityResolver.Identity identity = deviceIdentityResolver.resolve(request);
                if (identity.deviceId() != null && identity.fingerprint() != null) {
                    String sig = attackGuardService.observeDeviceFingerprint(
                            identity.deviceId(), identity.fingerprint(), ClientIpUtils.getClientIp(request));
                    if (sig != null && !sig.equals(identity.signature())) {
                        response.addHeader("Set-Cookie", "iw_fp_sig=" + sig
                                + "; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax");
                    }
                }
            } catch (Exception e) {
                // 指纹观察/签名失败不影响主链路（fail-open）
            }
        }

        // ---- HSTS (IronWall v1.2: 始终带 includeSubDomains + preload) ----
        // 后端位于nginx之后（SSL终止），因此无条件设置HSTS
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

        // ---- Cookie 安全标志 ----
        // 通过响应头提示浏览器对所有cookie应用安全策略
        response.setHeader("Expect-CT", "max-age=86400, enforce");



        // ---- CSP: 内容安全策略（API层防护） ----
        // 封禁警示页由 BlockedIpPageFilter 单独设置允许内联样式/脚本的页面级 CSP，
        // 否则本 API 级 CSP 会把该页自身的倒计时脚本与申诉表单禁用。
        if (!BlockedIpPageFilter.BLOCKED_PAGE_PATH.equals(request.getRequestURI())) {
            response.setHeader("Content-Security-Policy",
                "default-src 'none'; " +
                "frame-ancestors 'none'; " +
                "form-action 'none'");
        }

        // IronWall v1.16: 对后端下发的一切 Cookie 强制 Secure / HttpOnly / SameSite=Strict，
        // 即使外部配置覆盖了 spring.servlet.session.cookie 也能兜底。
        chain.doFilter(request, new CookieHardeningResponse(response));
    }

    private static class CookieHardeningResponse extends HttpServletResponseWrapper {

        CookieHardeningResponse(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void addHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                super.addHeader(name, hardenCookie(value));
            } else {
                super.addHeader(name, value);
            }
        }

        @Override
        public void setHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                super.setHeader(name, hardenCookie(value));
            } else {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addCookie(Cookie cookie) {
            if (cookie == null) {
                super.addCookie(null);
                return;
            }
            StringBuilder sb = new StringBuilder(cookie.getName()).append('=');
            sb.append(cookie.getValue() == null ? "" : cookie.getValue());
            if (cookie.getPath() != null && !cookie.getPath().isEmpty()) {
                sb.append("; Path=").append(cookie.getPath());
            }
            if (cookie.getDomain() != null && !cookie.getDomain().isEmpty()) {
                sb.append("; Domain=").append(cookie.getDomain());
            }
            if (cookie.getMaxAge() >= 0) {
                sb.append("; Max-Age=").append(cookie.getMaxAge());
            }
            super.addHeader("Set-Cookie", hardenCookie(sb.toString()));
        }

        private String hardenCookie(String header) {
            if (header == null || header.isBlank()) {
                return header;
            }
            String hardened = header;
            String lower = hardened.toLowerCase();
            if (!lower.contains("secure")) {
                hardened += "; Secure";
            }
            if (!lower.contains("httponly")) {
                hardened += "; HttpOnly";
            }
            if (!lower.contains("samesite")) {
                hardened += "; SameSite=Strict";
            }
            return hardened;
        }
    }
}
