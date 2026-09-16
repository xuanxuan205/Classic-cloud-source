package com.jdy.cloud.security;

import com.jdy.cloud.service.ThreatIntelService;
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
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 经典云网盘铁壁安全引擎 IronWall v1.6 - 攻击检测与预警过滤器
 * 检测攻击 -> 记录 -> 引擎署名警告（JSON/HTML）-> 记分封禁升级
 *
 * IronWall v1.19 封禁闭环加固：
 * WHITELISTED 配置白名单 IP 完全放行，不参与检测记录（唯一豁免）；
 * ADMIN / AUTHENTICATED 与匿名同权：封禁校验前置、攻击计分统一，
 * 已登录请求无法再绕过 IP 封禁与计分升级（封堵威慑链盲区）。
 * 封禁状态下的已登录请求与匿名请求同权处置。
 *
 * IronWall v1.17: 蜜标令牌触发即 4441 快速封禁；封禁判断扩展至 IP 段。
 *
 * IronWall v1.18: 按请求声明 charset 归一化解码后检测，
 * UTF-16/UTF-32 载荷不再盲区；罕见字符集一律 415 拒绝并记协议异常。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 4)
public class AttackAlertFilter extends OncePerRequestFilter {

    private static final int MAX_BODY_SCAN_BYTES = 128 * 1024;

    private final AttackGuardService attackGuardService;
    private final RequestTrustResolver trustResolver;
    private final CanaryService canaryService;
    private final TrapService trapService;
    private final DeviceIdentityResolver deviceIdentityResolver;
    private final TlsProfileResolver tlsProfileResolver;
    private final ThreatIntelService threatIntelService;
    private final DdosDefenseService ddosDefenseService;
    private final MultipartBodyScanner multipartBodyScanner;
    private final TrafficAggregationService trafficAggregationService;

    public AttackAlertFilter(AttackGuardService attackGuardService, RequestTrustResolver trustResolver,
                             CanaryService canaryService,
                             TrapService trapService,
                             DeviceIdentityResolver deviceIdentityResolver,
                             TlsProfileResolver tlsProfileResolver,
                             ThreatIntelService threatIntelService,
                             DdosDefenseService ddosDefenseService,
                             MultipartBodyScanner multipartBodyScanner,
                             TrafficAggregationService trafficAggregationService) {
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
        this.canaryService = canaryService;
        this.trapService = trapService;
        this.deviceIdentityResolver = deviceIdentityResolver;
        this.tlsProfileResolver = tlsProfileResolver;
        this.threatIntelService = threatIntelService;
        this.ddosDefenseService = ddosDefenseService;
        this.multipartBodyScanner = multipartBodyScanner;
        this.trafficAggregationService = trafficAggregationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        if (!attackGuardService.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        String clientIp = ClientIpUtils.getClientIp(request);
        String method = request.getMethod();

        // IronWall v1.15: 信任分级。白名单 IP 完全放行。
        RequestTrustResolver.Level trust = trustResolver.resolve(request, clientIp);
        if (trust == RequestTrustResolver.Level.WHITELISTED) {
            chain.doFilter(request, response);
            return;
        }

        // IronWall v1.28.16: 提前解析设备身份，蜜罐令牌触发等高置信攻击同样锁定设备
        DeviceIdentityResolver.Identity identity = deviceIdentityResolver.resolve(request);
        String fingerprint = identity.fingerprint();
        String deviceId = identity.deviceId();

        // IronWall v1.17: 蜜标令牌触发——攻击者回放了蜜罐里偷到的假凭据，
        // 属于高置信度定向攻击，立即记分并 4441 拒绝，快速升级封禁。
        if (canaryService.isCanaryPresent(request)) {
            try {
                if (fingerprint != null || deviceId != null) {
                    attackGuardService.recordAttack(clientIp, AttackGuardService.TYPE_TOOL,
                            "蜜罐令牌触发", request.getRequestURI(),
                            request.getHeader("User-Agent"), method, false, fingerprint, deviceId, identity.signature());
                } else {
                    attackGuardService.recordAttack(clientIp, AttackGuardService.TYPE_TOOL,
                            "蜜罐令牌触发", request.getRequestURI(),
                            request.getHeader("User-Agent"), method, false);
                }
            } catch (Exception e) {
                log.error("[IronWall] canary record failed: {}", e.getMessage());
            }
            // IronWall v1.21: 蜜标令牌回放 = 高置信定向攻击，直接投入 L1 黑洞陷阱
            trapService.trap(clientIp, 1, "蜜标令牌", request.getRequestURI(), request.getHeader("User-Agent"), method, false);
            log.error("[IronWall] CANARY TRIGGERED: ip={} method={} path={}", clientIp, method, request.getRequestURI());
            respondBlocked(response, clientIp, request.getHeader("Accept"), request.getRequestURI());
            return;
        }

        // 已封禁 IP / IP 段：匿名请求直接警告；登录态请求放行（真实攻击载荷仍会在下方被识别拦截）
        if (attackGuardService.isBlocked(clientIp) || attackGuardService.isBlockedSegment(clientIp)) {
            respondBlocked(response, clientIp, request.getHeader("Accept"), request.getRequestURI());
            return;
        }
        // IronWall v1.28.16: 设备身份被锁定（换代理IP无效），同样拦截；验证/警示页路径已由前置过滤器放行
        // IronWall v1.43.0: 指纹锁定与 UA 联合判定，仅轮换自报指纹无法绕过。
        if (attackGuardService.isIdentityJailed(fingerprint,
                attackGuardService.hashUserAgent(request.getHeader("User-Agent")))
                || attackGuardService.isIdentityJailed(deviceId)) {
            respondBlocked(response, clientIp, request.getHeader("Accept"), request.getRequestURI());
            return;
        }

        // IronWall v1.38.0: 流量级跨IP聚合观测（匿名 /api/ 请求，只告警不封禁）
        if (trust == RequestTrustResolver.Level.ANONYMOUS && request.getRequestURI() != null
                && request.getRequestURI().startsWith("/api/")) {
            try {
                trafficAggregationService.observe(request.getHeader("User-Agent"),
                        tlsProfileResolver.resolve(request), deviceId, clientIp);
            } catch (Exception e) {
                log.warn("[IronWall] aggregation observe failed: {}", e.getMessage());
            }
        }

        // IronWall v1.27.10: 管理员富文本写入端点豁免。
        // 系统公告 / 站点维护公告仅管理员（JWT role=admin）可写，并按设计经 v-html 渲染；
        // 富文本内合法的 HTML/CSS/SVG 动画不应命中 XSS 检测。匿名与普通用户仍全量检测。
        if (trust == RequestTrustResolver.Level.ADMIN && isAdminRichTextEndpoint(method, request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        if ("OPTIONS".equalsIgnoreCase(method) || isStaticAsset(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest requestToUse = request;
        String body = null;
        String contentType = request.getContentType();
        String declaredCharset = RequestCharset.extractCharset(contentType);
        RequestCharset.Family charsetFamily = RequestCharset.classify(declaredCharset);
        boolean bodyScannable = isScannableBody(method, contentType, request.getContentLengthLong());
        if (bodyScannable) {
            try {
                CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(request);
                requestToUse = wrapped;
                if (declaredCharset == null) {
                    // IronWall v1.18.1: 无声明 charset 时按 BOM 嗅探，与 Jackson 自动编码探测同视图
                    String bomCharset = RequestCharset.sniffBomCharset(wrapped.getCachedBody());
                    if (bomCharset != null && !"UTF-8".equalsIgnoreCase(bomCharset)) {
                        declaredCharset = bomCharset;
                        charsetFamily = RequestCharset.Family.ANOMALOUS;
                    }
                }
                if (charsetFamily == RequestCharset.Family.REJECT) {
                    // IronWall v1.18: 罕见/未知字符集一律 415 拒绝，压缩探测空间
                    AttackGuardService.AttackRecord protocolRecord = recordProtocolAnomaly(
                            request, clientIp, "罕见字符集拒绝: " + declaredCharset);
                    // IronWall v1.37.0: 协议异常只记 2 分，不入陷阱、不单次直封（闭环）
                    respondUnsupportedCharset(response, clientIp, declaredCharset, protocolRecord,
                            request.getHeader("Accept"), request.getRequestURI());
                    return;
                }
                body = RequestCharset.decode(wrapped.getCachedBody(), declaredCharset);
                if (body == null) {
                    AttackGuardService.AttackRecord protocolRecord = recordProtocolAnomaly(
                            request, clientIp, "字符集解码失败: " + declaredCharset);
                    respondUnsupportedCharset(response, clientIp, declaredCharset, protocolRecord,
                            request.getHeader("Accept"), request.getRequestURI());
                    return;
                }
            } catch (Exception e) {
                body = null;
            }
        }

        // IronWall v1.36.0: multipart 解析盲区闭环。part 名 / filename / 字段值 / 文件头
        // 与 JSON、form 走完全相同的检测管线；命中按 4440 拦截，畸形按协议异常 400，
        // 干净请求继续下方主链（queryString/URI 检测不丢）。绝不整块缓存，850MB 大文件上传不受影响。
        if (isMultipart(contentType) && isBodyMethod(method)) {
            MultipartBodyScanner.ScanResult multipartResult = null;
            try {
                multipartResult = multipartBodyScanner.scan(request);
            } catch (Exception e) {
                log.error("[IronWall] multipart scan failed, fail-open: {}", e.getMessage());
            }
            if (multipartResult != null && multipartResult.outcome == MultipartBodyScanner.Outcome.HIT) {
                blockAttack(request, response, clientIp, method, multipartResult.detection,
                        fingerprint, deviceId, identity);
                return;
            }
            if (multipartResult != null && multipartResult.outcome == MultipartBodyScanner.Outcome.MALFORMED) {
                // 畸形 boundary / part 超量等按协议异常记分并 400 拒绝（探测空间压缩）
                String reason = multipartResult.snippet == null ? "multipart 解析异常" : multipartResult.snippet;
                recordProtocolAnomaly(request, clientIp, reason);
                // IronWall v1.37.0: 畸形 multipart 为协议异常噪声，只记分不陷阱
                respondBadRequest(response, request.getHeader("Accept"), request.getRequestURI());
                return;
            }
        }

        // IronWall v1.33.0: 登录蜜标账号诱捕——提交随机假账号即高置信攻击，与蜜标令牌同级处置
        try {
            String honeypotUser = attackGuardService.matchLoginHoneypot(
                    request.getRequestURI(), method, request.getQueryString(), body);
            if (honeypotUser != null) {
                attackGuardService.recordAttack(clientIp, AttackGuardService.TYPE_TOOL,
                        "蜜标账号诱捕: " + honeypotUser, request.getRequestURI(),
                        request.getHeader("User-Agent"), method, false);
                trapService.trap(clientIp, 1, "蜜标账号诱捕: " + honeypotUser,
                        request.getRequestURI(), request.getHeader("User-Agent"), method, false);
                log.error("[IronWall] LOGIN HONEYPOT TRIGGERED: ip={} username={}", clientIp, honeypotUser);
                respondBlocked(response, clientIp, request.getHeader("Accept"), request.getRequestURI());
                return;
            }
        } catch (Exception e) {
            log.error("[IronWall] login honeypot check failed, continue: {}", e.getMessage());
        }

        AttackGuardService.Detection detection = null;
        try {
            detection = attackGuardService.detect(
                    request.getQueryString(), body, request.getRequestURI(),
                    request.getHeader("User-Agent"), request.getHeader("Referer"), request.getHeader("Cookie"));
        } catch (Exception e) {
            // IronWall v1.10: WAF must never turn legitimate traffic into 500
            log.error("[IronWall] detect failed, fail-open: {}", e.getMessage());
        }
        if (detection == null) {
            if (bodyScannable && charsetFamily == RequestCharset.Family.ANOMALOUS) {
                // IronWall v1.18: 编码异常且未命中载荷，仍按协议异常拒绝，杜绝零计分侦察
                AttackGuardService.AttackRecord protocolRecord = recordProtocolAnomaly(
                        request, clientIp, "异常字符集未授权: " + declaredCharset);
                // IronWall v1.37.0: 异常字符集未授权为协议异常噪声，只记分不陷阱
                respondUnsupportedCharset(response, clientIp, declaredCharset, protocolRecord,
                        request.getHeader("Accept"), request.getRequestURI());
                return;
            }
            chain.doFilter(requestToUse, response);
            return;
        }

        blockAttack(request, response, clientIp, method, detection, fingerprint, deviceId, identity);
    }

    /**
     * IronWall v1.36.0: 攻击拦截统一出口（JSON/form 主链与 multipart 分支共用）。
     * 记分 + DDoS 交叉分析 + TLS 指纹证据 + 陷阱升级 + 最小化 4440 响应。
     */
    private void blockAttack(HttpServletRequest request, HttpServletResponse response, String clientIp,
                             String method, AttackGuardService.Detection detection,
                             String fingerprint, String deviceId, DeviceIdentityResolver.Identity identity)
            throws IOException {
        AttackGuardService.AttackRecord record = null;
        try {
            String userAgent = request.getHeader("User-Agent");
            // IronWall v1.32.0: 代理/机房信誉放大器——仅命中真实攻击后叠加额外记分；
            // 只读本地情报缓存（绝不发网络请求），缓存未命中仅异步预热，下击生效。
            int extraWeight = resolveProxyReputationBoost(clientIp);
            if (fingerprint != null || deviceId != null) {
                record = attackGuardService.recordAttack(
                        clientIp, detection.type, detection.payload, request.getRequestURI(),
                        userAgent, method, false, fingerprint, deviceId, identity.signature(), extraWeight);
            } else {
                record = attackGuardService.recordAttack(
                        clientIp, detection.type, detection.payload, request.getRequestURI(),
                        userAgent, method, false, extraWeight);
            }
            // IronWall v1.35.0: 攻击源并入 DDoS 溯源交叉分析（DDoS 集群成员中谁同时在注入攻击）
            try {
                ddosDefenseService.markAttack(clientIp, request.getRequestURI(), detection.type);
            } catch (Exception e) {
                log.error("[IronWall] DDoS markAttack failed, continue: {}", e.getMessage());
            }
            // IronWall v1.31.0: 命中攻击时登记 TLS 会话指纹（JA4 近似）跨 IP 证据；
            // 仅加速已计分攻击 IP，绝不按指纹封锁流量。解析失败只记日志，不影响拦截。
            try {
                String tlsProfile = tlsProfileResolver.resolve(request);
                if (tlsProfile != null) {
                    attackGuardService.registerTlsSighting(tlsProfile, clientIp);
                }
            } catch (Exception e) {
                log.error("[IronWall] TLS profile sighting failed, continue: {}", e.getMessage());
            }
        } catch (Exception e) {
            log.error("[IronWall] recordAttack failed, continue with warning: {}", e.getMessage());
        }

        if (record != null && "BLOCKED".equals(record.action)) {
            // IronWall v1.21: 触顶封禁的攻击载荷同时投入 L1 黑洞陷阱（只进不出）
            trapService.trap(clientIp, 1, detection.payload, request.getRequestURI(),
                    request.getHeader("User-Agent"), method, false);
        } else if (record != null && "SEGMENT_BLOCKED".equals(record.action)) {
            // IronWall v1.28.8: 顽固攻击者网段升级，直接投入 L7 最高层黑洞陷阱
            trapService.trap(clientIp, 7, "顽固攻击者网段升级", request.getRequestURI(),
                    request.getHeader("User-Agent"), method, false);
        }
        log.warn("[IronWall] attack blocked: ip={} type={} method={} path={} score={} action={}",
                clientIp, detection.type, method, request.getRequestURI(), record != null ? record.score : 0, record != null ? record.action : "WARN");

        respondWarning(response, clientIp, detection, record, request.getHeader("Accept"), request.getRequestURI());
    }

    /**
     * IronWall v1.32.0: 代理/机房信誉放大解析。
     * 仅命中真实攻击后调用；只读本地情报缓存，命中即返回放大分值；
     * 未命中时异步预热情报（下一击生效）。任何异常按 0 处理，绝不影响拦截主链。
     */
    private int resolveProxyReputationBoost(String clientIp) {
        try {
            int boost = attackGuardService.proxyReputationBoost();
            if (boost <= 0) return 0;
            if (threatIntelService.isLikelyProxyCached(clientIp)) {
                return boost;
            }
            threatIntelService.warmUpGeoAsync(List.of(clientIp));
        } catch (Exception e) {
            log.error("[IronWall] proxy reputation resolution failed, continue: {}", e.getMessage());
        }
        return 0;
    }

    private boolean isScannableBody(String method, String contentType, long contentLength) {
        if (contentLength > MAX_BODY_SCAN_BYTES) return false;
        if (!("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)
                || "PATCH".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method))) return false;
        if (contentType == null) return false;
        String ct = contentType.toLowerCase();
        return ct.contains("json") || ct.contains("x-www-form-urlencoded") || ct.startsWith("text/");
    }

    /**
     * IronWall v1.27.10: 管理员富文本写入端点。
     * 仅限管理员 JWT 会话使用；控制器自身的 @AuthenticationPrincipal 鉴权仍然生效。
     */
    private boolean isAdminRichTextEndpoint(String method, String uri) {
        if (uri == null) return false;
        String m = method == null ? "" : method.toUpperCase();
        String path = uri;
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
        if ("PUT".equals(m) && path.equals("/api/admin/settings")) return true;
        if ("POST".equals(m) && path.equals("/api/admin/announcements")) return true;
        return "PUT".equals(m) && path.matches("/api/admin/announcements/[^/]+");
    }

    private boolean isStaticAsset(String uri) {
        if (uri == null) return false;
        String u = uri.toLowerCase();
        return u.startsWith("/assets/")
                || u.endsWith(".js") || u.endsWith(".css") || u.endsWith(".png")
                || u.endsWith(".jpg") || u.endsWith(".jpeg") || u.endsWith(".gif")
                || u.endsWith(".webp") || u.endsWith(".svg") || u.endsWith(".ico")
                || u.endsWith(".woff") || u.endsWith(".woff2") || u.endsWith(".ttf")
                || u.endsWith(".map") || u.endsWith(".mp3") || u.endsWith(".mp4")
                || u.endsWith(".zip") || u.endsWith(".rar") || u.endsWith(".7z");
    }

    /**
     * IronWall v1.18: 记录协议异常（低分 + 30 秒同签名去重），记录失败不阻断拦截流程。
     */
    private AttackGuardService.AttackRecord recordProtocolAnomaly(HttpServletRequest request, String clientIp,
                                                                  String payload) {
        try {
            return attackGuardService.recordAttack(clientIp, AttackGuardService.TYPE_PROTOCOL, payload,
                    request.getRequestURI(), request.getHeader("User-Agent"), request.getMethod());
        } catch (Exception e) {
            log.error("[IronWall] protocol anomaly record failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * IronWall v1.18: 415 拒绝异常/罕见字符集，并署名警告。
     */
    private void respondUnsupportedCharset(HttpServletResponse response, String ip, String charset,
                                           AttackGuardService.AttackRecord record, String accept, String uri)
            throws IOException {
        String warning = "请求声明的字符集 " + (charset == null ? "(空)" : charset)
                + " 不在允许范围，本次访问已按协议异常记录。请使用 UTF-8 编码重试，继续越界将触发封禁。";
        respond(response, ip, AttackGuardService.TYPE_PROTOCOL, record, warning, accept, uri, 415);
    }

    private void respondWarning(HttpServletResponse response, String ip,
                                 AttackGuardService.Detection detection,
                                 AttackGuardService.AttackRecord record,
                                 String accept, String uri) throws IOException {
        String warning = "你的 IP 与攻击载荷已被记录。请立即停止越界行为，否则将触发报警处理并延长封禁。";
        respond(response, ip, detection.type, record, warning, accept, uri, 4440);
    }

    private void respondBlocked(HttpServletResponse response, String ip, String accept, String uri) throws IOException {
        String warning = "该 IP 已触发自动封禁。越界行为将触发报警处理，封禁期内所有访问被拒绝。";
        respond(response, ip, null, null, warning, accept, uri, 4441);
    }

    private void respond(HttpServletResponse response, String ip, String type,
                         AttackGuardService.AttackRecord record, String warning,
                         String accept, String uri, int code) throws IOException {
        // IronWall v1.36.0: 响应信息泄露收敛。
        // 4440/4441 统一为 403 + 最小 JSON，不再输出引擎名/攻击类型/记分/解封时间/出口 IP，
        // 不再设置任何 X-IronWall* 引擎头。封禁态 X-IronWall-Blocked 仅由 BlockedIpPageFilter
        // 在封禁页流程按前端契约下发，引擎拦截响应与普通 403 不可区分。
        int status = code == 4440 || code == 4441 ? HttpStatus.FORBIDDEN.value() : code;
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Cache-Control", "no-store");

        boolean wantsHtml = accept != null && accept.contains("text/html") && !uri.startsWith("/api");
        if (wantsHtml) {
            writeMinimalHtml(response, status);
        } else {
            writeMinimalJson(response, status);
        }
    }

    private void writeMinimalJson(HttpServletResponse response, int status) throws IOException {
        String message = status == 400 || status == 415 ? "请求不合法" : "请求被拒绝";
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.getWriter().write("{\"code\":" + status + ",\"message\":\"" + message + "\"}");
    }

    private void writeMinimalHtml(HttpServletResponse response, int status) throws IOException {
        String message = status == 400 || status == 415 ? "请求不合法" : "请求被拒绝";
        String html = "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>访问被拒绝</title>"
                + "<style>body{margin:0;background:#0b0f1a;color:#e2e8f0;font-family:'PingFang SC','Microsoft YaHei',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}"
                + ".card{max-width:480px;width:92%;background:#111827;border:1px solid #334155;border-radius:16px;padding:40px 36px;text-align:center}"
                + "h1{font-size:22px;margin:0 0 12px;color:#fff}"
                + "p{font-size:14px;color:#94a3b8;margin:0;line-height:1.7}"
                + "</style></head><body><div class=\"card\">"
                + "<h1>访问被拒绝</h1>"
                + "<p>" + message + "</p>"
                + "</div></body></html>";
        response.setContentType(MediaType.TEXT_HTML_VALUE + ";charset=UTF-8");
        response.getWriter().write(html);
    }

    /** IronWall v1.36.0: multipart 畸形/超量统一 400 最小 JSON。 */
    private void respondBadRequest(HttpServletResponse response, String accept, String uri) throws IOException {
        respond(response, null, AttackGuardService.TYPE_PROTOCOL, null, null, accept, uri, 400);
    }

    private boolean isMultipart(String contentType) {
        return contentType != null && contentType.toLowerCase().startsWith("multipart/");
    }

    private boolean isBodyMethod(String method) {
        return "POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)
                || "PATCH".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method);
    }

}
