package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.40.0: API 加密层入口过滤器。
 *
 * 规则：
 * 1) 标准路径 /api/<path>（未带会话前缀）白名单外一律 403（X-IronWall-Sign-Required），
 * 不记攻击分、不封禁——防旧缓存/版本错位误伤真实用户；
 * 2) 会话路径 /api/s/<sid>/<path>：校验 sid 会话与 HMAC 签名（时间窗 + nonce 防重放），
 * 通过后把 URI 还原为标准 /api/<path> 交给下游（所有既有过滤器/控制器零改动）；
 * IronWall v1.41.0：/api/s/<sid>/<path> 的 <path> 首段为路由码（64 位 hex）时，
 * 按 ApiRouteTable 模板回填动态段还原真实路径；非路由码保持旧明文语义（双通道兼容）；
 * IronWall v1.41.0：会话绑定边缘 TLS 指纹，请求指纹不一致拒绝（不计分）；
 * IronWall v1.41.0：签名拒绝接入 SignFailureAuditService 审计（不计分不封禁）；
 * 3) JSON 且 content-length<=1MB 的请求体参与体哈希；multipart 不读体（大文件零开销）；
 * 4) 回环地址（本机运维脚本/护盾）默认免签名，可用配置关闭。
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 3)
public class ApiCryptoFilter extends OncePerRequestFilter {

    public static final String SIGN_REQUIRED_HEADER = "X-IronWall-Sign-Required";
    public static final String PREFIX = "/api/s/";
    /** IronWall v1.43.0: multipart 上传完整性哈希头（v1.45.0 起为全文件 SHA-256，强制）。 */
    public static final String FILE_HASH_HEADER = "X-Api-File-Hash";
    /** IronWall v1.45.0: 分片上传每片内容哈希头（HMAC 绑定 + 服务端复核，强制）。 */
    public static final String CHUNK_HASH_HEADER = "X-Api-Chunk-Hash";
    private static final long MAX_BODY_HASH_BYTES = 1024L * 1024L;

    private final ApiCryptoService apiCryptoService;
    private final ApiRouteTable apiRouteTable;
    private final SignFailureAuditService signFailureAuditService;
    private final TlsProfileResolver tlsProfileResolver;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${app.security.api-crypto.enabled:true}")
    private boolean enabled;
    @Value("${app.security.api-crypto.tls-bind-enabled:true}")
    private boolean tlsBindEnabled;
    @Value("${app.security.api-crypto.trust-loopback:true}")
    private boolean trustLoopback;
    @Value("${app.security.api-crypto.allow-paths:}")
    private String extraAllowPaths;

    private volatile Set<String> extraAllowPrefixes = Set.of();

    public ApiCryptoFilter(ApiCryptoService apiCryptoService, ApiRouteTable apiRouteTable,
                           SignFailureAuditService signFailureAuditService,
                           TlsProfileResolver tlsProfileResolver) {
        this.apiCryptoService = apiCryptoService;
        this.apiRouteTable = apiRouteTable;
        this.signFailureAuditService = signFailureAuditService;
        this.tlsProfileResolver = tlsProfileResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!enabled) {
            chain.doFilter(request, response);
            return;
        }
        String path = request.getRequestURI();
        if (path == null || !path.startsWith("/api/")) {
            chain.doFilter(request, response);
            return;
        }
        String method = request.getMethod();
        if (method == null || "OPTIONS".equalsIgnoreCase(method)) {
            chain.doFilter(request, response);
            return;
        }
        if (trustLoopback && isLoopback(ClientIpUtils.getClientIp(request))) {
            chain.doFilter(request, response);
            return;
        }
        if (isAllowlisted(method, path)) {
            chain.doFilter(request, response);
            return;
        }

        if (path.startsWith(PREFIX)) {
            handlePrefixed(request, response, chain, method, path);
        } else {
            reject(request, response, path);
        }
    }

    private void handlePrefixed(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                String method, String path) throws ServletException, IOException {
        String rest = path.substring(PREFIX.length());
        int slash = rest.indexOf('/');
        if (slash <= 0) {
            reject(request, response, path);
            return;
        }
        String sid = rest.substring(0, slash);
        ApiCryptoService.Session session = apiCryptoService.findSession(sid);
        if (session == null) {
            reject(request, response, path);
            return;
        }
        // IronWall v1.41.0: 会话绑定边缘 TLS 指纹；双侧缺失自动跳过（防误伤）
        if (tlsBindEnabled && session.tlsProfile() != null) {
            String requestProfile = tlsProfileResolver.resolve(request);
            if (requestProfile != null && !session.tlsProfile().equals(requestProfile)) {
                reject(request, response, path);
                return;
            }
        }
        // IronWall v1.41.0: 哈希码路由还原；未知码保持旧明文语义
        String canonical = resolveCanonical(rest.substring(slash + 1));
        if (canonical == null) {
            reject(request, response, path);
            return;
        }

        String query = request.getQueryString();
        String pathWithQuery = query == null || query.isBlank() ? canonical : canonical + "?" + query;
        String bodyHash = null;
        HttpServletRequest wrapped = request;
        // IronWall v1.43.0: 空 JSON body（Content-Length=0）不参与体哈希——
        // 前端无 body 的 POST/DELETE 不带 bodyHash，旧逻辑恒以 sha256("") 比对导致 403
        // (新建文件夹 400/403」根因）。hasSmallBody 已改为 len>0。
        if (isJsonBody(request) && hasSmallBody(request)) {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
            bodyHash = apiCryptoService.sha256Hex(cached.getCachedBody());
            wrapped = cached;
        } else if (isMultipart(request)) {
            // IronWall v1.45.0: multipart 完整性绑定升级为强制——
            // /files/upload 必须携带全文件 SHA-256（X-Api-File-Hash），
            // /files/upload/chunk 必须携带分片 SHA-256（X-Api-Chunk-Hash）；
            // 缺失或格式错误一律 403，杜绝「不带哈希整体跳过完整性校验」。
            if (canonical.endsWith("/files/upload")) {
                String fileHash = request.getHeader(FILE_HASH_HEADER);
                if (fileHash == null || !fileHash.matches("[0-9a-fA-F]{64}")) {
                    reject(request, response, path);
                    return;
                }
                bodyHash = fileHash.toLowerCase(Locale.ROOT);
            } else if (canonical.endsWith("/files/upload/chunk")) {
                String chunkHash = request.getHeader(CHUNK_HASH_HEADER);
                if (chunkHash == null || !chunkHash.matches("[0-9a-fA-F]{64}")) {
                    reject(request, response, path);
                    return;
                }
                bodyHash = chunkHash.toLowerCase(Locale.ROOT);
            } else {
                // 其他 multipart（头像等）：有合法哈希则纳入 HMAC，无则维持旧语义
                String fileHash = request.getHeader(FILE_HASH_HEADER);
                if (fileHash != null && fileHash.matches("[0-9a-fA-F]{64}")) {
                    bodyHash = fileHash.toLowerCase(Locale.ROOT);
                }
            }
        }

        boolean ok = apiCryptoService.verify(session, method, pathWithQuery,
                request.getHeader(ApiCryptoService.HEADER_TS),
                request.getHeader(ApiCryptoService.HEADER_NONCE),
                bodyHash,
                request.getHeader(ApiCryptoService.HEADER_SIG));
        if (!ok) {
            reject(request, response, path);
            return;
        }
        chain.doFilter(new RewrittenRequest(wrapped, canonical), response);
    }

    /**
     * IronWall v1.41.0: 路由码还原。
     * 首段命中路由码：按模板 {n} 回填动态段，占位符与动态段数量不符返回 null（拒绝）；
     * 非路由码（旧客户端明文逻辑路径）走旧语义 /api/<tail> 兼容。
     */
    private String resolveCanonical(String tail) {
        if (tail == null || tail.isBlank()) {
            return null;
        }
        int slash = tail.indexOf('/');
        String firstSegment = slash >= 0 ? tail.substring(0, slash) : tail;
        if (apiRouteTable.isCode(firstSegment)) {
            List<String> segments = new ArrayList<>();
            if (slash >= 0) {
                Collections.addAll(segments, tail.substring(slash + 1).split("/"));
            }
            return apiRouteTable.resolve(firstSegment, segments);
        }
        return "/api/" + tail;
    }

    private boolean isJsonBody(HttpServletRequest request) {
        String ct = request.getContentType();
        return ct != null && ct.toLowerCase(Locale.ROOT).startsWith(MediaType.APPLICATION_JSON_VALUE);
    }

    private boolean isMultipart(HttpServletRequest request) {
        String ct = request.getContentType();
        return ct != null && ct.toLowerCase(Locale.ROOT).startsWith("multipart/");
    }

    private boolean hasSmallBody(HttpServletRequest request) {
        long len;
        try {
            len = Long.parseLong(request.getHeader("Content-Length"));
        } catch (Exception e) {
            return false;
        }
        return len > 0 && len <= MAX_BODY_HASH_BYTES;
    }

    private boolean isLoopback(String ip) {
        return ip != null && (ip.equals("127.0.0.1") || ip.equals("::1") || ip.equals("0:0:0:0:0:0:0:1"));
    }

    private boolean isAllowlisted(String method, String path) {
        if (path.equals("/api/crawler-challenge") || path.equals("/api/crawler-verify")
                || ("POST".equalsIgnoreCase(method) && path.equals("/api/bootstrap"))
                || path.startsWith("/api/blocked-page")) {
            return true;
        }
        if ("GET".equalsIgnoreCase(method)
                && (path.startsWith("/api/files/avatar/")
                    || path.equals("/api/version/info")
                    || path.startsWith("/api/shares/download")
                    || path.startsWith("/api/shares/download-zip"))) {
            return true;
        }
        String extra = extraAllowPaths;
        if (extra != null && !extra.isBlank()) {
            Set<String> prefixes = extraAllowPrefixes;
            if (prefixes.isEmpty()) {
                prefixes = ConcurrentHashMap.newKeySet();
                prefixes.addAll(Arrays.asList(extra.split(",")));
                extraAllowPrefixes = prefixes;
            }
            for (String prefix : prefixes) {
                String trimmed = prefix.trim();
                if (!trimmed.isEmpty() && path.startsWith(trimmed)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, String path) throws IOException {
        // IronWall v1.41.0: 仅统计审计，不记攻击分、不封禁（防旧缓存/版本错位误伤）
        signFailureAuditService.record(ClientIpUtils.getClientIp(request));
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader(SIGN_REQUIRED_HEADER, "1");
        response.getWriter().write(objectMapper.writeValueAsString(
                java.util.Map.of("success", false, "code", 4030,
                        "message", "接口签名缺失或已失效，请刷新页面重试",
                        "path", "/api")));
    }

    /** 把请求 URI 还原为标准路径（getRequestURI/getServletPath 均还原，查询串保持不变）。 */
    private static class RewrittenRequest extends HttpServletRequestWrapper {
        private final String canonicalPath;

        RewrittenRequest(HttpServletRequest request, String canonicalPath) {
            super(request);
            this.canonicalPath = canonicalPath;
        }

        @Override
        public String getRequestURI() {
            return canonicalPath;
        }

        @Override
        public String getServletPath() {
            return canonicalPath;
        }

        @Override
        public String getPathInfo() {
            return null;
        }
    }
}
