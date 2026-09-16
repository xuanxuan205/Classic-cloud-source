package com.jdy.cloud.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.40.0: 接口加密层过滤器契约测试。
 * 未签名标准路径拒绝 / 签名会话路径放行并还原 / 白名单放行 / 防重放 / 时间窗。
 */
class ApiCryptoFilterTest {

    private ApiCryptoService service;
    private ApiCryptoFilter filter;
    private ApiCryptoService.Session session;
    private ApiRouteTable routeTable;

    private static class RecordingChain implements FilterChain {
        String uri;
        int calls = 0;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            calls++;
            uri = ((HttpServletRequest) request).getRequestURI();
        }
    }

    @BeforeEach
    void setUp() {
        service = new ApiCryptoService();
        ReflectionTestUtils.setField(service, "sessionTtlHours", 24L);
        ReflectionTestUtils.setField(service, "tsWindowSeconds", 120L);
        routeTable = new ApiRouteTable();
        filter = new ApiCryptoFilter(service, routeTable, new SignFailureAuditService(), new TlsProfileResolver());
        ReflectionTestUtils.setField(filter, "enabled", true);
        ReflectionTestUtils.setField(filter, "tlsBindEnabled", false);
        ReflectionTestUtils.setField(filter, "trustLoopback", true);
        ReflectionTestUtils.setField(filter, "extraAllowPaths", "");
        session = service.issueSession();
    }

    private String hmacHex(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : out) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private MockHttpServletRequest signedRequest(String method, String canonical, String body) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(method,
                "/api/s/" + session.sid() + (canonical.startsWith("/api/") ? canonical.substring(4) : canonical));
        req.setRemoteAddr("203.0.113.9");
        if (body != null) {
            req.setContent(body.getBytes(StandardCharsets.UTF_8));
            req.addHeader("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));
            req.setContentType("application/json");
        }
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String bodyHash = body != null ? service.sha256Hex(body) : null;
        String sig = hmacHex(session.key(), method + "|" + canonical + "|" + ts + "|" + nonce
                + (bodyHash != null ? "|" + bodyHash : ""));
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        return req;
    }

    @Test
    void unsignedCanonicalPath_isRejected() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setRemoteAddr("203.0.113.9");
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals("1", res.getHeader(ApiCryptoFilter.SIGN_REQUIRED_HEADER));
        assertEquals(0, chain.calls);
    }

    @Test
    void signedPrefixedPath_isAcceptedAndRewritten() throws Exception {
        String body = "{\"username\":\"a\",\"password\":\"b\"}";
        MockHttpServletRequest req = signedRequest("POST", "/api/auth/login", body);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/auth/login", chain.uri);
    }

    /** IronWall v1.43.0: 空 JSON body 的 POST（axios 默认头 + Content-Length:0）不再产生哈希不对称。 */
    @Test
    void jsonEmptyBodyPost_signedWithoutBodyHash_isAccepted() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/folder");
        MockHttpServletRequest req = new MockHttpServletRequest("POST",
                "/api/s/" + session.sid() + "/" + code);
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("application/json");
        req.addHeader("Content-Length", "0");
        req.setQueryString("name=newfolder");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(),
                "POST|/api/files/folder?name=newfolder|" + ts + "|" + nonce);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/files/folder", chain.uri);
    }

    /** IronWall v1.43.0: multipart 的 X-Api-File-Hash 纳入 HMAC，一致则放行。 */
    @Test
    void multipartFileHash_boundIntoSig_isAccepted() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/upload");
        MockHttpServletRequest req = new MockHttpServletRequest("POST",
                "/api/s/" + session.sid() + "/" + code);
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("multipart/form-data; boundary=xx");
        String fileHash = "a".repeat(64);
        req.addHeader(ApiCryptoFilter.FILE_HASH_HEADER, fileHash);
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(),
                "POST|/api/files/upload|" + ts + "|" + nonce + "|" + fileHash);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/files/upload", chain.uri);
    }

    /** IronWall v1.43.0: 头部哈希被篡改（签名按原哈希）必须拒绝。 */
    @Test
    void multipartFileHash_tamperedHeader_isRejected() throws Exception {
        String code = ApiRouteTable.codeOf("files/upload");
        MockHttpServletRequest req = new MockHttpServletRequest("POST",
                "/api/s/" + session.sid() + "/" + code);
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("multipart/form-data; boundary=xx");
        String signedHash = "a".repeat(64);
        req.addHeader(ApiCryptoFilter.FILE_HASH_HEADER, "b".repeat(64));
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(),
                "POST|/api/files/upload|" + ts + "|" + nonce + "|" + signedHash);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals(0, chain.calls);
    }

    /** IronWall v1.45.0: multipart 直传缺失 X-Api-File-Hash 一律 403（校验不可整体跳过）。 */
    @Test
    void signedMultipart_withoutFileHash_isRejected() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/s/" + session.sid() + "/files/upload");
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("multipart/form-data; boundary=xyz");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(), "POST|/api/files/upload|" + ts + "|" + nonce);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals(0, chain.calls);
    }

    /** IronWall v1.45.0: 分片上传的 X-Api-Chunk-Hash 纳入 HMAC，一致则放行。 */
    @Test
    void multipartChunkHash_boundIntoSig_isAccepted() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/upload/chunk");
        MockHttpServletRequest req = new MockHttpServletRequest("POST",
                "/api/s/" + session.sid() + "/" + code);
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("multipart/form-data; boundary=xx");
        String chunkHash = "c".repeat(64);
        req.addHeader(ApiCryptoFilter.CHUNK_HASH_HEADER, chunkHash);
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(),
                "POST|/api/files/upload/chunk|" + ts + "|" + nonce + "|" + chunkHash);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/files/upload/chunk", chain.uri);
    }

    /** IronWall v1.45.0: 分片上传缺失 X-Api-Chunk-Hash 一律 403。 */
    @Test
    void signedMultipartChunk_withoutChunkHash_isRejected() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/s/" + session.sid() + "/files/upload/chunk");
        req.setRemoteAddr("203.0.113.9");
        req.setContentType("multipart/form-data; boundary=xyz");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(), "POST|/api/files/upload/chunk|" + ts + "|" + nonce);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals(0, chain.calls);
    }

    @Test
    void replaySameNonce_isRejected() throws Exception {
        String body = "{\"a\":1}";
        MockHttpServletRequest first = signedRequest("POST", "/api/files/list", body);
        MockHttpServletResponse res1 = new MockHttpServletResponse();
        RecordingChain chain1 = new RecordingChain();
        filter.doFilter(first, res1, chain1);
        assertEquals(1, chain1.calls);

        MockHttpServletRequest replay = new MockHttpServletRequest("POST", "/api/s/" + session.sid() + "/files/list");
        replay.setRemoteAddr("203.0.113.9");
        replay.setContent(body.getBytes(StandardCharsets.UTF_8));
        replay.addHeader("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));
        replay.setContentType("application/json");
        replay.addHeader(ApiCryptoService.HEADER_TS, first.getHeader(ApiCryptoService.HEADER_TS));
        replay.addHeader(ApiCryptoService.HEADER_NONCE, first.getHeader(ApiCryptoService.HEADER_NONCE));
        replay.addHeader(ApiCryptoService.HEADER_SIG, first.getHeader(ApiCryptoService.HEADER_SIG));
        MockHttpServletResponse res2 = new MockHttpServletResponse();
        RecordingChain chain2 = new RecordingChain();
        filter.doFilter(replay, res2, chain2);
        assertEquals(403, res2.getStatus());
        assertEquals(0, chain2.calls);
    }

    @Test
    void allowlistedVersionInfo_passesUnsigned() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/version/info");
        req.setRemoteAddr("203.0.113.9");
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
    }

    @Test
    void loopback_isTrusted() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/files/ping");
        req.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
    }

    @Test
    void options_preflightPasses() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("OPTIONS", "/api/auth/login");
        req.setRemoteAddr("203.0.113.9");
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertNotNull(chain.uri);
        assertTrue(chain.uri.startsWith("/api/auth/login"));
    }

    @Test
    void codedStaticPath_isResolvedAndRewritten() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("auth/login");
        String body = "{\"username\":\"a\",\"password\":\"b\"}";
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/s/" + session.sid() + "/" + code);
        req.setRemoteAddr("203.0.113.9");
        req.setContent(body.getBytes(StandardCharsets.UTF_8));
        req.addHeader("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));
        req.setContentType("application/json");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String bodyHash = service.sha256Hex(body);
        String sig = hmacHex(session.key(), "POST|/api/auth/login|" + ts + "|" + nonce + "|" + bodyHash);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/auth/login", chain.uri);
    }

    @Test
    void codedDynamicPath_isResolvedWithSegments() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/download/{0}");
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/s/" + session.sid() + "/" + code + "/12345");
        req.setRemoteAddr("203.0.113.9");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(), "GET|/api/files/download/12345|" + ts + "|" + nonce);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/files/download/12345", chain.uri);
    }

    @Test
    void codedPath_segmentCountMismatch_isRejected() throws Exception {
        String code = ApiRouteTable.codeOf("files/download/{0}");
        MockHttpServletRequest req = new MockHttpServletRequest("GET",
                "/api/s/" + session.sid() + "/" + code + "/1/extra");
        req.setRemoteAddr("203.0.113.9");
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = hmacHex(session.key(), "GET|/api/files/download/1/extra|" + ts + "|" + nonce);
        req.addHeader(ApiCryptoService.HEADER_TS, String.valueOf(ts));
        req.addHeader(ApiCryptoService.HEADER_NONCE, nonce);
        req.addHeader(ApiCryptoService.HEADER_SIG, sig);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals(0, chain.calls);
    }

    @Test
    void tlsBoundSession_profileMismatch_isRejected() throws Exception {
        ReflectionTestUtils.setField(filter, "tlsBindEnabled", true);
        TlsProfileResolver resolver = new TlsProfileResolver();
        session = service.issueSession(resolver.resolve(requestWithProfile("TLSv1.3:ECDHE-AES: h2")));
        String body = "{\"username\":\"a\",\"password\":\"b\"}";
        MockHttpServletRequest req = signedRequest("POST", "/api/auth/login", body);
        req.addHeader(TlsProfileResolver.HEADER, "TLSv1.3:OTHER-CIPHER:h2");
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(403, res.getStatus());
        assertEquals(0, chain.calls);
    }

    @Test
    void tlsBoundSession_profileMatch_isAccepted() throws Exception {
        ReflectionTestUtils.setField(filter, "tlsBindEnabled", true);
        TlsProfileResolver resolver = new TlsProfileResolver();
        String profile = "TLSv1.3:ECDHE-AES:h2";
        session = service.issueSession(resolver.resolve(requestWithProfile(profile)));
        String body = "{\"username\":\"a\",\"password\":\"b\"}";
        MockHttpServletRequest req = signedRequest("POST", "/api/auth/login", body);
        req.addHeader(TlsProfileResolver.HEADER, profile);
        MockHttpServletResponse res = new MockHttpServletResponse();
        RecordingChain chain = new RecordingChain();
        filter.doFilter(req, res, chain);
        assertEquals(1, chain.calls);
        assertEquals("/api/auth/login", chain.uri);
    }

    private MockHttpServletRequest requestWithProfile(String profile) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/");
        req.setRemoteAddr("203.0.113.9");
        req.addHeader(TlsProfileResolver.HEADER, profile);
        return req;
    }
}
