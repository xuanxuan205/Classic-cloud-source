package com.jdy.cloud.security;

import jakarta.servlet.FilterChain;
import com.jdy.cloud.service.ThreatIntelService;
import com.jdy.cloud.repository.AttackLogRepository;
import jakarta.servlet.http.Part;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPart;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.19: attack alert filter contract tests.
 * Only whitelisted IPs bypass; authenticated sessions are scored and blocked
 * exactly like anonymous traffic, closing the deterrence-chain bypass.
 */
@ExtendWith(MockitoExtension.class)
class AttackAlertFilterTest {

    @Mock private AttackGuardService attackGuardService;
    @Mock private RequestTrustResolver trustResolver;
    @Mock private CanaryService canaryService;
    @Mock private TrapService trapService;
    @Mock private FilterChain chain;
    @Mock private ThreatIntelService threatIntelService;
    @Mock private DdosDefenseService ddosDefenseService;
    @Mock private TrafficAggregationService trafficAggregationService;
    @Mock private AttackLogRepository attackLogRepository;

    private AttackAlertFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AttackAlertFilter(attackGuardService, trustResolver, canaryService, trapService,
                new DeviceIdentityResolver(attackGuardService), new TlsProfileResolver(), threatIntelService,
                ddosDefenseService, new MultipartBodyScanner(attackGuardService), trafficAggregationService);
        lenient().when(attackGuardService.isEnabled()).thenReturn(true);
        lenient().when(attackGuardService.isBlocked(anyString())).thenReturn(false);
        lenient().when(attackGuardService.isBlockedSegment(anyString())).thenReturn(false);
        lenient().when(canaryService.isCanaryPresent(any())).thenReturn(false);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
    }

    private MockHttpServletRequest jsonPost(String ip) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/files/create");
        request.setRemoteAddr(ip);
        request.setContentType("application/json");
        request.setContent("{\"name\":\"x' OR 1=1 --\"}".getBytes(StandardCharsets.UTF_8));
        return request;
    }

    // ===== IronWall v1.36.0: multipart 解析盲区闭环 =====

    private MockHttpServletRequest multipartRequest(String ip, Collection<Part> parts) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/upload-avatar") {
            @Override
            public Collection<Part> getParts() {
                return parts;
            }
        };
        request.setRemoteAddr(ip);
        request.setContentType("multipart/form-data; boundary=test");
        request.addHeader("Accept", "application/json");
        return request;
    }

    private byte[] pngBytes() {
        return new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0};
    }

    @Test
    void multipartMaliciousFilenameShouldBeBlockedMinimally() throws Exception {
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "admin' OR '1'='1.png"));
        when(attackGuardService.recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean(), anyInt()))
                .thenReturn(new AttackGuardService.AttackRecord("203.0.113.50", AttackGuardService.TYPE_SQL, "p", 5, 0, 0, "WARN"));
        MockHttpServletRequest request = multipartRequest("203.0.113.50", List.of(
                new MockPart("avatar", "admin' OR '1'='1.png", pngBytes(), MediaType.parseMediaType("image/png"))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        assertNull(response.getHeader("X-IronWall-Engine"));
        assertNull(response.getHeader("X-IronWall"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void multipartBenignUploadShouldPassThrough() throws Exception {
        MockHttpServletRequest request = multipartRequest("203.0.113.51", List.of(
                new MockPart("avatar", "photo.png", pngBytes(), MediaType.parseMediaType("image/png"))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(any(), any());
    }

    /**
     * IronWall v1.39.0: 冒烟——用真实 AttackGuardService 检测管线
     * （根因护栏：良性 PNG 文件头含 0x00 不得误报；恶意文件名必须拦截）。
     */
    private AttackAlertFilter realPipelineFilter() throws Exception {
        AttackGuardService realGuard = new AttackGuardService(attackLogRepository);
        for (String name : List.of("enabled", "operatorFamilyEnabled", "mysqlBuiltinEnabled", "semanticEnabled")) {
            java.lang.reflect.Field field = AttackGuardService.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(realGuard, true);
        }
        return new AttackAlertFilter(realGuard, trustResolver, canaryService, trapService,
                new DeviceIdentityResolver(realGuard), new TlsProfileResolver(), threatIntelService,
                ddosDefenseService, new MultipartBodyScanner(realGuard), trafficAggregationService);
    }

    @Test
    void benignMultipartShouldPassRealDetectPipelineR55() throws Exception {
        AttackAlertFilter realFilter = realPipelineFilter();
        MockHttpServletRequest request = multipartRequest("203.0.113.60", List.of(
                new MockPart("avatar", "photo.png", pngBytes(), MediaType.parseMediaType("image/png"))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        realFilter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus(), "冒烟：良性 multipart 必须放行");
        verify(chain).doFilter(any(), any());
    }

    @Test
    void maliciousMultipartShouldBeBlockedByRealDetectPipelineR55() throws Exception {
        AttackAlertFilter realFilter = realPipelineFilter();
        MockHttpServletRequest request = multipartRequest("203.0.113.61", List.of(
                new MockPart("avatar", "admin' OR '1'='1.png", pngBytes(), MediaType.parseMediaType("image/png"))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        realFilter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void malformedMultipartShouldBeRejectedWith400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/upload-avatar") {
            @Override
            public Collection<Part> getParts() {
                throw new IllegalStateException("malformed multipart");
            }
        };
        request.setRemoteAddr("203.0.113.52");
        request.setContentType("multipart/form-data; boundary=abc");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(400, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求不合法"));
        verify(attackGuardService).recordAttack(eq("203.0.113.52"), eq(AttackGuardService.TYPE_PROTOCOL),
                anyString(), any(), any(), anyString());
        verify(trapService, never()).trap(anyString(), anyInt(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void whitelistedIpShouldBypassAllChecks() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        MockHttpServletRequest request = jsonPost("203.0.113.20");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
        verify(attackGuardService, never()).isBlocked(anyString());
        verify(attackGuardService, never()).detect(any(), any(), any(), any(), any(), any());
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean(), anyInt());
    }

    @Test
    void blockedIpAnonymousShouldGet4441() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.21")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.21");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedIpAuthenticatedShouldGet4441() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(attackGuardService.isBlocked("203.0.113.22")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.22");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void attackPayloadFromAuthenticatedShouldWarnAndScore() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "x' OR 1=1 --"));
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.23", AttackGuardService.TYPE_SQL, "x' OR 1=1 --", 15, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.23"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0))).thenReturn(warn);

        MockHttpServletRequest request = jsonPost("203.0.113.23");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
        verify(attackGuardService).recordAttack(eq("203.0.113.23"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0));
    }

    @Test
    void attackPayloadFromAnonymousShouldRecordStrictScore() throws Exception {
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "x' OR 1=1 --"));
        AttackGuardService.AttackRecord blocked = new AttackGuardService.AttackRecord(
                "203.0.113.24", AttackGuardService.TYPE_SQL, "x' OR 1=1 --", 25, 1, System.currentTimeMillis() + 3600_000L, "BLOCKED");
        when(attackGuardService.recordAttack(eq("203.0.113.24"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0))).thenReturn(blocked);

        MockHttpServletRequest request = jsonPost("203.0.113.24");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
        verify(attackGuardService).recordAttack(eq("203.0.113.24"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0));
    }

    @Test
    void blockedSegmentAnonymousShouldGet4441() throws Exception {
        when(attackGuardService.isBlockedSegment("203.0.113.25")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.25");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedSegmentAuthenticatedShouldGet4441() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(attackGuardService.isBlockedSegment("203.0.113.26")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.26");
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void canaryTokenShouldTrigger4441AndRecord() throws Exception {
        when(canaryService.isCanaryPresent(any())).thenReturn(true);
        AttackGuardService.AttackRecord rec = new AttackGuardService.AttackRecord(
                "203.0.113.27", AttackGuardService.TYPE_TOOL, "\u871c\u6807\u4ee4\u724c\u89e6\u53d1", 5, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.27"), eq(AttackGuardService.TYPE_TOOL),
                any(), any(), any(), any(), eq(false))).thenReturn(rec);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.27");
        request.addHeader("Accept", "application/json");
        request.addHeader("Authorization", "Bearer IronWall.Canary.abc");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
        verify(attackGuardService).recordAttack(eq("203.0.113.27"), eq(AttackGuardService.TYPE_TOOL),
                any(), any(), any(), any(), eq(false));
    }

    // ===== IronWall v1.18: 字符集归一化检测 =====

    @Test
    void utf16leSqlInjectionBodyShouldBeDetectedAndBlocked() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.30");
        request.setContentType("application/json; charset=UTF-16LE");
        request.setContent("{\"username\":\"' OR 1=1 --\"}".getBytes(StandardCharsets.UTF_16LE));
        request.addHeader("Accept", "application/json");
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "' OR 1=1 --"));
        when(attackGuardService.recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean(), anyInt()))
                .thenReturn(new AttackGuardService.AttackRecord("203.0.113.30", AttackGuardService.TYPE_SQL, "' OR 1=1 --", 5, 0, 0, "WARN"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(attackGuardService).detect(any(), bodyCaptor.capture(), any(), any(), any(), any());
        assertTrue(bodyCaptor.getValue().contains("' OR 1=1 --"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void utf16BodyWithoutPayloadShouldBeRejectedAsProtocolAnomaly() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.31");
        request.setContentType("application/json; charset=UTF-16");
        request.setContent("{\"username\":\"normal\"}".getBytes(StandardCharsets.UTF_16));
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(415, response.getStatus());
        verify(attackGuardService).recordAttack(eq("203.0.113.31"), eq(AttackGuardService.TYPE_PROTOCOL),
                contains("字符集"), anyString(), any(), anyString());
        verify(trapService, never()).trap(anyString(), anyInt(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void rareCharsetShouldBeRejectedWith415() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.32");
        request.setContentType("application/json; charset=UTF-7");
        request.setContent("hello".getBytes(StandardCharsets.UTF_8));
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(415, response.getStatus());
        verify(attackGuardService).recordAttack(eq("203.0.113.32"), eq(AttackGuardService.TYPE_PROTOCOL),
                contains("字符集"), anyString(), any(), anyString());
        verify(trapService, never()).trap(anyString(), anyInt(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
        verify(attackGuardService, never()).detect(any(), any(), any(), any(), any(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void bomOnlyUtf16BodyWithoutCharsetShouldStillBeDetected() throws Exception {
        // Jackson 会按 BOM 自动解码 UTF-16LE；检测层必须与之一致（v1.18.1 封堵盲区）
        byte[] bodyBytes = "{\"username\":\"' OR 1=1 --\"}".getBytes(StandardCharsets.UTF_16LE);
        byte[] withBom = new byte[bodyBytes.length + 2];
        withBom[0] = (byte) 0xFF;
        withBom[1] = (byte) 0xFE;
        System.arraycopy(bodyBytes, 0, withBom, 2, bodyBytes.length);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.34");
        request.setContentType("application/json");
        request.setContent(withBom);
        request.addHeader("Accept", "application/json");
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "' OR 1=1 --"));
        when(attackGuardService.recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean(), anyInt()))
                .thenReturn(new AttackGuardService.AttackRecord("203.0.113.34", AttackGuardService.TYPE_SQL, "' OR 1=1 --", 5, 0, 0, "WARN"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(attackGuardService).detect(any(), bodyCaptor.capture(), any(), any(), any(), any());
        assertTrue(bodyCaptor.getValue().contains("' OR 1=1 --"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void gbkCharsetBodyShouldBeScannedNormally() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/files/create");
        request.setRemoteAddr("203.0.113.33");
        request.setContentType("application/json; charset=GBK");
        request.setContent("{\"name\":\"x' OR 1=1 --\"}".getBytes(Charset.forName("GBK")));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(attackGuardService).detect(any(), bodyCaptor.capture(), any(), any(), any(), any());
        assertTrue(bodyCaptor.getValue().contains("' OR 1=1 --"));
        verify(chain).doFilter(any(), any());
    }

    @Test
    void adminRichTextEndpointsShouldBypassContentDetection() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ADMIN);
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/admin/settings");
        request.setRemoteAddr("203.0.113.40");
        request.setContentType("application/json");
        request.setContent("{\"disabled_notice\":\"<div><svg width='10' height='10'><animateTransform attributeName='transform'/></svg></div>\"}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(attackGuardService, never()).detect(any(), any(), any(), any(), any(), any());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void anonymousRichTextBodyShouldStillBeDetected() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_XSS, "<svg"));
        when(attackGuardService.recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean(), anyInt()))
                .thenReturn(new AttackGuardService.AttackRecord("203.0.113.41", AttackGuardService.TYPE_XSS, "<svg", 5, 0, 0, "WARN"));
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/admin/settings");
        request.setRemoteAddr("203.0.113.41");
        request.setContentType("application/json");
        request.setContent("{\"disabled_notice\":\"<svg></svg>\"}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(chain, never()).doFilter(any(), any());
    }

    // ===== IronWall v1.32.0: 代理/机房信誉放大器（只放大已确认攻击，绝不发网络请求） =====

    @Test
    void proxyReputationAttackShouldAmplifyScore() throws Exception {
        when(attackGuardService.proxyReputationBoost()).thenReturn(10);
        when(threatIntelService.isLikelyProxyCached("203.0.113.42")).thenReturn(true);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "x' OR 1=1 --"));
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.42", AttackGuardService.TYPE_SQL, "x' OR 1=1 --", 15, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.42"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(10))).thenReturn(warn);
        MockHttpServletRequest request = jsonPost("203.0.113.42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(attackGuardService).recordAttack(eq("203.0.113.42"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(10));
        verify(threatIntelService, never()).warmUpGeoAsync(anyCollection());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void proxyReputationCacheMissShouldWarmUpWithoutAmplify() throws Exception {
        when(attackGuardService.proxyReputationBoost()).thenReturn(10);
        when(threatIntelService.isLikelyProxyCached("203.0.113.43")).thenReturn(false);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "x' OR 1=1 --"));
        when(attackGuardService.recordAttack(eq("203.0.113.43"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0)))
                .thenReturn(new AttackGuardService.AttackRecord(
                        "203.0.113.43", AttackGuardService.TYPE_SQL, "x' OR 1=1 --", 5, 0, 0, "WARN"));
        MockHttpServletRequest request = jsonPost("203.0.113.43");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verify(attackGuardService).recordAttack(eq("203.0.113.43"), eq(AttackGuardService.TYPE_SQL),
                any(), any(), any(), eq("POST"), eq(false), eq(0));
        verify(threatIntelService).warmUpGeoAsync(argThat(col -> col != null && col.contains("203.0.113.43")));
        verify(chain, never()).doFilter(any(), any());
    }

    // ===== IronWall v1.33.0: 登录蜜标账号诱捕 =====

    @Test
    void loginHoneypotUsernameShouldTrigger4441AndRecord() throws Exception {
        when(attackGuardService.matchLoginHoneypot(eq("/api/auth/login"), eq("POST"), isNull(),
                contains("trap_user_alpha"))).thenReturn("trap_user_alpha");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.50");
        request.setContentType("application/json");
        request.setContent("{\"username\":\"trap_user_alpha\",\"password\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        request.addHeader("Accept", "application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("请求被拒绝"));
        verify(attackGuardService).recordAttack(eq("203.0.113.50"), eq(AttackGuardService.TYPE_TOOL),
                contains("蜜标账号诱捕"), any(), any(), any(), eq(false));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void normalLoginUsernameShouldNotTriggerHoneypot() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.51");
        request.setContentType("application/json");
        request.setContent("{\"username\":\"alice\",\"password\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(any(), any());
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
    }
}
