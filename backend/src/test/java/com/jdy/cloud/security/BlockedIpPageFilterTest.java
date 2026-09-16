package com.jdy.cloud.security;

import com.jdy.cloud.service.AppealCenterService;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.17.4: 封禁专属警示页过滤器契约测试。
 */
@ExtendWith(MockitoExtension.class)
class BlockedIpPageFilterTest {

    /** v1.48.0: 站点域名由 app.site.domain 提供，测试使用 IANA 保留域。 */
    private static final String SITE_DOMAIN = "example.com";

    @Mock private AttackGuardService attackGuardService;
    @Mock private RequestTrustResolver trustResolver;
    @Mock private BlockedIpPageService blockedIpPageService;
    @Mock private AppealCenterService appealCenterService;
    @Mock private FilterChain chain;

    private BlockedIpPageFilter filter;

    @BeforeEach
    void setUp() {
        filter = new BlockedIpPageFilter(attackGuardService, trustResolver, blockedIpPageService, appealCenterService,
                new DeviceIdentityResolver(attackGuardService));
        ReflectionTestUtils.setField(filter, "enabled", true);
        ReflectionTestUtils.setField(filter, "siteDomain", SITE_DOMAIN);
        lenient().when(attackGuardService.isEnabled()).thenReturn(true);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
    }

    private MockHttpServletRequest apiRequest(String ip, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(ip);
        return request;
    }

    @Test
    void unblockedIpShouldPassThrough() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.70")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.70")).thenReturn(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.70", "/api/files/list"), response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void blockedAnonymousShouldGet403WithBlockedHeader() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.71")).thenReturn(true);
        lenient().when(attackGuardService.isBlockedSegment("203.0.113.71")).thenReturn(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.71", "/api/files/list"), response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("true", response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("blocked_page"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void segmentBlockedShouldAlsoGet403() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.72")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.72")).thenReturn(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.72", "/api/shares/download/7256ccf7"), response, chain);

        assertEquals(403, response.getStatus());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void statusEndpointShouldReportBlockedForAnonymous() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.76")).thenReturn(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.76", "/api/blocked-page/status"), response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("true", response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("\"blocked\":true"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void statusEndpointShouldReportFreeForUnblocked() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.77", "/api/blocked-page/status"), response, chain);

        // IronWall v1.36.0: 未封禁来源统一 404 标准体，禁止 {"blocked":false} 批量探测
        assertEquals(404, response.getStatus());
        assertNull(response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("资源不存在"));
        assertFalse(response.getContentAsString().contains("blocked"));
    }

    @Test
    void statusEndpointShouldLockAuthenticatedUsersOnBlockedIp() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.78")).thenReturn(true);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.78", "/api/blocked-page/status"), response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("true", response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        assertTrue(response.getContentAsString().contains("\"blocked\":true"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedPagePathShouldRenderPageForBlockedIp() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.73")).thenReturn(true);
        when(blockedIpPageService.render(eq("203.0.113.73"), nullable(String.class)))
                .thenReturn("<html>封禁警示页</html>");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.73", "/api/blocked-page"), response, chain);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentType().startsWith("text/html"));
        assertTrue(response.getContentAsString().contains("封禁警示页"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedAuthenticatedShouldGet403() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.74")).thenReturn(true);
        lenient().when(attackGuardService.isBlockedSegment("203.0.113.74")).thenReturn(false);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.74", "/api/files/list"), response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("true", response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedButWhitelistedShouldPassThrough() throws Exception {
        when(attackGuardService.isBlocked("198.51.100.26")).thenReturn(true);
        lenient().when(attackGuardService.isBlockedSegment("198.51.100.26")).thenReturn(false);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("198.51.100.26", "/api/files/list"), response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void disabledFilterShouldPassThrough() throws Exception {
        ReflectionTestUtils.setField(filter, "enabled", false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.75", "/api/files/list"), response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(any(), any());
        verify(attackGuardService, never()).isBlocked(anyString());
    }

    @Test
    void blockedPagePathShouldRenderForTrapOnlyIp() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.96")).thenReturn(true);
        when(blockedIpPageService.render(eq("203.0.113.96"), nullable(String.class)))
                .thenReturn("<html>陷阱警示页</html>");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.96", "/api/blocked-page"), response, chain);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("陷阱警示页"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedPagePathShouldReturn404ForUnblockedIp() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("203.0.113.79", "/api/blocked-page"), response, chain);

        assertEquals(404, response.getStatus());
        verify(blockedIpPageService, never()).render(anyString(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldRedirectHomeWhenChallengePasses() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.88")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.88"), any(), any())).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.88");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        assertEquals("https://example.com/", response.getRedirectedUrl());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldRedirectHttpsWhenProxySaysSo() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.93")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.93"), any(), any())).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.93");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        request.addHeader("X-Forwarded-Proto", "https");
        request.addHeader("Host", "example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        assertEquals("https://example.com/", response.getRedirectedUrl());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldFallbackToOfficialHttpsDomainWhenHostIsUntrusted() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.94")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.94"), any(), any())).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.94");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        request.addHeader("Host", "evil.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        assertEquals("https://example.com/", response.getRedirectedUrl());
        assertFalse(response.getHeader("Location").startsWith("http://"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldReturn403WhenNotEligible() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.89")).thenReturn(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.89");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verify(attackGuardService, never()).verifyChallenge(any(), any(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldReturn405ForNonPost() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.90");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(405, response.getStatus());
        assertEquals("POST", response.getHeader("Allow"));
        verify(attackGuardService, never()).verifyChallenge(any(), any(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldAcceptJsonBody() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.91")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.91"), eq("tok-json"), eq("42"))).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.91");
        request.setContentType("application/json");
        request.setContent("{\"token\":\"tok-json\",\"answer\":\"42\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        assertEquals("https://example.com/", response.getRedirectedUrl());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyEndpointShouldTolerateTrailingSlash() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.92")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.92"), eq("t"), eq("42"))).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH + "/");
        request.setRemoteAddr("203.0.113.92");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void statusEndpointShouldNotLockWhitelistedOnBlockedIp() throws Exception {
        when(blockedIpPageService.isActiveLockdown("198.51.100.26")).thenReturn(true);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(apiRequest("198.51.100.26", "/api/blocked-page/status"), response, chain);

        assertEquals(404, response.getStatus());
        assertTrue(response.getContentAsString().contains("资源不存在"));
    }

    @Test
    void verifyEndpointShouldForceHttpsEvenWhenSchemeIsHttpR40L03() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.95")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.95"), any(), any())).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", BlockedIpPageFilter.VERIFY_PATH);
        request.setRemoteAddr("203.0.113.95");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        request.setScheme("http");
        request.addHeader("Host", "example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        assertEquals("https://example.com/", response.getHeader("Location"));
        verify(chain, never()).doFilter(any(), any());
    }

    // ========== IronWall v1.28.16: 设备身份锁定 ==========

    private static final String FP_B = "bbbb111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

    private MockHttpServletRequest identityRequest(String ip, String path) {
        MockHttpServletRequest request = apiRequest(ip, path);
        request.addHeader("X-IronWall-FP", FP_B);
        return request;
    }

    @Test
    void identityJailedShouldGet403WithBlockedHeader() throws Exception {
        when(attackGuardService.isBlocked("203.0.113.98")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.98")).thenReturn(false);
        when(attackGuardService.isIdentityJailed(eq(FP_B), isNull())).thenReturn(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(identityRequest("203.0.113.98", "/api/files/list"), response, chain);

        assertEquals(403, response.getStatus());
        assertEquals("true", response.getHeader(BlockedIpPageFilter.BLOCKED_HEADER));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void identityJailedBlockedPageShouldRenderDeviceLockPage() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.99")).thenReturn(false);
        when(attackGuardService.isIdentityJailed(eq(FP_B), isNull())).thenReturn(true);
        when(attackGuardService.identityJailRemainingSeconds(FP_B)).thenReturn(123L);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(identityRequest("203.0.113.99", "/api/blocked-page"), response, chain);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("设备已锁定"));
        verify(blockedIpPageService, never()).render(anyString(), any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void identityJailedStatusShouldReportBlocked() throws Exception {
        when(blockedIpPageService.isActiveLockdown("203.0.113.100")).thenReturn(false);
        when(attackGuardService.isIdentityJailed(eq(FP_B), isNull())).thenReturn(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(identityRequest("203.0.113.100", "/api/blocked-page/status"), response, chain);

        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("\"blocked\":true"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void verifyPassShouldReleaseJailedIdentity() throws Exception {
        when(blockedIpPageService.isChallengeEligible("203.0.113.101")).thenReturn(true);
        when(attackGuardService.verifyChallenge(eq("203.0.113.101"), any(), any())).thenReturn(null);
        MockHttpServletRequest request = identityRequest("203.0.113.101", BlockedIpPageFilter.VERIFY_PATH);
        request.setMethod("POST");
        request.addParameter("token", "t");
        request.addParameter("answer", "42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(302, response.getStatus());
        verify(attackGuardService).releaseIdentity(FP_B);
        verify(chain, never()).doFilter(any(), any());
    }
}
