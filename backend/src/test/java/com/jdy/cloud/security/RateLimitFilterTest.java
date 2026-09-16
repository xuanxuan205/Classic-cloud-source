package com.jdy.cloud.security;

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
 * IronWall v1.15: rate limit filter trust-tier contract tests.
 * Anonymous keeps strict limits; authenticated gets 10x limits bucketed by user id;
 * whitelisted IPs bypass entirely.
 */
@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock private RequestTrustResolver trustResolver;
    @Mock private AttackGuardService attackGuardService;
    @Mock private TrapService trapService;
    @Mock private DdosDefenseService ddosDefenseService;
    @Mock private FilterChain chain;

    private RateLimitFilter filter;

    @BeforeEach
    void setUp() {
        filter = new RateLimitFilter(trustResolver, attackGuardService, trapService, ddosDefenseService);
        ReflectionTestUtils.setField(filter, "enabled", true);
        ReflectionTestUtils.setField(filter, "requestsPerMinute", 3);
        ReflectionTestUtils.setField(filter, "authRequestsPerMinute", 2);
        ReflectionTestUtils.setField(filter, "authenticatedRequestsPerMinute", 60);
        ReflectionTestUtils.setField(filter, "authenticatedBurst", 20);
        ReflectionTestUtils.setField(filter, "authenticatedBurstSeconds", 10);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
        lenient().when(trustResolver.userId(any())).thenReturn(null);
        lenient().when(attackGuardService.isBlocked(anyString())).thenReturn(false);
        lenient().when(attackGuardService.isBlockedSegment(anyString())).thenReturn(false);
    }

    private MockHttpServletRequest apiRequest(String ip, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(ip);
        return request;
    }

    @Test
    void anonymousShouldBeLimitedStrictly() throws Exception {
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 4; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.30", "/api/files/list"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    void blockedStatusShouldUseGeneralAnonymousBucket() throws Exception {
        // IronWall v1.28.14: /status 是无副作用探测端点，应走通用桶（requestsPerMinute=3）
        // 而非严格桶（authRequestsPerMinute=2）；旧实现第 3 次即 429，前端多标签页轮询会误触
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.40", "/api/blocked-page/status"), response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    void blockedVerifyShouldStayInStrictBucket() throws Exception {
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.41", "/api/blocked-page/verify"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(2)).doFilter(any(), any());
    }

    @Test
    void authenticatedShouldGetTenfoldLimitAndUserBucket() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(trustResolver.userId(any())).thenReturn(42L);

        for (int i = 0; i < 5; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.31", "/api/files/list"), response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(chain, times(5)).doFilter(any(), any());
    }

    @Test
    void authenticatedAuthEndpointShouldGetTenfoldLimit() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(trustResolver.userId(any())).thenReturn(42L);

        for (int i = 0; i < 5; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.32", "/api/auth/login"), response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(chain, times(5)).doFilter(any(), any());
    }


    @Test
    void authenticatedShouldBeThrottledByBurstWindow() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(trustResolver.userId(any())).thenReturn(42L);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 21; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.35", "/api/files/list"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(20)).doFilter(any(), any());
    }

    @Test
    void authenticatedShouldBeThrottledBySlidingRpm() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(trustResolver.userId(any())).thenReturn(43L);
        ReflectionTestUtils.setField(filter, "authenticatedRequestsPerMinute", 3);
        ReflectionTestUtils.setField(filter, "authenticatedBurst", 1000);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 4; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.36", "/api/files/list"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(3)).doFilter(any(), any());
    }
    @Test
    void whitelistedIpShouldBypassLimits() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        ReflectionTestUtils.setField(filter, "requestsPerMinute", 2);

        for (int i = 0; i < 5; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.33", "/api/files/list"), response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(chain, times(5)).doFilter(any(), any());
    }

    @Test
    void anonymousAuthEndpointShouldKeepStrictLimit() throws Exception {
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.34", "/api/auth/login"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(2)).doFilter(any(), any());
    }

    @Test
    void repeatedOverLimitTriggersLayer3TrapForAutomation() throws Exception {
        for (int i = 0; i < 8; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.31", "/api/files/list"), response, chain);
        }

        verify(trapService).trap(eq("203.0.113.31"), eq(3), anyString(), anyString(), any(), anyString(), eq(false));
    }

    @Test
    void browserLikeAnonymousShouldNotBeTrappedOnRepeatedOverLimit() throws Exception {
        for (int i = 0; i < 8; i++) {
            MockHttpServletRequest request = apiRequest("203.0.113.44", "/api/files/list");
            request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36");
            request.addHeader("Accept", "application/json");
            request.addHeader("Accept-Language", "zh-CN,zh;q=0.9");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
        }

        verify(trapService, never()).trap(eq("203.0.113.44"), anyInt(), anyString(), anyString(), any(), anyString(), anyBoolean());
    }

    @Test
    void twoFactorLoginShouldUseStrictAuthLimit() throws Exception {
        // IronWall v1.28.1: /api/auth/2fa/login 必须纳入认证敏感端点严格限流（防动态码穷举）
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("203.0.113.55", "/api/auth/2fa/login"), response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(chain, times(2)).doFilter(any(), any());
    }}
