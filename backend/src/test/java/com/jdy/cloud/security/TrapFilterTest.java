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
 * IronWall v1.21: 五层黑洞陷阱过滤器契约测试（只有入口，没有出口）。
 */
@ExtendWith(MockitoExtension.class)
class TrapFilterTest {

    @Mock
    private TrapService trapService;
    @Mock
    private AttackGuardService attackGuardService;
    @Mock
    private RequestTrustResolver trustResolver;
    @Mock
    private FilterChain chain;

    private TrapFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TrapFilter(trapService, attackGuardService, trustResolver);
        ReflectionTestUtils.setField(filter, "trapDelayMs", 0L);
        ReflectionTestUtils.setField(filter, "maxConcurrent", 4);
        when(trapService.isEnabled()).thenReturn(true);
        when(attackGuardService.isEnabled()).thenReturn(true);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
    }

    @Test
    void trappedIpIsSwallowedWith429() throws Exception {
        when(trapService.isTrapped("203.0.113.60")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.60");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("true", response.getHeader(TrapService.TRAP_HEADER));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void blockedPageStaysReachableForTrappedIp() throws Exception {
        when(trapService.isTrapped("203.0.113.61")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", BlockedIpPageFilter.BLOCKED_PAGE_PATH);
        request.setRemoteAddr("203.0.113.61");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void whitelistedIpEscapesTrap() throws Exception {
        when(trapService.isTrapped("203.0.113.62")).thenReturn(true);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.62");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void untrappedIpPassesThrough() throws Exception {
        when(trapService.isTrapped("203.0.113.63")).thenReturn(false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.63");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void failOpenWhenServiceThrows() throws Exception {
        when(trapService.isTrapped(anyString())).thenThrow(new RuntimeException("boom"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.64");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}