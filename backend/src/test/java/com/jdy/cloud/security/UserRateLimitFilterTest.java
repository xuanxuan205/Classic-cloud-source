package com.jdy.cloud.security;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.44.0: 认证用户级限速契约测试。
 */
class UserRateLimitFilterTest {

    private UserRateLimitFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        filter = new UserRateLimitFilter();
        setField("enabled", true);
        setField("maxPerMinute", 5);
        setField("retryAfterSeconds", 30);
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest apiRequest(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        return request;
    }

    private void authAs(Long userId, String role) {
        UserPrincipal principal = new UserPrincipal(userId, "user" + userId, role);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null,
                        java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority(
                                "admin".equalsIgnoreCase(role) ? "ROLE_ADMIN" : "ROLE_USER"))));
    }

    @Test
    void anonymousRequest_shouldPassThrough() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(apiRequest("/api/files/list"), new MockHttpServletResponse(), chain);
        assertNotNull(chain.getRequest());
    }

    @Test
    void adminRequest_shouldBeExempt() throws Exception {
        authAs(999L, "admin");
        for (int i = 0; i < 10; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("/api/admin/security/summary"), response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void overLimit_shouldReturn429WithRetryAfter() throws Exception {
        authAs(1L, "user");
        MockHttpServletResponse response = new MockHttpServletResponse();
        for (int i = 0; i < 5; i++) {
            response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("/api/files/list"), response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }
        response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("/api/files/list"), response, new MockFilterChain());
        assertEquals(429, response.getStatus());
        assertEquals("30", response.getHeader("Retry-After"));
        assertTrue(response.getContentAsString().contains("请求过于频繁"));
    }

    @Test
    void blockedPagePath_shouldBeExempt() throws Exception {
        authAs(1L, "user");
        for (int i = 0; i < 12; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("/api/blocked-page/status"), response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void windowReset_shouldAllowAgain() throws Exception {
        authAs(2L, "user");
        MockHttpServletResponse response = new MockHttpServletResponse();
        for (int i = 0; i < 6; i++) {
            response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("/api/files/storage"), response, new MockFilterChain());
        }
        assertEquals(429, response.getStatus());
        // 回拨窗口起始时间，模拟 60s 滚动后自动恢复
        Object window = reflectWindows().get(2L);
        assertNotNull(window);
        var ws = window.getClass().getDeclaredField("windowStart");
        ws.setAccessible(true);
        ws.setLong(window, System.currentTimeMillis() - 61_000L);
        response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("/api/files/storage"), response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }

    @Test
    void stats_shouldReportCounters() throws Exception {
        authAs(3L, "user");
        MockHttpServletResponse response = new MockHttpServletResponse();
        for (int i = 0; i < 7; i++) {
            response = new MockHttpServletResponse();
            filter.doFilter(apiRequest("/api/files/recycle"), response, new MockFilterChain());
        }
        assertEquals(429, response.getStatus());
        Map<String, Object> stats = filter.stats();
        assertEquals(true, stats.get("enabled"));
        assertEquals(5, stats.get("max_requests_per_minute"));
        assertTrue(((Number) stats.get("limited_total")).longValue() >= 1);
    }

    private void setField(String name, Object value) throws Exception {
        var field = UserRateLimitFilter.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(filter, value);
    }

    @SuppressWarnings("unchecked")
    private Map<Long, Object> reflectWindows() throws Exception {
        var field = UserRateLimitFilter.class.getDeclaredField("windows");
        field.setAccessible(true);
        return (Map<Long, Object>) field.get(filter);
    }
}
