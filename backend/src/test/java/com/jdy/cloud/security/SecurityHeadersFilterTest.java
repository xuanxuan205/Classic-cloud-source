package com.jdy.cloud.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.7: Cookie 安全属性强制测试。
 */
class SecurityHeadersFilterTest {

    private final SecurityHeadersFilter filter = new SecurityHeadersFilter();

    private MockHttpServletResponse runThroughFilter(ServletRequest request, FilterChain chain) throws ServletException, IOException {
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(request, res, chain);
        return res;
    }

    @Test
    void addCookie_shouldForceSecureHttpOnlySameSite() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = runThroughFilter(req, (request, response) ->
                ((HttpServletResponse) response).addCookie(new Cookie("JSESSIONID", "abc123")));

        List<String> cookies = res.getHeaders("Set-Cookie");
        assertFalse(cookies.isEmpty());
        String joined = String.join(";", cookies).toLowerCase();
        assertTrue(joined.contains("secure"), joined);
        assertTrue(joined.contains("httponly"), joined);
        assertTrue(joined.contains("samesite"), joined);
    }

    @Test
    void setHeader_shouldAppendMissingFlags() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = runThroughFilter(req, (request, response) ->
                ((HttpServletResponse) response).setHeader("Set-Cookie", "JSESSIONID=abc123; HttpOnly"));

        String joined = String.join(";", res.getHeaders("Set-Cookie")).toLowerCase();
        assertTrue(joined.contains("secure"), joined);
        assertTrue(joined.contains("httponly"), joined);
        assertTrue(joined.contains("samesite"), joined);
    }

    @Test
    void alreadyHardenedCookie_shouldStayIntact() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = runThroughFilter(req, (request, response) ->
                ((HttpServletResponse) response).setHeader("Set-Cookie",
                        "JSESSIONID=abc; Secure; HttpOnly; SameSite=Lax"));

        String joined = String.join(";", res.getHeaders("Set-Cookie")).toLowerCase();
        assertEquals(1, countOccurrences(joined, "secure"));
        assertEquals(1, countOccurrences(joined, "httponly"));
        assertEquals(1, countOccurrences(joined, "samesite"));
    }

    private int countOccurrences(String text, String token) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(token, idx)) >= 0) {
            count++;
            idx += token.length();
        }
        return count;
    }
}