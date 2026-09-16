package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.17: canary token contract tests.
 */
class CanaryServiceTest {

    @Test
    void shouldGenerateRandomTokenWhenUnconfigured() {
        CanaryService service = new CanaryService("");
        String token = service.token();
        assertTrue(token.startsWith(CanaryService.PREFIX));
        assertTrue(token.length() > CanaryService.PREFIX.length());
    }

    @Test
    void shouldUseConfiguredTokenSuffix() {
        CanaryService service = new CanaryService("fixed-secret");
        assertEquals(CanaryService.PREFIX + "fixed-secret", service.token());
    }

    @Test
    void shouldMatchContainedToken() {
        CanaryService service = new CanaryService("fixed-secret");
        assertTrue(service.isCanaryValue("Bearer " + service.token()));
        assertTrue(service.isCanaryValue(service.token()));
        assertFalse(service.isCanaryValue("Bearer something-else"));
        assertFalse(service.isCanaryValue(null));
    }

    @Test
    void shouldDetectTokenInHeadersAndParams() {
        CanaryService service = new CanaryService("fixed-secret");

        MockHttpServletRequest auth = new MockHttpServletRequest();
        auth.addHeader("Authorization", "Bearer " + service.token());
        assertTrue(service.isCanaryPresent(auth));

        MockHttpServletRequest header = new MockHttpServletRequest();
        header.addHeader("X-Admin-Token", service.token());
        assertTrue(service.isCanaryPresent(header));

        MockHttpServletRequest param = new MockHttpServletRequest();
        param.addParameter("token", service.token());
        assertTrue(service.isCanaryPresent(param));

        MockHttpServletRequest clean = new MockHttpServletRequest();
        clean.addHeader("Authorization", "Bearer real-jwt");
        assertFalse(service.isCanaryPresent(clean));
    }
}
