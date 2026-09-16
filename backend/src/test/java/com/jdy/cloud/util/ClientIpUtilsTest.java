package com.jdy.cloud.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.6: 真实 IP 解析单元测试。
 */
class ClientIpUtilsTest {

    @Test
    void trustedProxy_shouldReturnXRealIp_first() {
        ClientIpUtils.configureTrustedProxies("127.0.0.1,::1");
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("X-Real-IP", "198.51.100.33");
        req.addHeader("X-Forwarded-For", "7.7.7.1, 198.51.100.33");

        assertEquals("198.51.100.33", ClientIpUtils.getClientIp(req));
    }

    @Test
    void trustedProxy_withoutXRealIp_shouldUseLastXffHop() {
        ClientIpUtils.configureTrustedProxies("127.0.0.1,::1");
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 198.51.100.33");

        assertEquals("198.51.100.33", ClientIpUtils.getClientIp(req));
    }

    @Test
    void untrustedPeer_shouldIgnoreAllProxyHeaders() {
        ClientIpUtils.configureTrustedProxies("127.0.0.1,::1");
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("8.8.8.8");
        req.addHeader("X-Real-IP", "1.2.3.4");
        req.addHeader("X-Forwarded-For", "5.5.5.5, 6.6.6.6");

        assertEquals("8.8.8.8", ClientIpUtils.getClientIp(req));
    }

    @Test
    void invalidHeaders_shouldFallbackToPeer() {
        ClientIpUtils.configureTrustedProxies("127.0.0.1,::1");
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("X-Real-IP", "not-an-ip");
        req.addHeader("X-Forwarded-For", "<script>alert(1)</script>");

        assertEquals("127.0.0.1", ClientIpUtils.getClientIp(req));
    }

    @Test
    void rotatingXff_shouldAlwaysResolveSameRealIp() {
        ClientIpUtils.configureTrustedProxies("127.0.0.1,::1");
        for (int i = 1; i <= 10; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.setRemoteAddr("127.0.0.1");
            req.addHeader("X-Real-IP", "198.51.100.33");
            req.addHeader("X-Forwarded-For", "7.7.7." + i + ", 198.51.100.33");
            assertEquals("198.51.100.33", ClientIpUtils.getClientIp(req));
        }
    }

    @Test
    void nullRequest_shouldReturnUnknown() {
        assertEquals("unknown", ClientIpUtils.getClientIp(null));
    }
}