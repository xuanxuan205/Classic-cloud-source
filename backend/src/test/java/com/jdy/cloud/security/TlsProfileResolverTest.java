package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.31.0: TLS 会话指纹（JA4 近似）归一化测试。
 * nginx 转发 X-TLS-Profile: $ssl_protocol:$ssl_cipher:$ssl_alpn_protocol，
 * 后端归一化为稳定指纹键（小写 + SHA-256 前 32 hex）。
 */
class TlsProfileResolverTest {

    private final TlsProfileResolver resolver = new TlsProfileResolver();

    @Test
    void resolve_shouldNormalizeHeaderToStableKey() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.addHeader(TlsProfileResolver.HEADER, "TLSv1.3:TLS_AES_128_GCM_SHA256:h2");
        String key = resolver.resolve(request);
        assertNotNull(key);
        assertTrue(key.startsWith("tls:"), "指纹键应以 tls: 前缀归一化: " + key);
        assertEquals(36, key.length(), "tls: + 32 hex 应为 36 字符");
        assertEquals(key, resolver.resolve(request), "同一头两次解析应稳定一致");

        MockHttpServletRequest upper = new MockHttpServletRequest("GET", "/api");
        upper.addHeader(TlsProfileResolver.HEADER, "TLSV1.3:TLS_AES_128_GCM_SHA256:H2");
        assertEquals(key, resolver.resolve(upper), "大小写差异应归一化为同一指纹");
    }

    @Test
    void resolve_shouldReturnNullForMissingBlankOrMalformed() {
        MockHttpServletRequest missing = new MockHttpServletRequest("GET", "/api");
        assertNull(resolver.resolve(missing), "头缺失应返回 null");

        MockHttpServletRequest blank = new MockHttpServletRequest("GET", "/api");
        blank.addHeader(TlsProfileResolver.HEADER, "   ");
        assertNull(resolver.resolve(blank), "空白头应返回 null");

        MockHttpServletRequest shortVal = new MockHttpServletRequest("GET", "/api");
        shortVal.addHeader(TlsProfileResolver.HEADER, "x");
        assertNull(resolver.resolve(shortVal), "过短头应返回 null");

        MockHttpServletRequest longVal = new MockHttpServletRequest("GET", "/api");
        longVal.addHeader(TlsProfileResolver.HEADER, "a".repeat(200));
        assertNull(resolver.resolve(longVal), "过长头应返回 null");

        assertNull(resolver.resolve(null), "null 请求应返回 null");
    }

    // ===== IronWall v1.33.0: 标准 JA4 头优先，非法回退 =====

    @Test
    void resolve_shouldPreferStandardJa4HeaderWhenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.addHeader(TlsProfileResolver.JA4_HEADER, "t13d1516h2_8daaf6152771_02713d6af862");
        request.addHeader(TlsProfileResolver.HEADER, "TLSv1.3:TLS_AES_128_GCM_SHA256:h2");
        String key = resolver.resolve(request);
        assertNotNull(key);
        assertTrue(key.startsWith("tls:"));
        assertEquals(36, key.length());

        MockHttpServletRequest ja4Only = new MockHttpServletRequest("GET", "/api");
        ja4Only.addHeader(TlsProfileResolver.JA4_HEADER, "t13d1516h2_8daaf6152771_02713d6af862");
        assertEquals(key, resolver.resolve(ja4Only), "同 JA4 两次解析应稳定一致");
    }

    @Test
    void resolve_shouldAcceptJa4WithoutAlpnSegment() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
        request.addHeader(TlsProfileResolver.JA4_HEADER, "t12d280000_b75078996b15_000000000000");
        request.addHeader(TlsProfileResolver.HEADER, "TLSv1.2:OTHER-CIPHER:h2");
        String key = resolver.resolve(request);
        assertNotNull(key);
        assertTrue(key.startsWith("tls:"));
        assertEquals(36, key.length());

        MockHttpServletRequest ja4Only = new MockHttpServletRequest("GET", "/api");
        ja4Only.addHeader(TlsProfileResolver.JA4_HEADER, "t12d280000_b75078996b15_000000000000");
        assertEquals(key, resolver.resolve(ja4Only), "无 ALPN 段的 JA4 应被采信并稳定归一");
    }

    @Test
    void resolve_shouldFallbackToProfileHeaderForInvalidJa4() {
        MockHttpServletRequest invalid = new MockHttpServletRequest("GET", "/api");
        invalid.addHeader(TlsProfileResolver.JA4_HEADER, "not-a-ja4");
        invalid.addHeader(TlsProfileResolver.HEADER, "TLSv1.3:TLS_AES_128_GCM_SHA256:h2");
        MockHttpServletRequest plain = new MockHttpServletRequest("GET", "/api");
        plain.addHeader(TlsProfileResolver.HEADER, "TLSv1.3:TLS_AES_128_GCM_SHA256:h2");
        assertEquals(resolver.resolve(plain), resolver.resolve(invalid), "非法 JA4 应回退 X-TLS-Profile");
    }
}
