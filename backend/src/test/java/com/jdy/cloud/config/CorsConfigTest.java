package com.jdy.cloud.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.47.8: 站点域名 CORS 回归门禁。
 * 线上事故根因：环境变量顶替内置白名单后漏配站点域名，浏览器 POST 全 403。
 * v1.48.0 起域名改由 app.site.domain 提供，其派生的内置项必须恒在列。
 */
class CorsConfigTest {

    private static final String SITE_DOMAIN = "example.com";

    private CorsConfig configWith(String rawOrigins) {
        CorsConfig config = new CorsConfig();
        ReflectionTestUtils.setField(config, "siteDomain", SITE_DOMAIN);
        ReflectionTestUtils.setField(config, "allowedOrigins", rawOrigins);
        return config;
    }

    private List<String> patterns(CorsConfig config) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/version/info");
        CorsConfiguration cors = config.corsConfigurationSource().getCorsConfiguration(request);
        assertNotNull(cors);
        return cors.getAllowedOriginPatterns();
    }

    @Test
    void 环境变量缺配站点域名时内置白名单仍生效() {
        List<String> patterns = patterns(configWith("http://localhost:5173,http://localhost:5174"));
        assertTrue(patterns.contains("https://example.com"));
        assertTrue(patterns.contains("https://www.example.com"));
        assertTrue(patterns.contains("http://localhost:5173"));
    }

    @Test
    void 站点域名未配置时不产生空内置项() {
        CorsConfig config = new CorsConfig();
        ReflectionTestUtils.setField(config, "siteDomain", "");
        ReflectionTestUtils.setField(config, "allowedOrigins", "http://localhost:5173");
        List<String> patterns = patterns(config);
        assertFalse(patterns.contains(""));
        assertFalse(patterns.contains("https://"));
        assertTrue(patterns.contains("http://localhost:5173"));
    }

    @Test
    void 环境变量追加而非顶替且去重() {
        List<String> patterns = patterns(configWith("https://cdn.example.com,https://example.com"));
        assertTrue(patterns.contains("https://cdn.example.com"));
        assertEquals(1, patterns.stream().filter("https://example.com"::equals).count());
    }

    @Test
    void 空值与空白片段被清洗() {
        List<String> patterns = patterns(configWith(" , https://example.com , ,"));
        assertEquals(1, patterns.stream().filter("https://example.com"::equals).count());
        assertFalse(patterns.contains(""));
    }
}
