package com.jdy.cloud.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

@Configuration
public class CorsConfig {

    /**
     * 内置白名单由 {@code app.site.domain} 派生，站点域名不在源码中硬编码。
     *
     * <p>安全语义：内置项永远在列，环境变量只做加法，
     * 运维漏配域名不会导致带 Origin 的写接口被 CORS 拒绝。
     */
    @Value("${app.site.domain:}")
    private String siteDomain;

    /** 内置放行来源：站点域名（正/带 www）与本地开发端口。 */
    private List<String> builtinOriginPatterns() {
        List<String> out = new ArrayList<>();
        if (siteDomain != null && !siteDomain.isBlank()) {
            String domain = siteDomain.trim();
            out.add("https://" + domain);
            out.add("https://www." + domain);
        }
        out.add("http://localhost:5173");
        out.add("http://localhost:5174");
        return out;
    }

    // 额外放行来源由部署者在 .env 的 CORS_ALLOWED_ORIGINS 中填写。
    // 前端与后端同源部署时无需配置 CORS；本地开发默认放行 Vite 端口。
    @Value("${app.cors.allowed-origins:http://localhost:5173,http://localhost:5174}")
    private String allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(allowedOriginPatterns());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization", "Content-Disposition"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * IronWall v1.47.8: 内置白名单与 CORS_ALLOWED_ORIGINS 取并集（去重、保序）。
     * 内置项永远在列，环境变量只做加法——运维漏配生产域名不再造成写接口 403。
     */
    private List<String> allowedOriginPatterns() {
        LinkedHashSet<String> merged = new LinkedHashSet<>(builtinOriginPatterns());
        Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(merged::add);
        return List.copyOf(merged);
    }
}
