package com.jdy.cloud.config;

import com.jdy.cloud.security.JwtAuthenticationFilter;
import com.jdy.cloud.security.RateLimitFilter;
import com.jdy.cloud.security.SecurityHeadersFilter;
import com.jdy.cloud.security.AttackAlertFilter;
import com.jdy.cloud.security.ApiCryptoFilter;
import com.jdy.cloud.security.CrawlerDefenseFilter;
import com.jdy.cloud.security.TarpitFilter;
import com.jdy.cloud.security.BlockedIpPageFilter;
import com.jdy.cloud.security.TrapFilter;
import com.jdy.cloud.security.UserRateLimitFilter;
import com.jdy.cloud.security.AccountDeviceTrackerFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimitFilter rateLimitFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final AttackAlertFilter attackAlertFilter;
    private final ApiCryptoFilter apiCryptoFilter;
    private final CrawlerDefenseFilter crawlerDefenseFilter;
    private final TarpitFilter tarpitFilter;
    private final BlockedIpPageFilter blockedIpPageFilter;
    private final TrapFilter trapFilter;
    private final UserRateLimitFilter userRateLimitFilter;
    private final AccountDeviceTrackerFilter accountDeviceTrackerFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/auth/login", "/api/auth/2fa/login", "/api/auth/register", "/api/auth/send-code",
                        "/api/auth/verify-code", "/api/auth/reset-password").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/auth/check-email").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/auth/announcements").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/shares/download/*").permitAll()
                // IronWall v1.12: 分享列表必须登录（先于 /api/shares/* 的通配规则）
                .requestMatchers(HttpMethod.GET, "/api/shares/list").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/shares/download-zip/*").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/shares/*").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/shares/challenge/*").permitAll()
                // IronWall v1.27.11: 公开站点信息（站点名/描述/维护公告）供首页展示
                .requestMatchers(HttpMethod.GET, "/api/site/info").permitAll()
                .requestMatchers("/api/files/ping").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/files/avatar/**").permitAll()
                // IronWall v1.17: 蜜罐诱捕路径公开可达（真实业务不存在，供扫描器触碰）
                .requestMatchers("/api/.env", "/api/config.php", "/api/phpinfo.php", "/api/server-status",
                        "/api/admin.php", "/api/phpmyadmin/index.php", "/api/actuator/env",
                        "/api/swagger-ui.html", "/api/wp-login.php", "/api/legacy/admin/login",
                        "/api/backup.sql", "/api/.git/config", "/api/honeypot/**").permitAll()
                // IronWall v1.17.4: 封禁专属警示页及自助验证/申诉/状态端点公开可达
                .requestMatchers("/api/blocked-page", "/api/blocked-page/**").permitAll()
                // IronWall v1.21 L2: 爬虫 JS 挑战入口必须匿名可达，由 CrawlerDefenseFilter 签发与校验
                .requestMatchers("/api/crawler-challenge", "/api/crawler-verify").permitAll()
                // IronWall v1.40.0: 接口加密层密钥签发入口（有挑战+指纹+限频三重门槛）
                .requestMatchers("/api/bootstrap").permitAll()
                // IronWall v1.26.2: 版本信息与更新日志公开；意见反馈公开提交（邮件通知官方邮箱）
                .requestMatchers(HttpMethod.GET, "/api/version/info").permitAll()
                .requestMatchers("/api/feedback").permitAll()
                // IronWall v1.9: 管理端路径大小写不敏感统一要求 ADMIN 角色，
                // 杜绝 /api/Admin/** 等变体绕过 URL 鉴权落入控制器
                .requestMatchers(request -> {
                    String uri = request.getRequestURI();
                    return uri != null && uri.toLowerCase(java.util.Locale.ROOT).startsWith("/api/admin/");
                }).hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(securityHeadersFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(blockedIpPageFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(trapFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(apiCryptoFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(attackAlertFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(crawlerDefenseFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(tarpitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            // IronWall v1.44.0: JWT 认证后按用户维度限速（令牌泄露换 IP 拉取也受限）
            .addFilterAfter(userRateLimitFilter, JwtAuthenticationFilter.class)
            // IronWall v1.45.0: 账号级设备指纹观察（只统计不拦截，零误伤）
            .addFilterAfter(accountDeviceTrackerFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // IronWall v1.41.0: 哈希成本 10 -> 12（存量哈希兼容，仅新密码生成变慢）
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
