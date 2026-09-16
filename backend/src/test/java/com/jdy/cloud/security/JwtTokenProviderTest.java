package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.28.1: 两步验证中间令牌与业务会话令牌必须严格隔离。
 * 中间令牌仅能被 /api/auth/2fa/login 消费，业务鉴权链（JwtAuthenticationFilter）必须拒绝。
 */
class JwtTokenProviderTest {

    private JwtTokenProvider newProvider() {
        return new JwtTokenProvider("0123456789abcdef0123456789abcdef0123456789abcdef", 3_600_000L);
    }

    @Test
    void twoFactorToken_shouldBeRecognizedAndYieldUserId() {
        JwtTokenProvider provider = newProvider();
        String token = provider.generateTwoFactorToken(7L, "alice");
        assertTrue(provider.isTwoFactorToken(token), "中间令牌应被识别为 two_factor");
        assertEquals(7L, provider.getTwoFactorUserId(token));
    }

    @Test
    void businessToken_shouldNotBeRecognizedAsTwoFactor() {
        JwtTokenProvider provider = newProvider();
        String token = provider.generateToken(7L, "alice", "user", false, 0);
        assertFalse(provider.isTwoFactorToken(token), "业务令牌不得被识别为两步验证令牌");
    }

    @Test
    void twoFactorToken_shouldHaveNoRoleClaim() {
        // JwtAuthenticationFilter 依赖 role 为空 + two_factor 标记双重拒绝中间令牌
        JwtTokenProvider provider = newProvider();
        String token = provider.generateTwoFactorToken(7L, "alice");
        assertNull(provider.getRoleFromToken(token), "中间令牌不得携带角色声明");
        assertEquals(0, provider.getTokenVersionFromToken(token));
    }

    @Test
    void tamperedOrExpiredToken_shouldBeRejected() {
        JwtTokenProvider provider = newProvider();
        assertFalse(provider.isTwoFactorToken("not-a-token"));
        assertFalse(provider.isTwoFactorToken(""));
        assertNull(provider.getTwoFactorUserId("garbage.token.value"));
    }

    @Test
    void twoFactorUserId_shouldRejectBusinessToken() {
        JwtTokenProvider provider = newProvider();
        String token = provider.generateToken(7L, "alice", "user", false, 0);
        assertNull(provider.getTwoFactorUserId(token), "业务令牌不能当作两步验证令牌消费");
    }

    @Test
    void weakSecret_shouldFailFast() {
        // IronWall v1.41.0: 少于 32 字节的密钥必须启动即失败
        assertThrows(IllegalArgumentException.class,
                () -> new JwtTokenProvider("short-secret", 3_600_000L));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtTokenProvider(null, 3_600_000L));
    }
}
