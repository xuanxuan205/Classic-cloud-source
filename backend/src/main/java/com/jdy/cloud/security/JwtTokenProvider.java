package com.jdy.cloud.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final long expirationMs;

    public JwtTokenProvider(@Value("${app.jwt.secret}") String secret,
                            @Value("${app.jwt.expiration-ms:86400000}") long expirationMs) {
        // IronWall v1.41.0: 密钥强度启动校验（少于 32 字节拒绝启动，避免弱密钥上线）
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT_SECRET 强度不足：至少需要 32 字节随机密钥");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generateToken(Long userId, String username, String role) {
        return generateToken(userId, username, role, false);
    }

    public String generateToken(Long userId, String username, String role, boolean rememberMe) {
        return generateToken(userId, username, role, rememberMe, 0);
    }

    /**
     * IronWall v1.20: 令牌版本号写入 claim ver。
     * 改密 / 重置密码 / 管理员封禁时递增用户 token_version，旧 JWT 立即失效。
     */
    public String generateToken(Long userId, String username, String role, boolean rememberMe, int tokenVersion) {
        Date now = new Date();
        long expMs = expirationMs; // IronWall v1.13: remember-me no longer extends token lifetime (24h default)
        Date expiryDate = new Date(now.getTime() + expMs);

        log.info("Generating token for user={} rememberMe={} expMs={}", username, rememberMe, expMs);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("username", username)
                .claim("role", role)
                .claim("ver", tokenVersion)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = parseToken(token);
        return Long.parseLong(claims.getSubject());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.get("username", String.class);
    }

    public int getTokenVersionFromToken(String token) {
        Claims claims = parseToken(token);
        Number ver = claims.get("ver", Number.class);
        return ver != null ? ver.intValue() : 0;
    }

    public String getRoleFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.get("role", String.class);
    }

    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * IronWall v1.28.0: 两步验证中间令牌（仅用于登录第二步，5 分钟有效，不可当业务令牌使用）。
     * claim two_factor=true 与业务令牌严格区分。
     */
    public String generateTwoFactorToken(Long userId, String username) {
        return generateTwoFactorToken(userId, username, null);
    }

    /**
     * IronWall v1.40.0: 两步验证中间令牌绑定发起登录时的设备指纹哈希，
     * 第二步必须由同一设备完成（换代理 IP 不受影响，换设备则拒绝）。
     */
    public String generateTwoFactorToken(Long userId, String username, String deviceHash) {
        return Jwts.builder()
                .subject(userId.toString())
                .claim("username", username)
                .claim("two_factor", true)
                .claim("dev", deviceHash)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 5 * 60_000L))
                .signWith(key)
                .compact();
    }

    /** 取两步验证中间令牌绑定的设备哈希；旧令牌或未绑定返回 null。 */
    public String getTwoFactorDeviceHash(String token) {
        try {
            Claims claims = parseToken(token);
            return claims.get("dev", String.class);
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    /** 解析两步验证中间令牌；不是 two_factor 令牌时返回 null。 */
    public Long getTwoFactorUserId(String token) {
        try {
            Claims claims = parseToken(token);
            Object flag = claims.get("two_factor");
            if (!Boolean.TRUE.equals(flag) && !"true".equals(String.valueOf(flag))) {
                return null;
            }
            return Long.parseLong(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * IronWall v1.28.1: 判断是否为两步验证中间令牌。
     * 中间令牌仅用于 /api/auth/2fa/login，绝不允许作为业务会话令牌通过 JwtAuthenticationFilter。
     */
    public boolean isTwoFactorToken(String token) {
        try {
            Claims claims = parseToken(token);
            Object flag = claims.get("two_factor");
            return Boolean.TRUE.equals(flag) || "true".equals(String.valueOf(flag));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    public long getExpirationMs() {
        return expirationMs;
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
