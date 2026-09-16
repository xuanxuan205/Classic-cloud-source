package com.jdy.cloud.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 密码护航安全引擎
 * 挑战-应答机制：每次密码传输前获取一次性令牌
 * 前端发送 SHA256(token + password) 代替明文密码
 * 防止中间人抓包、重放攻击
 */
@Slf4j
@Service
public class PasswordGuardService {

    // IronWall v1.28.9: 分享密码服务端只存加盐哈希，不再保存明文。
    // 存储格式：sha256$<hex>，hex = SHA256("jdy-share:" + shareCode + ":" + password)
    // 前端计算 inner = SHA256(salt)，再随一次性令牌计算 pwHash = SHA256(token + inner)。
    public static final String SHARE_PW_SALT = "jdy-share:";
    public static final String SHARE_PW_HASH_PREFIX = "sha256$";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long TOKEN_TTL_MS = 5 * 60 * 1000; // 5分钟有效期
    private static final int TOKEN_LENGTH = 32;

    // 令牌存储：token -> (shareCode, expiresAt)
    private final Map<String, TokenEntry> tokenStore = new ConcurrentHashMap<>();

    public PasswordGuardService() {
        // 每分钟清理过期令牌
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "pw-guard-cleaner");
            t.setDaemon(true);
            return t;
        }).scheduleAtFixedRate(this::cleanExpired, 1, 1, TimeUnit.MINUTES);
    }

    /**
     * 生成一次性挑战令牌
     */
    public ChallengeResponse generateChallenge(String shareCode) {
        byte[] bytes = new byte[TOKEN_LENGTH];
        SECURE_RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        long expiresAt = System.currentTimeMillis() + TOKEN_TTL_MS;

        tokenStore.put(token, new TokenEntry(shareCode, expiresAt));
        log.info("PasswordGuard: generated challenge for share={} token={} expiresIn=5min", shareCode, token.substring(0, 8) + "...");

        return new ChallengeResponse(token, expiresAt);
    }

    /**
     * 验证密码哈希（挑战-应答）
     * @param shareCode 分享码
     * @param token 挑战令牌
     * @param pwHash 前端计算的 SHA256(token + password)
     * @param storedPassword 数据库中的密码
     * @return true 密码正确
     */
    public boolean verifyChallenge(String shareCode, String token, String pwHash, String storedPassword) {
        // 1. 验证令牌是否存在且未过期
        TokenEntry entry = tokenStore.get(token);
        if (entry == null) {
            log.warn("PasswordGuard: token not found or already used: {}", token.substring(0, Math.min(8, token.length())) + "...");
            return false;
        }

        if (System.currentTimeMillis() > entry.expiresAt) {
            tokenStore.remove(token);
            log.warn("PasswordGuard: token expired for share={}", shareCode);
            return false;
        }

        // 2. 验证 shareCode 匹配
        if (!entry.shareCode.equals(shareCode)) {
            tokenStore.remove(token);
            log.warn("PasswordGuard: shareCode mismatch, expected={} got={}", entry.shareCode, shareCode);
            return false;
        }

        // 3. 计算 SHA256(token + 密码材料) 并比较
        // 新版材料为内层哈希（sha256$ 前缀），旧数据为明文，兼容两代协议
        String material = storedPassword == null ? "" : storedPassword;
        if (material.startsWith(SHARE_PW_HASH_PREFIX)) {
            material = material.substring(SHARE_PW_HASH_PREFIX.length());
        }
        String expectedHash = sha256(token + material);
        boolean match = expectedHash.equalsIgnoreCase(pwHash);

        // 4. 令牌一次性使用，立即销毁
        tokenStore.remove(token);

        if (match) {
            log.info("PasswordGuard: challenge verified OK for share={}", shareCode);
        } else {
            log.warn("PasswordGuard: challenge verification FAILED for share={}", shareCode);
        }

        return match;
    }

    /**
     * IronWall v1.28.9: 生成分享密码的存储哈希。
     * shareCode 作为盐的一部分，防止同密码不同分享产生相同哈希。
     */
    public static String hashSharePassword(String shareCode, String password) {
        return SHARE_PW_HASH_PREFIX + sha256(SHARE_PW_SALT + shareCode + ":" + password);
    }

    /**
     * SHA256 哈希
     */
    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA256 failed", e);
        }
    }

    private void cleanExpired() {
        long now = System.currentTimeMillis();
        tokenStore.entrySet().removeIf(e -> e.getValue().expiresAt < now);
        if (!tokenStore.isEmpty()) {
            log.debug("PasswordGuard: {} active tokens", tokenStore.size());
        }
    }

    // ---- 数据类 ----

    public static class ChallengeResponse {
        public String token;
        public long expiresAt;
        public long ttlSeconds;

        public ChallengeResponse(String token, long expiresAt) {
            this.token = token;
            this.expiresAt = expiresAt;
            this.ttlSeconds = (expiresAt - System.currentTimeMillis()) / 1000;
        }
    }

    private static class TokenEntry {
        final String shareCode;
        final long expiresAt;

        TokenEntry(String shareCode, long expiresAt) {
            this.shareCode = shareCode;
            this.expiresAt = expiresAt;
        }
    }
}
