package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.46.0: 分享下载凭证新契约测试。
 * sig = 8 位 hex 签发时刻 + 32 位 hex HMAC（共 40 位小写 hex）；
 * HMAC 绑定 share_code|file_id|folder_id|created_at，24h 过期；
 * 缺失/错误/过期/换绑定目标一律拒绝。
 */
class ShareLinkSignerTest {

    private static final LocalDateTime CREATED = LocalDateTime.of(2026, 9, 1, 12, 0, 0);

    @Test
    void sign_returns40Hex_andVerifyRoundtrip() {
        ShareLinkSigner signer = new ShareLinkSigner("", "jwt-secret-for-test");
        String sig = signer.sign("a1b2c3d4", 20L, null, CREATED);
        assertNotNull(sig);
        assertEquals(40, sig.length());
        assertTrue(sig.matches("[0-9a-f]{40}"), "签名应为 40 位小写 hex");
        assertTrue(signer.verify("a1b2c3d4", 20L, null, CREATED, sig));
        // 大小写归一：签发为小写，校验侧按小写比对
        assertTrue(signer.verify("a1b2c3d4", 20L, null, CREATED, sig.toUpperCase()));
    }

    @Test
    void verify_rejectsForgedSignature() {
        ShareLinkSigner signer = new ShareLinkSigner("", "jwt-secret-for-test");
        String sig = signer.sign("a1b2c3d4", 20L, null, CREATED);
        char last = sig.charAt(39);
        char flip = last == '0' ? '1' : '0';
        assertFalse(signer.verify("a1b2c3d4", 20L, null, CREATED, sig.substring(0, 39) + flip), "伪造签名必须拒绝");
        assertFalse(signer.verify("a1b2c3d4", 20L, null, CREATED, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
        assertFalse(signer.verify("a1b2c3d4", 20L, null, CREATED, null), "缺失签名必须拒绝");
        assertFalse(signer.verify("a1b2c3d4", 20L, null, CREATED, "deadbeefdeadbeefdeadbeefdeadbeef"), "旧 32 位 hex 凭证必须拒绝");
    }

    @Test
    void verify_rejectsExpiredSignature() {
        ShareLinkSigner signer = new ShareLinkSigner("", "jwt-secret-for-test");
        long now = System.currentTimeMillis() / 1000L;
        // 26 小时前签发 → 已过 24h 有效期（HMAC 覆盖签发时刻，客户端无法篡改时间续期）
        String expired = signer.signAt("a1b2c3d4", 20L, null, CREATED, now - 26L * 3600L);
        assertFalse(signer.verify("a1b2c3d4", 20L, null, CREATED, expired), "过期凭证必须拒绝");
        String fresh = signer.signAt("a1b2c3d4", 20L, null, CREATED, now);
        assertTrue(signer.verify("a1b2c3d4", 20L, null, CREATED, fresh), "新鲜凭证必须通过");
    }

    @Test
    void verify_rejectsDifferentBinding() {
        ShareLinkSigner signer = new ShareLinkSigner("", "jwt-secret-for-test");
        String sig = signer.sign("a1b2c3d4", 20L, null, CREATED);
        assertFalse(signer.verify("a1b2c3d4", 21L, null, CREATED, sig), "换 fileId 绑定必须拒绝");
        assertFalse(signer.verify("other-code", 20L, null, CREATED, sig), "换分享码必须拒绝");
        assertFalse(signer.verify("a1b2c3d4", null, 7L, CREATED, sig), "换成文件夹绑定必须拒绝");
    }

    @Test
    void folderShare_bindsFolderId() {
        ShareLinkSigner signer = new ShareLinkSigner("", "jwt-secret-for-test");
        String sig = signer.sign("a1b2c3d4", null, 7L, CREATED);
        assertTrue(signer.verify("a1b2c3d4", null, 7L, CREATED, sig));
        assertFalse(signer.verify("a1b2c3d4", null, 8L, CREATED, sig));
    }

    @Test
    void configuredSecret_overridesJwtSecret() {
        ShareLinkSigner a = new ShareLinkSigner("", "s1");
        ShareLinkSigner b = new ShareLinkSigner("s2", "s1");
        String sigA = a.sign("code", 1L, null, CREATED);
        String sigB = b.sign("code", 1L, null, CREATED);
        assertFalse(sigA.equals(sigB), "独立配置的密钥应产生不同签名");
    }

    @Test
    void missingSecret_disablesSignerSafely() {
        ShareLinkSigner signer = new ShareLinkSigner("", "");
        assertFalse(signer.isEnabled());
        assertTrue(signer.sign("code", 1L, null, CREATED) == null);
        assertFalse(signer.verify("code", 1L, null, CREATED, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    }
}