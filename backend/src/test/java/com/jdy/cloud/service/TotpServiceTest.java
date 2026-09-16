package com.jdy.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.28.0: TOTP 两步验证（RFC 6238 实现正确性 + 绑定生命周期）。
 */
class TotpServiceTest {

    @TempDir
    Path tempDir;

    private TotpService newService() {
        return new TotpService(new ObjectMapper(), tempDir.resolve("totp-state.json").toString());
    }

    @Test
    void generateSecret_shouldBeBase32Of20Bytes() {
        String secret = newService().generateSecret();
        assertEquals(32, secret.length(), "20 字节密钥 Base32 编码应为 32 字符");
        assertTrue(secret.matches("[A-Z2-7]{32}"), "密钥应仅含 Base32 字符集");
    }

    @Test
    void currentCode_shouldBeSixDigits() {
        TotpService service = newService();
        String code = service.currentCode(service.generateSecret());
        assertTrue(code.matches("\\d{6}"), "动态码应为 6 位数字");
    }

    @Test
    void validate_shouldAcceptCurrentWindowAndRejectWrongCode() {
        TotpService service = newService();
        String secret = service.generateSecret();
        assertTrue(service.validate(secret, service.currentCode(secret)));
        assertFalse(service.validate(secret, "000000"));
        assertFalse(service.validate(secret, "abc123"));
    }

    @Test
    void otpauthUri_shouldContainSecretAndIssuer() {
        TotpService service = newService();
        String uri = service.otpauthUri("ABCDEFGH", "testuser");
        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("ABCDEFGH"));
        assertTrue(uri.contains("testuser"));
        assertTrue(uri.contains("digits=6"));
    }

    @Test
    void bindLifecycle_shouldEnableAfterConfirmAndDisableCleanly() {
        TotpService service = newService();
        Long uid = 7L;
        String secret = service.generateSecret();
        service.savePending(uid, secret);
        assertTrue(service.hasPending(uid));
        assertFalse(service.isEnabled(uid));

        assertTrue(service.confirm(uid, service.currentCode(secret)), "当前动态码应能确认绑定");
        assertTrue(service.isEnabled(uid));
        assertTrue(service.verifyLoginCode(uid, service.currentCode(secret)), "登录第二步应通过");
        assertFalse(service.verifyLoginCode(uid, "123456"));

        service.disable(uid);
        assertFalse(service.isEnabled(uid));
        assertFalse(service.verifyLoginCode(uid, service.currentCode(secret)));
    }

    @Test
    void verifyAndConsume_shouldRejectReplayWithinWindow() {
        TotpService service = newService();
        Long uid = 9L;
        String secret = service.generateSecret();
        service.savePending(uid, secret);
        assertTrue(service.confirm(uid, service.currentCode(secret)));
        String code = service.currentCode(secret);
        assertTrue(service.verifyAndConsumeLoginCode(uid, code), "首次使用应通过");
        assertFalse(service.verifyAndConsumeLoginCode(uid, code), "同一动态码重放应被拒绝");
        assertFalse(service.verifyAndConsumeLoginCode(uid, "000000"), "错误码不应通过");
    }
}
