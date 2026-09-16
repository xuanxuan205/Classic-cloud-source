package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.40.0: 接口加密层服务契约测试。
 * 签名往返 / 错误密钥 / 过期时间戳 / nonce 重放 / 路由地图 AES-GCM 往返。
 */
class ApiCryptoServiceTest {

    private ApiCryptoService service;

    @BeforeEach
    void setUp() {
        service = new ApiCryptoService();
        ReflectionTestUtils.setField(service, "sessionTtlHours", 24L);
        ReflectionTestUtils.setField(service, "tsWindowSeconds", 120L);
    }

    private ApiCryptoService.Session issue() {
        return service.issueSession();
    }

    @Test
    void signAndVerify_roundTrip() {
        ApiCryptoService.Session session = issue();
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String bodyHash = service.sha256Hex("{\"a\":1}");
        String sig = service.sign(session, "POST", "/api/auth/login?x=1", ts, nonce, bodyHash);
        assertTrue(service.verify(session, "POST", "/api/auth/login?x=1",
                String.valueOf(ts), nonce, bodyHash, sig));
    }

    @Test
    void verify_rejectsWrongKey() {
        ApiCryptoService.Session session = issue();
        ApiCryptoService.Session other = issue();
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = service.sign(other, "GET", "/api/files/list", ts, nonce, null);
        assertFalse(service.verify(session, "GET", "/api/files/list",
                String.valueOf(ts), nonce, null, sig));
    }

    @Test
    void verify_rejectsExpiredTimestamp() {
        ApiCryptoService.Session session = issue();
        long ts = System.currentTimeMillis() - 10 * 60_000L;
        String nonce = service.randomHex(16);
        String sig = service.sign(session, "GET", "/api/files/list", ts, nonce, null);
        assertFalse(service.verify(session, "GET", "/api/files/list",
                String.valueOf(ts), nonce, null, sig));
    }

    /** IronWall v1.43.0: 时间窗前后对称（±120s），过去/未来同等对待。 */
    @Test
    void verify_timeWindowIsSymmetric() {
        ApiCryptoService.Session session = issue();
        long now = System.currentTimeMillis();
        String noncePast = service.randomHex(16);
        long tsPast = now - 60_000L;
        String sigPast = service.sign(session, "GET", "/api/files/list", tsPast, noncePast, null);
        assertTrue(service.verify(session, "GET", "/api/files/list",
                String.valueOf(tsPast), noncePast, null, sigPast));

        String nonceFuture = service.randomHex(16);
        long tsFuture = now + 60_000L;
        String sigFuture = service.sign(session, "GET", "/api/files/list", tsFuture, nonceFuture, null);
        assertTrue(service.verify(session, "GET", "/api/files/list",
                String.valueOf(tsFuture), nonceFuture, null, sigFuture));

        String noncePastOut = service.randomHex(16);
        long tsPastOut = now - 121_000L;
        String sigPastOut = service.sign(session, "GET", "/api/files/list", tsPastOut, noncePastOut, null);
        assertFalse(service.verify(session, "GET", "/api/files/list",
                String.valueOf(tsPastOut), noncePastOut, null, sigPastOut));

        String nonceFutureOut = service.randomHex(16);
        long tsFutureOut = now + 121_000L;
        String sigFutureOut = service.sign(session, "GET", "/api/files/list", tsFutureOut, nonceFutureOut, null);
        assertFalse(service.verify(session, "GET", "/api/files/list",
                String.valueOf(tsFutureOut), nonceFutureOut, null, sigFutureOut));
    }

    @Test
    void verify_rejectsReplayedNonce() {
        ApiCryptoService.Session session = issue();
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = service.sign(session, "GET", "/api/shares/list", ts, nonce, null);
        assertTrue(service.verify(session, "GET", "/api/shares/list",
                String.valueOf(ts), nonce, null, sig));
        assertFalse(service.verify(session, "GET", "/api/shares/list",
                String.valueOf(ts), nonce, null, sig));
    }

    @Test
    void verify_rejectsTamperedPath() {
        ApiCryptoService.Session session = issue();
        long ts = System.currentTimeMillis();
        String nonce = service.randomHex(16);
        String sig = service.sign(session, "GET", "/api/files/list", ts, nonce, null);
        assertFalse(service.verify(session, "GET", "/api/admin/users",
                String.valueOf(ts), nonce, null, sig));
    }

    @Test
    void routeMap_encryptDecryptRoundTrip() throws Exception {
        ApiCryptoService.Session session = issue();
        String plain = "{\"auth/login\":\"/api/auth/login\"}";
        String payload = service.encryptRouteMap(session.key(), plain);
        int dot = payload.indexOf('.');
        byte[] nonce = Base64.getDecoder().decode(payload.substring(0, dot));
        byte[] ct = Base64.getDecoder().decode(payload.substring(dot + 1));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(session.key(), "AES"), new GCMParameterSpec(128, nonce));
        String decrypted = new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        assertTrue(decrypted.equals(plain));
    }
}
