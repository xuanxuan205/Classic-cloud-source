package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * IronWall v1.40.0: API 加密层会话密钥 / 签名 / 防重放服务。
 *
 * 职责：
 * 1) 签发会话密钥（sid + 32 字节随机密钥，24h TTL，内存有界）；
 * 2) HMAC-SHA256 请求签名与校验（method|path[?query]|ts|nonce[|bodyHash]）；
 * 3) nonce 一次性消费（防重放，每会话 LRU）；
 * 4) AES-GCM 加密路由地图（前端 WebCrypto 解密，隐藏真实接口路径）。
 *
 * 设计红线：
 * 热路径 O(1) 哈希查找，零锁竞争（ConcurrentHashMap）；
 * 校验失败只拒绝请求、绝不记攻击分（防旧缓存/版本错位误伤真实用户）；
 * 任何内部异常按「校验失败」处理，不抛到调用方导致 500。
 */
@Slf4j
@Service
public class ApiCryptoService {

    public static final String HEADER_SID = "X-Api-Sid";
    public static final String HEADER_TS = "X-Api-Ts";
    public static final String HEADER_NONCE = "X-Api-Nonce";
    public static final String HEADER_SIG = "X-Api-Sig";

    private static final int MAX_SESSIONS = 50_000;
    private static final int NONCE_LRU_PER_SESSION = 2048;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Long>> nonceCache = new ConcurrentHashMap<>();

    @Value("${app.security.api-crypto.session-ttl-hours:24}")
    private long sessionTtlHours;
    @Value("${app.security.api-crypto.ts-window-seconds:120}")
    private long tsWindowSeconds;

    /**
     * IronWall v1.41.0: tlsProfile 为签发会话时绑定的边缘 TLS 指纹哈希
     * （TlsProfileResolver 归一化结果）；null 表示边缘未提供指纹，比对自动跳过。
     */
    public record Session(String sid, byte[] key, long createdAt, AtomicLong lastSeenAt, String tlsProfile) {
    }

    /** 签发新会话：16 hex sid + 32 字节随机密钥。 */
    public Session issueSession() {
        return issueSession(null);
    }

    /** 签发新会话并绑定边缘 TLS 指纹（null 表示不绑定）。 */
    public Session issueSession(String tlsProfile) {
        if (sessions.size() >= MAX_SESSIONS) {
            expireStaleSessions();
        }
        String sid = randomHex(16);
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        long now = System.currentTimeMillis();
        Session session = new Session(sid, key, now, new AtomicLong(now), tlsProfile);
        sessions.put(sid, session);
        return session;
    }

    /** 查找并续期会话；过期或不存在返回 null。 */
    public Session findSession(String sid) {
        if (sid == null || sid.isBlank()) {
            return null;
        }
        Session session = sessions.get(sid);
        if (session == null) {
            return null;
        }
        long now = System.currentTimeMillis();
        long ttlMs = sessionTtlHours * 3600_000L;
        if (now - session.createdAt > ttlMs || now - session.lastSeenAt().get() > ttlMs) {
            sessions.remove(sid, session);
            nonceCache.remove(sid);
            return null;
        }
        session.lastSeenAt().set(now);
        return session;
    }

    /** 签名：method|path[?query]|ts|nonce[|bodyHash]。 */
    public String sign(Session session, String method, String pathWithQuery, long ts, String nonce, String bodyHash) {
        String data = method + "|" + pathWithQuery + "|" + ts + "|" + nonce
                + (bodyHash != null ? "|" + bodyHash : "");
        return hmacHex(session.key(), data);
    }

    /** 校验签名并消费 nonce（防重放）。任何一步失败返回 false，不抛出异常。 */
    public boolean verify(Session session, String method, String pathWithQuery,
                          String tsRaw, String nonceRaw, String bodyHash, String sig) {
        try {
            if (session == null || method == null || pathWithQuery == null
                    || tsRaw == null || nonceRaw == null || sig == null) {
                return false;
            }
            long ts = Long.parseLong(tsRaw.trim());
            long now = System.currentTimeMillis();
            if (Math.abs(now - ts) > tsWindowSeconds * 1000L) {
                return false;
            }
            String nonce = nonceRaw.trim();
            if (!nonce.matches("[0-9a-fA-F]{8,64}")) {
                return false;
            }
            String expected = sign(session, method, pathWithQuery, ts, nonce, bodyHash);
            if (!constantEquals(expected, sig.trim())) {
                return false;
            }
            return consumeNonce(session.sid(), nonce);
        } catch (Exception e) {
            log.warn("[IronWall] api signature verify failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean consumeNonce(String sid, String nonce) {
        Map<String, Long> used = nonceCache.computeIfAbsent(sid, k -> new ConcurrentHashMap<>());
        if (used.size() >= NONCE_LRU_PER_SESSION) {
            long now = System.currentTimeMillis();
            used.entrySet().removeIf(e -> now - e.getValue() > tsWindowSeconds * 2L * 1000L);
            if (used.size() >= NONCE_LRU_PER_SESSION) {
                used.clear();
            }
        }
        return used.putIfAbsent(nonce, System.currentTimeMillis()) == null;
    }

    /** AES-GCM 加密路由地图，返回 "nonce12.cipher"（均 base64）。 */
    public String encryptRouteMap(byte[] key, String plainJson) {
        try {
            byte[] nonce = new byte[12];
            secureRandom.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            byte[] ct = cipher.doFinal(plainJson.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(nonce) + "." + Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("[IronWall] route map encrypt failed", e);
        }
    }

    /** SHA-256 hex（请求体哈希 / 设备指纹哈希复用）。 */
    public String sha256Hex(String data) {
        return sha256Hex(data.getBytes(StandardCharsets.UTF_8));
    }

    public String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("[IronWall] sha256 failed", e);
        }
    }

    public boolean constantEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    public String randomHex(int length) {
        byte[] bytes = new byte[length / 2];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(length);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String hmacHex(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("[IronWall] hmac failed", e);
        }
    }

    public long getSessionTtlHours() {
        return sessionTtlHours;
    }

    private void expireStaleSessions() {
        long now = System.currentTimeMillis();
        long ttlMs = sessionTtlHours * 3600_000L;
        sessions.entrySet().removeIf(e -> {
            Session s = e.getValue();
            boolean stale = now - s.createdAt > ttlMs || now - s.lastSeenAt().get() > ttlMs;
            if (stale) {
                nonceCache.remove(s.sid());
            }
            return stale;
        });
    }
}
