package com.jdy.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.28.0: TOTP 两步验证（RFC 6238，HMAC-SHA1，6 位动态码，30 秒窗口 ±1 容差）。
 * 密钥与绑定状态存于 JSON 状态文件（与 feedback/blocked-appeals 同一持久化模式），
 * 绑定必须先用当前 TOTP 码确认，关闭需验证登录密码，登录时二次校验动态码。
 */
@Slf4j
@Service
public class TotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int SECRET_BYTES = 20;
    private static final int CODE_DIGITS = 6;
    private static final long STEP_SECONDS = 30L;
    private static final String ISSUER = "经典云网盘";

    private final ObjectMapper objectMapper;
    private final String stateFile;
    private final Map<String, Object> state = new ConcurrentHashMap<>();

    @SuppressWarnings("unchecked")
    public TotpService(ObjectMapper objectMapper,
                       @Value("${app.security.totp-state-file:./logs/totp-state.json}") String stateFile) {
        this.objectMapper = objectMapper;
        this.stateFile = stateFile;
        try {
            java.nio.file.Path p = java.nio.file.Path.of(stateFile).toAbsolutePath();
            if (java.nio.file.Files.exists(p)) {
                Map<String, Object> loaded = objectMapper.readValue(java.nio.file.Files.readAllBytes(p), LinkedHashMap.class);
                if (loaded != null) state.putAll(loaded);
            }
        } catch (Exception e) {
            log.warn("[IronWall] totp state load failed, starting empty: {}", e.getMessage());
        }
    }

    /** 生成 20 字节随机密钥并 Base32 编码（无填充）。 */
    public String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        new SecureRandom().nextBytes(bytes);
        return base32Encode(bytes);
    }

    /** 当前时间窗口的 6 位动态码。 */
    public String currentCode(String secret) {
        return codeAt(secret, System.currentTimeMillis() / 1000L / STEP_SECONDS);
    }

    /** 校验动态码，允许 ±1 个时间窗口（时钟偏差容差）。 */
    public boolean validate(String secret, String code) {
        if (secret == null || secret.isBlank() || code == null || !code.trim().matches("\\d{6}")) {
            return false;
        }
        long counter = System.currentTimeMillis() / 1000L / STEP_SECONDS;
        String normalized = code.trim();
        for (long c = counter - 1; c <= counter + 1; c++) {
            if (constantEquals(codeAt(secret, c), normalized)) {
                return true;
            }
        }
        return false;
    }

    public String otpauthUri(String secret, String account) {
        String safeAccount = account == null || account.isBlank() ? "user" : account;
        return "otpauth://totp/" + ISSUER + ":" + safeAccount
                + "?secret=" + secret + "&issuer=" + ISSUER
                + "&algorithm=SHA1&digits=" + CODE_DIGITS + "&period=" + STEP_SECONDS;
    }

    /** 保存待确认密钥（setup 阶段），确认成功后转为已启用。 */
    public synchronized void savePending(Long userId, String secret) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("pending_secret", secret);
        entry.put("pending_at", System.currentTimeMillis());
        entry.put("enabled", false);
        state.put(String.valueOf(userId), entry);
        persist();
    }

    public boolean hasPending(Long userId) {
        Object entry = state.get(String.valueOf(userId));
        return entry instanceof Map && ((Map<?, ?>) entry).get("pending_secret") != null;
    }

    /** 用当前动态码确认绑定：验证通过后启用并清除待确认密钥。 */
    public synchronized boolean confirm(Long userId, String code) {
        Object entry = state.get(String.valueOf(userId));
        if (!(entry instanceof Map)) return false;
        Map<String, Object> map = (Map<String, Object>) entry;
        String pending = String.valueOf(map.get("pending_secret"));
        if (!validate(pending, code)) return false;
        Map<String, Object> enabled = new LinkedHashMap<>();
        enabled.put("secret", pending);
        enabled.put("enabled", true);
        enabled.put("bound_at", System.currentTimeMillis());
        state.put(String.valueOf(userId), enabled);
        persist();
        return true;
    }

    public boolean isEnabled(Long userId) {
        Object entry = state.get(String.valueOf(userId));
        if (!(entry instanceof Map)) return false;
        Object enabled = ((Map<?, ?>) entry).get("enabled");
        return Boolean.TRUE.equals(enabled);
    }

    /** 校验当前启用密钥的动态码（登录第二步使用）。 */
    public boolean verifyLoginCode(Long userId, String code) {
        Object entry = state.get(String.valueOf(userId));
        if (!(entry instanceof Map)) return false;
        Map<?, ?> map = (Map<?, ?>) entry;
        if (!Boolean.TRUE.equals(map.get("enabled"))) return false;
        String secret = String.valueOf(map.get("secret"));
        return validate(secret, code);
    }

    /**
     * IronWall v1.40.0: 一次性消费校验——同一动态码在 150 秒内只允许使用一次，
     * 堵住 ±1 窗口内的重放。登录第二步与关闭 2FA 均走此入口。
     */
    public synchronized boolean verifyAndConsumeLoginCode(Long userId, String code) {
        Object entry = state.get(String.valueOf(userId));
        if (!(entry instanceof Map)) return false;
        Map<?, ?> map = (Map<?, ?>) entry;
        if (!Boolean.TRUE.equals(map.get("enabled"))) return false;
        String secret = String.valueOf(map.get("secret"));
        if (!validate(secret, code)) return false;
        long now = System.currentTimeMillis();
        consumedCodes.entrySet().removeIf(e -> now - e.getValue() > CONSUMED_TTL_MS);
        String key = userId + ":" + code.trim();
        return consumedCodes.putIfAbsent(key, now) == null;
    }

    // IronWall v1.40.0: 已消费动态码集合（TTL 150s > ±1 窗口最大跨度 90s + 时钟偏差）
    private final Map<String, Long> consumedCodes = new ConcurrentHashMap<>();
    private static final long CONSUMED_TTL_MS = 150_000L;

    public synchronized void disable(Long userId) {
        state.remove(String.valueOf(userId));
        persist();
    }

    public Map<String, Object> status(Long userId) {
        Map<String, Object> out = new LinkedHashMap<>();
        Object entry = state.get(String.valueOf(userId));
        boolean enabled = entry instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) entry).get("enabled"));
        out.put("enabled", enabled);
        Object boundAt = entry instanceof Map ? ((Map<?, ?>) entry).get("bound_at") : null;
        out.put("bound_at", boundAt != null ? new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(Long.parseLong(String.valueOf(boundAt)))) : "");
        out.put("has_pending", hasPending(userId));
        return out;
    }

    private synchronized void persist() {
        try {
            java.nio.file.Path p = java.nio.file.Path.of(stateFile).toAbsolutePath();
            java.nio.file.Files.createDirectories(p.getParent());
            byte[] json = objectMapper.writeValueAsBytes(state);
            java.nio.file.Files.write(p, json);
            java.nio.file.Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception e) {
            log.error("[IronWall] totp state persist failed: {}", e.getMessage());
        }
    }

    private String codeAt(String secret, long counter) {
        try {
            byte[] key = base32Decode(secret);
            byte[] data = new byte[8];
            long value = counter;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (Exception e) {
            log.warn("[IronWall] totp code generation failed: {}", e.getMessage());
            return "000000";
        }
    }

    private boolean constantEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                sb.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            sb.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }

    private byte[] base32Decode(String input) {
        String normalized = input == null ? "" : input.toUpperCase().replaceAll("[^A-Z2-7]", "");
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : normalized.toCharArray()) {
            int value = BASE32_ALPHABET.indexOf(c);
            if (value < 0) continue;
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
