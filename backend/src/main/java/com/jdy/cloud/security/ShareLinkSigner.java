package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * IronWall v1.46.0: 分享下载凭证强制化。
 *
 * sig = 签发时刻 epoch 秒（8 位小写 hex）+ HMAC-SHA256 摘要（32 位小写 hex），共 40 位小写 hex。
 * HMAC 消息 = share|{code}|{fileId}|{folderId}|{createdAtEpoch}
 * 单文件分享绑定 fileId，文件夹分享绑定 folderId（另一侧传 null/0）；
 * 凭证 24h 过期（SHARE_SIG_TTL_SECONDS）；
 * 缺失/错误/过期/旧版 32 位 hex 凭证一律无效，verify 恒 false，调用方统一 403（无侧信道）。
 * secret 未单独配置时自动派生自 JWT 主密钥（已强制 2048-bit，重启稳定）。
 */
@Slf4j
@Component
public class ShareLinkSigner {

    /** 下载凭证有效期：24 小时。 */
    public static final long SHARE_SIG_TTL_SECONDS = 24L * 3600L;

    private final byte[] secret;

    public ShareLinkSigner(@Value("${app.security.share-link.secret:}") String configured,
                           @Value("${app.jwt.secret:}") String jwtSecret) {
        String source = (configured != null && !configured.isBlank()) ? configured : jwtSecret;
        if (source == null || source.isBlank()) {
            this.secret = null;
            log.warn("[IronWall] share link signer disabled: no secret configured");
        } else {
            this.secret = source.getBytes(StandardCharsets.UTF_8);
        }
    }

    public boolean isEnabled() {
        return secret != null;
    }

    /** 单文件分享调用：fileId 绑定目标文件，folderId 传 null。文件夹分享反之。 */
    public String sign(String code, Long fileId, Long folderId, LocalDateTime createdAt) {
        if (!isEnabled() || code == null || code.isBlank()) {
            return null;
        }
        // 有效期从「签发时刻」计时（分享页每次加载重新换证）；HMAC 绑定分享创建时刻 + 签发时刻。
        return signAt(code, fileId, folderId, createdAt, java.time.Instant.now().getEpochSecond());
    }

    /** 包内可见：指定签发时刻（仅用于过期语义测试）。 */
    String signAt(String code, Long fileId, Long folderId, LocalDateTime createdAt, long issuedEpoch) {
        if (!isEnabled() || code == null || code.isBlank()) {
            return null;
        }
        long createdEpoch = createdAt != null
                ? createdAt.atZone(ZoneOffset.UTC).toEpochSecond()
                : 0L;
        return epochHex(issuedEpoch) + hmacHex(messageOf(code, fileId, folderId, createdEpoch, issuedEpoch));
    }

    public boolean verify(String code, Long fileId, Long folderId, LocalDateTime createdAt, String sig) {
        if (!isEnabled() || code == null || sig == null || sig.length() != 40) {
            return false;
        }
        try {
            String issuedHex = sig.substring(0, 8);
            String digest = sig.substring(8);
            long issued = Long.parseLong(issuedHex, 16);
            long now = System.currentTimeMillis() / 1000L;
            // 允许 300s 时钟偏差，其余一律按过期拒绝
            if (issued <= 0 || now - issued > SHARE_SIG_TTL_SECONDS || issued - now > 300L) {
                return false;
            }
            long epoch = createdAt != null
                    ? createdAt.atZone(ZoneOffset.UTC).toEpochSecond()
                    : 0L;
            String expected = hmacHex(messageOf(code, fileId, folderId, epoch, issued));
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    digest.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private String messageOf(String code, Long fileId, Long folderId, long createdAtEpoch, long issuedEpoch) {
        return "share|" + code.trim() + "|" + (fileId == null ? 0L : fileId)
                + "|" + (folderId == null ? 0L : folderId) + "|" + createdAtEpoch + "|" + issuedEpoch;
    }

    private static String epochHex(long epoch) {
        return String.format("%08x", epoch);
    }

    private String hmacHex(String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] out = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.substring(0, 32);
        } catch (Exception e) {
            throw new IllegalStateException("[IronWall] share link sign failed", e);
        }
    }
}