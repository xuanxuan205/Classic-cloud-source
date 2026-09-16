package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Pattern;

/**
 * IronWall v1.31.0: TLS 会话指纹（JA4 近似）。
 * nginx 边缘转发 X-TLS-Profile: $ssl_protocol:$ssl_cipher:$ssl_alpn_protocol，
 * 后端归一化为稳定指纹键（小写 + SHA-256 前 32 hex）。
 * 该指纹为共享特征（同版本浏览器同协议同套件），仅用于攻击 IP 的跨 IP 证据聚合，
 * 绝不按指纹封锁流量（防误封全体同版本客户端）。
 */
@Component
public class TlsProfileResolver {

    public static final String HEADER = "X-TLS-Profile";
    /** IronWall v1.33.0: 标准 JA4 头（nginx njs 未来提供），优先采信。 */
    public static final String JA4_HEADER = "X-TLS-JA4";
    /** 标准 JA4：t13d1516h2_8daaf6152771_02713d6af862 三段式；起 ALPN 段允许为空（客户端未发 ALPN 时省略该段，如 t12d280000_b75078996b15_000000000000）。 */
    private static final Pattern JA4_SHAPE =
            Pattern.compile("^t\\d{2}[di][0-9a-f]{4}[0-9a-z]{0,2}_[0-9a-f]{12}_[0-9a-f]{12}$");

    /** 读取并归一化 TLS 会话指纹；头缺失/非法返回 null。 */
    public String resolve(HttpServletRequest request) {
        if (request == null) return null;
        // IronWall v1.33.0: 标准 JA4 优先；非法/缺失回退 nginx 三字段近似
        String raw = request.getHeader(JA4_HEADER);
        if (raw == null || !looksLikeJa4(raw)) {
            raw = request.getHeader(HEADER);
        }
        if (raw == null || raw.isBlank()) return null;
        String cleaned = raw.trim();
        if (cleaned.length() < 8 || cleaned.length() > 128) return null;
        return "tls:" + sha256Hex(cleaned.toLowerCase()).substring(0, 32);
    }

    private boolean looksLikeJa4(String raw) {
        if (raw == null || raw.isBlank()) return false;
        String v = raw.trim();
        return v.length() <= 64 && JA4_SHAPE.matcher(v).find();
    }

    private String sha256Hex(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(data.hashCode());
        }
    }
}
