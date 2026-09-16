package com.jdy.cloud.util;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * IronWall v1.6: 统一真实客户端 IP 解析，杜绝 X-Forwarded-For / X-Real-IP 伪造绕过限流、锁定与封禁。
 *
 * 信任边界原则：
 * 1) 只有请求直接来自可信反向代理（默认本机回环，即 nginx 与后端同机部署）时才读取代理头；
 * 2) nginx 将 X-Real-IP 强制覆盖为 $remote_addr，并把真实客户端 IP 追加到 X-Forwarded-For 末位，
 * 因此可信代理场景下优先取 X-Real-IP，其次取 XFF 最后一跳，绝不取首段（客户端可伪造）；
 * 3) 直连请求（对端不是可信代理）一律忽略所有代理头，直接使用 TCP 对端地址；
 * 4) 解析失败时回退到对端地址，保证限流桶永远有稳定键值。
 */
public final class ClientIpUtils {

    private static final Pattern IP_PATTERN = Pattern.compile("^[0-9a-fA-F:.%]{3,64}$");

    private static final Set<String> DEFAULT_TRUSTED = Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1");

    private static volatile Set<String> trustedProxies = new HashSet<>(DEFAULT_TRUSTED);

    private ClientIpUtils() {
    }

    /** 由配置注入扩展可信代理（如 nginx 与后端分机部署时的内网 IP）。 */
    public static void configureTrustedProxies(String csv) {
        if (csv == null || csv.isBlank()) {
            return;
        }
        Set<String> set = new HashSet<>(DEFAULT_TRUSTED);
        for (String part : csv.split("[,;|]")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                set.add(trimmed);
            }
        }
        trustedProxies = set;
    }

    public static String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        String direct = trimToNull(request.getRemoteAddr());

        // 直连请求：对端不是可信代理，忽略一切可伪造的代理头
        if (direct != null && !isTrustedProxy(direct)) {
            return direct;
        }

        // 经由可信代理（nginx）：X-Real-IP 被 nginx 覆盖为 $remote_addr，客户端无法伪造
        String xri = trimToNull(request.getHeader("X-Real-IP"));
        if (xri != null && isValidIp(xri)) {
            return xri;
        }

        // X-Forwarded-For：nginx 使用 $proxy_add_x_forwarded_for 将真实 IP 追加到末位，
        // 首段为客户端可控值，因此从右向左取第一跳合法地址（即 nginx 追加的真实 IP）
        String xff = trimToNull(request.getHeader("X-Forwarded-For"));
        if (xff != null) {
            String[] parts = xff.split(",");
            for (int i = parts.length - 1; i >= 0; i--) {
                String candidate = trimToNull(parts[i]);
                if (candidate != null && isValidIp(candidate)) {
                    return candidate;
                }
            }
        }

        return direct != null ? direct : "unknown";
    }

    public static boolean isValidIp(String ip) {
        if (ip == null) {
            return false;
        }
        String trimmed = ip.trim();
        return !trimmed.isEmpty() && trimmed.length() <= 64 && IP_PATTERN.matcher(trimmed).matches();
    }

    public static boolean isTrustedProxy(String ip) {
        return ip != null && trustedProxies.contains(ip.trim());
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}