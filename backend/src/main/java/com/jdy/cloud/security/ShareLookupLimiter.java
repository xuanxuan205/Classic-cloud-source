package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.12: 分享码枚举限速。
 * 匿名可访问的分享码查询/下载/挑战端点按真实 IP 限频（默认 30 次/分钟），
 * 超限直接 429，阻断扫描器批量枚举 8 位分享码（今日已在利用的攻击面）。
 */
@Slf4j
@Component
public class ShareLookupLimiter {

    @Value("${app.security.share-lookup-rpm:30}")
    private int lookupsPerMinute;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public void checkAllowed(String clientIp) {
        int limit = lookupsPerMinute > 0 ? lookupsPerMinute : 30;
        String ip = normalizeIp(clientIp);
        Window window = windows.computeIfAbsent(ip, k -> new Window());
        synchronized (window) {
            long now = System.currentTimeMillis();
            if (now - window.windowStart > 60_000L) {
                window.windowStart = now;
                window.count = 0;
            }
            window.count++;
            if (window.count > limit) {
                log.warn("[IronWall] share-code enumeration throttled: ip={} count={}/min", ip, window.count);
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "分享码访问过于频繁，请1分钟后再试");
            }
        }
    }

    private String normalizeIp(String ip) {
        return ip == null || ip.isBlank() ? "unknown" : ip.trim();
    }

    private static class Window {
        long windowStart = System.currentTimeMillis();
        int count = 0;
    }
}