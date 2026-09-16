package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.7: 分享密码暴力爆破限频。
 * 双维计数：分享码+IP（5 次/5 分钟锁定）+ IP 全局（20 次/10 分钟锁定），
 * 密码校验成功即清零，失败落告警日志。
 */
@Slf4j
@Component
public class SharePasswordLimiter {

    private static final int FAIL_LIMIT = 5;
    private static final long WINDOW_MS = 5 * 60_000L;
    private static final long BLOCK_MS = 5 * 60_000L;

    private static final int IP_FAIL_LIMIT = 20;
    private static final long IP_WINDOW_MS = 10 * 60_000L;

    private final Map<String, Window> shareWindows = new ConcurrentHashMap<>();
    private final Map<String, Window> ipWindows = new ConcurrentHashMap<>();

    public void checkAllowed(String code, String clientIp) {
        String ipKey = normalizeIp(clientIp);

        Window ipWin = ipWindows.computeIfAbsent(ipKey, k -> new Window());
        synchronized (ipWin) {
            long now = System.currentTimeMillis();
            if (now < ipWin.blockedUntil) {
                throw tooMany();
            }
            if (now - ipWin.windowStart > IP_WINDOW_MS) {
                ipWin.windowStart = now;
                ipWin.count = 0;
            }
            if (ipWin.count >= IP_FAIL_LIMIT) {
                ipWin.blockedUntil = now + BLOCK_MS;
                ipWin.count = 0;
                throw tooMany();
            }
        }

        Window w = shareWindows.computeIfAbsent(key(code, ipKey), k -> new Window());
        synchronized (w) {
            long now = System.currentTimeMillis();
            if (now < w.blockedUntil) {
                throw tooMany();
            }
            if (now - w.windowStart > WINDOW_MS) {
                w.windowStart = now;
                w.count = 0;
            }
            if (w.count >= FAIL_LIMIT) {
                w.blockedUntil = now + BLOCK_MS;
                w.count = 0;
                throw tooMany();
            }
        }
    }

    public void recordFailure(String code, String clientIp) {
        String ipKey = normalizeIp(clientIp);
        Window ipWin = ipWindows.computeIfAbsent(ipKey, k -> new Window());
        synchronized (ipWin) {
            long now = System.currentTimeMillis();
            if (now - ipWin.windowStart > IP_WINDOW_MS) {
                ipWin.windowStart = now;
                ipWin.count = 0;
            }
            ipWin.count++;
        }
        Window w = shareWindows.computeIfAbsent(key(code, ipKey), k -> new Window());
        synchronized (w) {
            long now = System.currentTimeMillis();
            if (now - w.windowStart > WINDOW_MS) {
                w.windowStart = now;
                w.count = 0;
            }
            w.count++;
        }
        log.warn("[IronWall] share password brute-force attempt: code={} ip={}", code, ipKey);
    }

    public void clear(String code, String clientIp) {
        shareWindows.remove(key(code, normalizeIp(clientIp)));
    }

    private BusinessException tooMany() {
        return new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "密码尝试次数过多，请5分钟后再试");
    }

    private String key(String code, String ipKey) {
        return (code == null ? "" : code.trim()) + "|" + ipKey;
    }

    private String normalizeIp(String ip) {
        return ip == null || ip.isBlank() ? "unknown" : ip.trim();
    }

    private static class Window {
        long windowStart = System.currentTimeMillis();
        long blockedUntil = 0;
        int count = 0;
    }
}