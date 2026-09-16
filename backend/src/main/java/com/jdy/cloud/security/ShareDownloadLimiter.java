package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.17.3: 分享下载独立限流（防批量拉取消耗带宽 / 抓取分享数据）。
 *
 * IronWall v1.47.3 重构（闭环）：
 * 1) 计数维度改为联合桶——登录 = (账号 + share_code)，匿名 = (IP + share_code)，
 * 取消纯 IP 大桶，消除公网 NAT / 共享 IP 下正常用户被长期误伤；
 * 另保留 share_code 全局桶兜底热链。
 * 2) 超限时按窗口真实剩余时间计算 retryAfterSeconds，随 BusinessException 透出，
 * GlobalExceptionHandler 写入与事实一致的 Retry-After（修复「提示 1 分钟、实际 15 分钟)。
 * 3) 提供 snapshot()/reset(key)/resetAll()，供管理端「频控状态查看 / 手动重置」。
 */
@Slf4j
@Component
public class ShareDownloadLimiter {

    /** 计数窗口：固定 60 秒，窗口结束自动重置。 */
    public static final long WINDOW_MS = 60_000L;

    @Value("${app.security.share-download-rpm:10}")
    private int downloadsPerClientPerMinute;

    @Value("${app.security.share-download-per-code-rpm:30}")
    private int downloadsPerCodePerMinute;

    private final Map<String, Window> clientWindows = new ConcurrentHashMap<>();
    private final Map<String, Window> codeWindows = new ConcurrentHashMap<>();

    public void checkAllowed(String code, String clientIp) {
        checkAllowed(code, clientIp, false, null);
    }

    /**
     * IronWall v1.42.0: 带直链签名校验的限流。
     * 签名有效（新链接）走完整额度；缺失（历史链接）/伪造走收紧额度（原额度的 1/2，下限 2），
     * 兼容旧链接零误伤的同时压缩匿名直链被批量抓取的窗口。
     */
    public void checkAllowed(String code, String clientIp, boolean signed) {
        checkAllowed(code, clientIp, signed, null);
    }

    /**
     * IronWall v1.47.3: 联合维度入口。
     * userId 为 null 时按 (IP + share_code) 分桶；登录用户按 (账号 + share_code) 分桶。
     */
    public void checkAllowed(String code, String clientIp, boolean signed, Long userId) {
        String codeKey = normalizeCode(code);
        int clientLimit = downloadsPerClientPerMinute > 0 ? downloadsPerClientPerMinute : 10;
        int codeLimit = downloadsPerCodePerMinute > 0 ? downloadsPerCodePerMinute : 30;
        if (!signed) {
            clientLimit = Math.max(2, clientLimit / 2);
            codeLimit = Math.max(2, codeLimit / 2);
        }
        String clientKey = userId != null
                ? "user:" + userId + ":code:" + codeKey
                : "ip:" + normalizeIp(clientIp) + ":code:" + codeKey;
        check(clientWindows, clientKey, clientLimit, "下载过于频繁，请");
        check(codeWindows, codeKey, codeLimit, "该分享下载过于频繁，请");
        cleanupIfNeeded();
    }

    private void check(Map<String, Window> windows, String key, int limit, String messagePrefix) {
        Window window = windows.computeIfAbsent(key, k -> new Window());
        synchronized (window) {
            long now = System.currentTimeMillis();
            if (now - window.windowStart > WINDOW_MS) {
                window.windowStart = now;
                window.count = 0;
            }
            window.count++;
            window.lastLimit = limit;
            if (window.count > limit) {
                long retryAfter = Math.max(1L, (window.windowStart + WINDOW_MS - now + 999L) / 1000L);
                // IronWall v1.47.9: 文案与 Retry-After 精确一致（秒级），不再出现"1 分钟"与真实剩余秒数不符
                String message = messagePrefix + retryAfter + "秒后再试";
                log.warn("[IronWall] share download throttled: key={} count={}/{}s retry_after={}s",
                        key, window.count, WINDOW_MS / 1000L, retryAfter);
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), message, retryAfter,
                        Map.of("retry_after", retryAfter,
                               "window_seconds", WINDOW_MS / 1000L,
                               "limit", limit,
                               "key", key));
            }
        }
    }

    /** IronWall v1.47.3: 管理端状态查看（不泄露账号明文，仅桶键与计数）。 */
    public Map<String, Object> snapshot() {
        long now = System.currentTimeMillis();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("window_seconds", WINDOW_MS / 1000L);
        result.put("client_limit", downloadsPerClientPerMinute > 0 ? downloadsPerClientPerMinute : 10);
        result.put("code_limit", downloadsPerCodePerMinute > 0 ? downloadsPerCodePerMinute : 30);
        result.put("clients", snapshotOf(clientWindows, now));
        result.put("codes", snapshotOf(codeWindows, now));
        return result;
    }

    private List<Map<String, Object>> snapshotOf(Map<String, Window> windows, long now) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map.Entry<String, Window> entry : windows.entrySet()) {
            Window window = entry.getValue();
            synchronized (window) {
                if (now - window.windowStart > WINDOW_MS) {
                    continue;
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("key", entry.getKey());
                item.put("count", window.count);
                item.put("limit", window.lastLimit);
                item.put("reset_in_seconds", Math.max(1L,
                        (window.windowStart + WINDOW_MS - now + 999L) / 1000L));
                list.add(item);
            }
        }
        list.sort((a, b) -> Long.compare(
                (Long) b.get("reset_in_seconds"), (Long) a.get("reset_in_seconds")));
        return list;
    }

    /** IronWall v1.47.3: 按桶键重置；key 为空/未命中返回 false。 */
    public boolean reset(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String normalized = key.trim();
        if (clientWindows.remove(normalized) != null) {
            return true;
        }
        return codeWindows.remove(normalized) != null;
    }

    /** IronWall v1.47.3: 一键重置全部下载频控桶，返回清除的桶数。 */
    public int resetAll() {
        int cleared = clientWindows.size() + codeWindows.size();
        clientWindows.clear();
        codeWindows.clear();
        return cleared;
    }

    private void cleanupIfNeeded() {
        if (clientWindows.size() <= 10_000 && codeWindows.size() <= 10_000) return;
        long now = System.currentTimeMillis();
        removeStale(clientWindows, now);
        removeStale(codeWindows, now);
    }

    private void removeStale(Map<String, Window> windows, long now) {
        Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Window> entry = it.next();
            synchronized (entry.getValue()) {
                if (now - entry.getValue().windowStart > 300_000L) {
                    it.remove();
                }
            }
        }
    }

    private String normalizeIp(String ip) {
        return ip == null || ip.isBlank() ? "unknown" : ip.trim();
    }

    private String normalizeCode(String code) {
        return code == null || code.isBlank() ? "unknown" : code.trim().toLowerCase(Locale.ROOT);
    }

    private static class Window {
        long windowStart = System.currentTimeMillis();
        int count = 0;
        volatile int lastLimit = 0;
    }
}
