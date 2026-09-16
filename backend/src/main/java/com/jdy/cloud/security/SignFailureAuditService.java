package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.41.0: 签名失败审计（只统计与告警，绝不记攻击分/封禁）。
 *
 * 设计红线：403 签名拒绝可能来自旧缓存、版本错位或真实用户设备时钟漂移，
 * 因此本服务只做每 IP 分钟滑窗计数：窗口内达到阈值时首次 WARN 告警（含 IP 与次数），
 * 供管理面板查看 sign_audit 统计块。任何情况下不调用 AttackGuardService 计分。
 */
@Slf4j
@Service
public class SignFailureAuditService {

    private static final long WINDOW_MS = 60_000L;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    @Value("${app.security.api-crypto.audit-threshold-per-minute:30}")
    private int thresholdPerMinute;

    private static class Window {
        long resetAt = System.currentTimeMillis();
        int count = 0;
        boolean alerted = false;
    }

    /** O(1) 记录一次签名拒绝；达到阈值时本窗口首次告警。 */
    public void record(String ip) {
        if (ip == null || ip.isBlank()) {
            return;
        }
        long now = System.currentTimeMillis();
        Window w = windows.computeIfAbsent(ip, k -> new Window());
        synchronized (w) {
            if (now - w.resetAt >= WINDOW_MS) {
                w.resetAt = now;
                w.count = 0;
                w.alerted = false;
            }
            w.count++;
            int threshold = thresholdPerMinute > 0 ? thresholdPerMinute : 30;
            if (!w.alerted && w.count >= threshold) {
                w.alerted = true;
                log.warn("[IronWall] SIGN-FAIL AUDIT: ip={} signRejections={} perMinute>=threshold={}",
                        ip, w.count, threshold);
            }
        }
    }

    /** 当前窗口审计统计（管理面板展示）。 */
    public Map<String, Object> stats() {
        long now = System.currentTimeMillis();
        long total = 0;
        Map<String, Integer> snapshot = new LinkedHashMap<>();
        for (Map.Entry<String, Window> e : windows.entrySet()) {
            Window w = e.getValue();
            synchronized (w) {
                if (now - w.resetAt >= WINDOW_MS) {
                    continue;
                }
                snapshot.put(e.getKey(), w.count);
                total += w.count;
            }
        }
        List<Map<String, Object>> top = new ArrayList<>();
        snapshot.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder()))
                .limit(5)
                .forEach(e -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("ip", e.getKey());
                    item.put("count", e.getValue());
                    top.add(item);
                });
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total_1m", total);
        out.put("distinct_ips_1m", snapshot.size());
        out.put("top", top);
        return out;
    }
}
