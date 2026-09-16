package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.38.0: 流量级行为基线——跨IP聚合观测（只告警，不封禁）。
 *
 * 时间窗口内同一 UA 摘要 / TLS 指纹 / 设备ID 在过多数量的不同 IP 上出现
 * （代理池扫描、僵尸网络探活），触发聚合告警。共享特征绝不用于封锁流量，
 * 只作为态势证据进入告警通道与面板。内存有界（键上限 512、每窗口 IP 集合上限 64），
 * 任何异常静默失败，绝不影响请求主链。
 */
@Slf4j
@Service
public class TrafficAggregationService {

    private static final int MAX_KEYS = 512;
    private static final int MAX_IPS_PER_WINDOW = 64;

    @Value("${app.security.defense-engine.aggregation.ua-ip-threshold:8}")
    private int uaIpThreshold;

    @Value("${app.security.defense-engine.aggregation.tls-ip-threshold:6}")
    private int tlsIpThreshold;

    @Value("${app.security.defense-engine.aggregation.device-ip-threshold:4}")
    private int deviceIpThreshold;

    @Value("${app.security.defense-engine.aggregation.window-ms:1800000}")
    private long windowMs;

    private final AlertNotifierService alertNotifier;
    private final Map<String, IpWindow> uaWindows = new ConcurrentHashMap<>();
    private final Map<String, IpWindow> tlsWindows = new ConcurrentHashMap<>();
    private final Map<String, IpWindow> deviceWindows = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlert = new ConcurrentHashMap<>();

    public TrafficAggregationService(AlertNotifierService alertNotifier) {
        this.alertNotifier = alertNotifier;
    }

    /** 观测一次匿名请求（仅 /api/ 调用方接入）。ip 为空忽略。 */
    public void observe(String userAgent, String tlsKey, String deviceId, String ip) {
        if (ip == null || ip.isBlank()) {
            return;
        }
        maybeTrack(uaWindows, uaIpThreshold, digest(userAgent), ip, "同UA多源聚合",
                "同一浏览器指纹在多个来源IP上出现");
        maybeTrack(tlsWindows, tlsIpThreshold, tlsKey, ip, "同TLS指纹多源聚合",
                "同一TLS会话指纹在多个来源IP上出现");
        maybeTrack(deviceWindows, deviceIpThreshold, deviceId, ip, "同设备多源聚合",
                "同一设备身份在多个来源IP上出现");
    }

    private void maybeTrack(Map<String, IpWindow> windows, int threshold, String key, String ip,
                            String alertType, String detail) {
        if (key == null || key.isBlank() || threshold <= 0) {
            return;
        }
        long now = System.currentTimeMillis();
        IpWindow window = windows.computeIfAbsent(key, k -> new IpWindow(now));
        boolean crossed;
        synchronized (window) {
            if (now - window.start > windowMs) {
                window.start = now;
                window.ips.clear();
            }
            if (window.ips.size() < MAX_IPS_PER_WINDOW) {
                window.ips.add(ip);
            }
            crossed = window.ips.size() >= threshold;
        }
        if (crossed) {
            Long last = lastAlert.get(key);
            if (last == null || now - last > windowMs) {
                lastAlert.put(key, now);
                notifyAlert(alertType, ip, detail + "，已关联 " + window.ips.size() + " 个来源IP");
            }
        }
    }

    private void notifyAlert(String type, String ip, String detail) {
        if (alertNotifier != null) {
            alertNotifier.notify(type, ip, detail);
        }
        log.warn("[IronWall] aggregation alert: type={} ip={} detail={}", type, ip, detail);
    }

    /** 面板快照：当前活跃窗口数、越过阈值的集群数。 */
    public Map<String, Object> snapshot() {
        long now = System.currentTimeMillis();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ua_clusters", clusterCount(uaWindows, uaIpThreshold, now));
        m.put("tls_clusters", clusterCount(tlsWindows, tlsIpThreshold, now));
        m.put("device_clusters", clusterCount(deviceWindows, deviceIpThreshold, now));
        m.put("tracked_keys", uaWindows.size() + tlsWindows.size() + deviceWindows.size());
        return m;
    }

    private long clusterCount(Map<String, IpWindow> windows, int threshold, long now) {
        long count = 0;
        for (IpWindow w : windows.values()) {
            if (w.start + windowMs >= now && w.ips.size() >= threshold) {
                count++;
            }
        }
        return count;
    }

    @Scheduled(fixedDelay = 600_000L, initialDelay = 300_000L)
    public void sweep() {
        long now = System.currentTimeMillis();
        sweepMap(uaWindows, now);
        sweepMap(tlsWindows, now);
        sweepMap(deviceWindows, now);
        lastAlert.entrySet().removeIf(e -> now - e.getValue() > windowMs * 2);
    }

    private void sweepMap(Map<String, IpWindow> windows, long now) {
        Iterator<Map.Entry<String, IpWindow>> it = windows.entrySet().iterator();
        while (it.hasNext()) {
            IpWindow w = it.next().getValue();
            if (now - w.start > windowMs) {
                it.remove();
            }
        }
        while (windows.size() > MAX_KEYS) {
            Iterator<String> keys = windows.keySet().iterator();
            if (!keys.hasNext()) {
                break;
            }
            windows.remove(keys.next());
        }
    }

    private static String digest(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", out[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return raw;
        }
    }

    private static final class IpWindow {
        volatile long start;
        final Set<String> ips = new HashSet<>();
        IpWindow(long start) {
            this.start = start;
        }
    }
}
