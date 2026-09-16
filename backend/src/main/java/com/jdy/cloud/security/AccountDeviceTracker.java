package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * IronWall v1.45.0: 账号级设备指纹追踪（观察模式，零误伤）。
 *
 * 定位：设备指纹仍为客户端自报（遗留「可伪造)，但账号维度的「多指纹 / 多 TLS 画像
 * 并存」是凭据共享、令牌被盗或会话被异地复用时的强信号。本组件只观察统计、绝不自动封禁——
 * 数据供管理员面板展示与事后取证，自动处置仍由既有登录审计与异地登录提醒负责。
 *
 * 零误伤设计：
 * 只读内存、永不抛异常、永不拦截请求（过滤器保证链必然继续）；
 * 指纹/TLS 缺失时不记入集合（自报数据可伪造，只做弱信号）；
 * 单账号指纹/TLS 集合封顶 8 个，全局账号数封顶 5000，超限丢最旧（内存有界）；
 * 7 天未见活动自动过期清理。
 */
@Slf4j
@Component
public class AccountDeviceTracker {

    public static final int MAX_TRACKED_ACCOUNTS = 5000;
    private static final int MAX_KEYS_PER_ACCOUNT = 8;
    private static final int MAX_ALERTS = 200;
    private static final long EVICT_AFTER_MS = 7L * 24 * 3600_000L;

    private final Map<Long, Profile> profiles = new ConcurrentHashMap<>();
    private final List<Map<String, Object>> recentAlerts =
            Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong totalObservations = new AtomicLong();
    private final AtomicLong multiFingerprintAlerts = new AtomicLong();
    private final AtomicLong multiTlsAlerts = new AtomicLong();

    /** 由过滤器在认证链后调用；任何异常都被吞掉，绝不影响请求。 */
    public void observe(Long userId, String username, String fingerprint, String tlsProfile, String ip) {
        if (userId == null) {
            return;
        }
        try {
            totalObservations.incrementAndGet();
            Profile profile = profiles.computeIfAbsent(userId, k -> new Profile(userId, username));
            profile.lastSeen = System.currentTimeMillis();
            profile.username = username == null ? profile.username : username;

            String fpKey = fingerprint == null || fingerprint.isBlank() ? null : "fp:" + fingerprint.trim();
            String tlsKey = tlsProfile == null || tlsProfile.isBlank() ? null : "tls:" + tlsProfile.trim();
            String ipKey = ip == null || ip.isBlank() ? null : "ip:" + ip.trim();

            boolean newFp = fpKey != null && addIfAbsentBounded(profile.fingerprintKeys, fpKey);
            boolean newTls = tlsKey != null && addIfAbsentBounded(profile.tlsKeys, tlsKey);
            if (ipKey != null) {
                addIfAbsentBounded(profile.ipKeys, ipKey);
            }

            if (newFp && profile.fingerprintKeys.size() > 1) {
                multiFingerprintAlerts.incrementAndGet();
                recordAlert(userId, profile.username, "multi_fingerprint",
                        new ArrayList<>(profile.fingerprintKeys), new ArrayList<>(profile.tlsKeys));
            }
            if (newTls && profile.tlsKeys.size() > 1) {
                multiTlsAlerts.incrementAndGet();
                recordAlert(userId, profile.username, "multi_tls",
                        new ArrayList<>(profile.fingerprintKeys), new ArrayList<>(profile.tlsKeys));
            }
            enforceGlobalCap();
        } catch (Exception e) {
            log.debug("[IronWall] account device tracking skipped: {}", e.getMessage());
        }
    }

    private boolean addIfAbsentBounded(Set<String> set, String key) {
        if (set.contains(key)) {
            return false;
        }
        synchronized (set) {
            if (set.contains(key)) {
                return false;
            }
            if (set.size() >= MAX_KEYS_PER_ACCOUNT) {
                set.remove(set.iterator().next());
            }
            return set.add(key);
        }
    }

    private void recordAlert(Long userId, String username, String kind,
                             List<String> fpKeys, List<String> tlsKeys) {
        Map<String, Object> alert = new LinkedHashMap<>();
        alert.put("time", System.currentTimeMillis());
        alert.put("user_id", userId);
        alert.put("username", username);
        alert.put("kind", kind);
        alert.put("fingerprints", fpKeys);
        alert.put("tls_profiles", tlsKeys);
        synchronized (recentAlerts) {
            recentAlerts.add(alert);
            while (recentAlerts.size() > MAX_ALERTS) {
                recentAlerts.remove(0);
            }
        }
    }

    /** 全局账号数封顶：超出上限 10% 时按最近活跃时间丢最旧。 */
    private void enforceGlobalCap() {
        if (profiles.size() <= MAX_TRACKED_ACCOUNTS) {
            return;
        }
        List<Profile> sorted = new ArrayList<>(profiles.values());
        sorted.sort(Comparator.comparingLong(p -> p.lastSeen));
        int excess = profiles.size() - MAX_TRACKED_ACCOUNTS;
        for (int i = 0; i < excess && i < sorted.size(); i++) {
            Profile p = sorted.get(i);
            profiles.remove(p.userId, p);
        }
    }

    /** 7 天未活跃的账号画像过期清理（每 6 小时一次）。 */
    @Scheduled(fixedDelay = 6L * 3600_000L, initialDelay = 3600_000L)
    public void evictStale() {
        long cutoff = System.currentTimeMillis() - EVICT_AFTER_MS;
        for (Map.Entry<Long, Profile> e : profiles.entrySet()) {
            if (e.getValue().lastSeen < cutoff) {
                profiles.remove(e.getKey(), e.getValue());
            }
        }
    }

    /** 供管理面板展示的只读快照（不泄露完整指纹值，仅统计与告警样本）。 */
    public Map<String, Object> snapshot() {
        int multiFp = 0;
        int multiTls = 0;
        for (Profile p : profiles.values()) {
            if (p.fingerprintKeys.size() > 1) {
                multiFp++;
            }
            if (p.tlsKeys.size() > 1) {
                multiTls++;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tracked_accounts", profiles.size());
        out.put("total_observations", totalObservations.get());
        out.put("multi_fingerprint_accounts", multiFp);
        out.put("multi_tls_accounts", multiTls);
        out.put("multi_fingerprint_alerts", multiFingerprintAlerts.get());
        out.put("multi_tls_alerts", multiTlsAlerts.get());
        synchronized (recentAlerts) {
            out.put("recent_alerts", new ArrayList<>(recentAlerts));
        }
        return out;
    }

    private static final class Profile {
        final Long userId;
        volatile String username;
        volatile long lastSeen;
        final Set<String> fingerprintKeys =
                Collections.newSetFromMap(new ConcurrentHashMap<>());
        final Set<String> tlsKeys =
                Collections.newSetFromMap(new ConcurrentHashMap<>());
        final Set<String> ipKeys =
                Collections.newSetFromMap(new ConcurrentHashMap<>());

        Profile(Long userId, String username) {
            this.userId = userId;
            this.username = username;
            this.lastSeen = System.currentTimeMillis();
        }
    }
}