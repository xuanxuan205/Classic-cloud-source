package com.jdy.cloud.security;

import com.jdy.cloud.service.ThreatIntelService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * IronWall v1.35.0: DDoS 分层防御与溯源取证。
 *
 * 设计红线：
 * 1. 热路径（observe）零 I/O、零锁竞争、有界内存——DDoS 期间引擎不能自我击穿。
 * 2. 「记录在案」= 秒级聚合快照 + 事件环定期落盘（原始逐请求记录由 nginx access log 承担）。
 * 3. 登录态/白名单只计数不记分；TLS 指纹/UA 集群只做证据加成，绝不单独封禁流量。
 * 4. 数据库写保护：每周期最多对 maxScorePerCycle 个 IP 记分，其余只进聚合日志。
 */
@Slf4j
@Component
public class DdosDefenseService {

    public static final String TYPE_DDOS = "DDoS洪水攻击";
    public static final String TYPE_DDOS_CLUSTER = "僵尸网络集群";

    @Value("${app.security.ddos.enabled:true}")
    private boolean enabled;
    @Value("${app.security.ddos.per-ip-flood-rps:25}")
    private int perIpFloodRps;
    @Value("${app.security.ddos.per-ip-severe-rps:100}")
    private int perIpSevereRps;
    @Value("${app.security.ddos.window-seconds:5}")
    private int windowSeconds;
    @Value("${app.security.ddos.endpoint-flood-rps:800}")
    private int endpointFloodRps;
    @Value("${app.security.ddos.cluster-min-ips:30}")
    private int clusterMinIps;
    @Value("${app.security.ddos.cluster-member-min-rps:10}")
    private int clusterMemberMinRps;
    @Value("${app.security.ddos.cluster-window-seconds:120}")
    private int clusterWindowSeconds;
    @Value("${app.security.ddos.cluster-evidence-boost:10}")
    private int clusterEvidenceBoost;
    @Value("${app.security.ddos.global-ips-surge:2000}")
    private int globalIpsSurge;
    @Value("${app.security.ddos.max-tracked-ips:20000}")
    private int maxTrackedIps;
    @Value("${app.security.ddos.max-score-per-cycle:300}")
    private int maxScorePerCycle;
    @Value("${app.security.ddos.log-path:logs/ironwall-ddos.log}")
    private String logPath;

    private static final int RING_SLOTS = 60;
    private static final int MAX_TRACKED_PATHS = 200;
    private static final int MAX_CLUSTERS = 500;
    private static final int CLUSTER_MEMBER_CAP = 512;
    private static final int EVENT_RING_CAP = 1000;
    private static final int ATTACK_SOURCE_CAP = 5000;

    private final AttackGuardService attackGuardService;
    private final TlsProfileResolver tlsProfileResolver;
    private final ThreatIntelService threatIntelService;

    private final ConcurrentHashMap<String, RateWindow> ipWindows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RateWindow> pathWindows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ClusterEntry> clusters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> attackSources = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastFloodScoreAt = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastSevereScoreAt = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastEndpointEventAt = new ConcurrentHashMap<>();
    private final ArrayDeque<String> eventRing = new ArrayDeque<>(EVENT_RING_CAP);

    private final AtomicLong observedRequests = new AtomicLong();
    private final AtomicLong floodEvents = new AtomicLong();
    private final AtomicLong severeEvents = new AtomicLong();
    private final AtomicLong endpointFloodEvents = new AtomicLong();
    private final AtomicLong clusterEvents = new AtomicLong();
    private final AtomicLong scoredByDdos = new AtomicLong();
    private final AtomicLong blockedByDdos = new AtomicLong();
    private final AtomicInteger scoredThisCycle = new AtomicInteger();
    private final AtomicLong distinctIpsWindow = new AtomicLong();

    private final long startedAt = System.currentTimeMillis();
    private volatile long lastDistinctResetAt = System.currentTimeMillis();
    private volatile long lastFlushAt = System.currentTimeMillis();

    public DdosDefenseService(AttackGuardService attackGuardService, TlsProfileResolver tlsProfileResolver,
                              ThreatIntelService threatIntelService) {
        this.attackGuardService = attackGuardService;
        this.tlsProfileResolver = tlsProfileResolver;
        this.threatIntelService = threatIntelService;
    }

    // ==================== 热路径观测（零 I/O） ====================

    /** 每个请求调用一次：只做计数与阈值判定，绝不抛异常、绝不写盘。 */
    public void observe(HttpServletRequest request, String clientIp, boolean trustedSession, boolean blocked) {
        if (!enabled || request == null || clientIp == null || clientIp.isBlank()) return;
        try {
            observedRequests.incrementAndGet();
            long now = System.currentTimeMillis();
            long sec = now / 1000;
            String path = request.getRequestURI() == null ? "/" : request.getRequestURI();
            RateWindow w = ipWindows.get(clientIp);
            if (w == null) {
                if (ipWindows.size() >= maxTrackedIps) {
                    if ((Math.floorMod(clientIp.hashCode(), 8)) != 0) return;
                }
                RateWindow created = new RateWindow();
                RateWindow existed = ipWindows.putIfAbsent(clientIp, created);
                w = existed != null ? existed : created;
                if (existed == null) {
                    distinctIpsWindow.incrementAndGet();
                }
            }
            w.add(sec);
            w.lastSeen = now;
            w.lastIp = clientIp;
            w.lastPath = path;

            if (!blocked && !trustedSession) {
                double rate = w.avgRate(windowSeconds, sec);
                if (rate >= clusterMemberMinRps) {
                    String tls = tlsProfileResolver == null ? null : safeResolveTls(request);
                    String ua = request.getHeader("User-Agent");
                    String prefix = pathPrefix(path);
                    registerClusterMember(clusterKey(tls, ua, prefix), clientIp, prefix, tls, ua, now);
                }
                if (rate >= perIpSevereRps) {
                    scoreFlood(clientIp, path, request.getMethod(), request.getHeader("User-Agent"),
                            10, 10_000L, now, "严重洪水 " + (long) rate + "r/s", true);
                } else if (rate >= perIpFloodRps) {
                    scoreFlood(clientIp, path, request.getMethod(), request.getHeader("User-Agent"),
                            5, 30_000L, now, "L7洪水 " + (long) rate + "r/s", false);
                }
            }

            // 端点洪水（全局单路径速率）：只记录事件，IP 级处置由上一层兜底
            RateWindow pw = pathWindows.get(path);
            if (pw == null) {
                if (pathWindows.size() < MAX_TRACKED_PATHS) {
                    RateWindow created = new RateWindow();
                    RateWindow existed = pathWindows.putIfAbsent(path, created);
                    pw = existed != null ? existed : created;
                }
            }
            if (pw != null) {
                pw.add(sec);
                double pathRate = pw.avgRate(windowSeconds, sec);
                if (pathRate >= endpointFloodRps) {
                    Long last = lastEndpointEventAt.put(path, now);
                    if (last == null || now - last >= 30_000L) {
                        endpointFloodEvents.incrementAndGet();
                        pushEvent("端点洪水", clientIp, path, "全局速率 " + (long) pathRate + "r/s", "EVENT");
                    }
                }
            }
        } catch (Exception e) {
            log.error("[IronWall] DDoS observe failed (fail-open): {}", e.getMessage());
        }
    }

    /** 攻击检测命中时登记攻击源（供溯源交叉分析：DDoS 集群成员中哪些同时在注入攻击）。 */
    public void markAttack(String ip, String path, String type) {
        if (!enabled || ip == null) return;
        if (attackSources.size() < ATTACK_SOURCE_CAP) {
            attackSources.put(ip, System.currentTimeMillis());
        }
    }

    // ==================== 处置（去重 + 周期配额） ====================

    private void scoreFlood(String ip, String path, String method, String ua, int weight,
                            long dedupeMs, long now, String payload, boolean severe) {
        if (scoredThisCycle.getAndIncrement() >= maxScorePerCycle) {
            scoredThisCycle.decrementAndGet();
            return;
        }
        ConcurrentHashMap<String, Long> dedupeMap = severe ? lastSevereScoreAt : lastFloodScoreAt;
        Long prev = dedupeMap.put(ip, now);
        if (prev != null && now - prev < dedupeMs) {
            scoredThisCycle.decrementAndGet();
            return;
        }
        try {
            AttackGuardService.AttackRecord record = attackGuardService.recordWeighted(
                    ip, TYPE_DDOS, payload, path, ua, method, false, weight);
            scoredByDdos.incrementAndGet();
            if (severe) severeEvents.incrementAndGet(); else floodEvents.incrementAndGet();
            if (record != null && "BLOCKED".equals(record.action)) {
                blockedByDdos.incrementAndGet();
            }
            pushEvent(severe ? "严重洪水" : "L7洪水", ip, path, payload, record != null ? record.action : "WARN");
        } catch (Exception e) {
            log.error("[IronWall] DDoS score failed: {}", e.getMessage());
        }
    }

    // ==================== 僵尸网络集群（证据加成，绝不单独封禁） ====================

    private void registerClusterMember(String key, String ip, String prefix, String tls, String ua, long now) {
        if (clusters.size() >= MAX_CLUSTERS && !clusters.containsKey(key)) return;
        ClusterEntry entry = clusters.computeIfAbsent(key, k -> new ClusterEntry(prefix, tls, uaHash(ua), now));
        entry.touch(ip, now);
    }

    /** 定时评估集群触发；每集群每窗口最多触发一次。 */
    public void evaluateClusters() {
        if (!enabled) return;
        long now = System.currentTimeMillis();
        for (ClusterEntry entry : new ArrayList<>(clusters.values())) {
            if (entry.members.size() < clusterMinIps) continue;
            if (now - entry.lastTriggerAt < clusterWindowSeconds * 1000L) continue;
            entry.lastTriggerAt = now;
            clusterEvents.incrementAndGet();
            pushEvent("僵尸网络集群", entry.pathPrefix, entry.uaHash,
                    "同指纹集群 " + entry.members.size() + " IP（样本 " + entry.sample(3) + "）", "EVIDENCE");
            int boosted = 0;
            for (String ip : entry.members) {
                if (scoredThisCycle.getAndIncrement() >= maxScorePerCycle) {
                    scoredThisCycle.decrementAndGet();
                    break;
                }
                try {
                    attackGuardService.recordWeighted(ip, TYPE_DDOS_CLUSTER,
                            "僵尸网络集群证据 " + entry.members.size() + " IP", entry.pathPrefix,
                            entry.uaHash, "GET", false, clusterEvidenceBoost);
                    boosted++;
                } catch (Exception e) {
                    log.error("[IronWall] DDoS cluster boost failed for {}: {}", ip, e.getMessage());
                }
            }
            if (boosted > 0) scoredByDdos.addAndGet(boosted);
        }
    }

    // ==================== 落盘与清扫（定时） ====================

    /** 每 10 秒：事件 + Top 聚合 + 全局计数落盘（防 DDoS 时段证据丢失）。 */
    @Scheduled(fixedRateString = "${app.security.ddos.flush-ms:10000}")
    public void flushToLog() {
        if (!enabled) return;
        try {
            scoredThisCycle.set(0);
            long now = System.currentTimeMillis();
            List<String> lines = new ArrayList<>();
            lines.add("{\"type\":\"totals\",\"ts\":" + now + ",\"observed\":" + observedRequests.get()
                    + ",\"flood_events\":" + floodEvents.get() + ",\"severe_events\":" + severeEvents.get()
                    + ",\"endpoint_events\":" + endpointFloodEvents.get()
                    + ",\"cluster_events\":" + clusterEvents.get() + ",\"scored\":" + scoredByDdos.get()
                    + ",\"blocked\":" + blockedByDdos.get() + ",\"tracked_ips\":" + ipWindows.size()
                    + ",\"tracked_paths\":" + pathWindows.size() + ",\"distinct_ips_60s\":" + distinctIpsWindow.get() + "}");
            for (Map<String, Object> top : topIps(10, now)) {
                lines.add("{\"type\":\"obs\",\"ip\":\"" + sjson(String.valueOf(top.get("ip"))) + "\",\"rps\":" + top.get("rps")
                        + ",\"path\":\"" + sjson(String.valueOf(top.get("path"))) + "\"}");
            }
            for (Map<String, Object> top : topPaths(5, now)) {
                lines.add("{\"type\":\"path\",\"path\":\"" + sjson(String.valueOf(top.get("path"))) + "\",\"rps\":" + top.get("rps") + "}");
            }
            synchronized (eventRing) {
                while (!eventRing.isEmpty()) lines.add(eventRing.pollFirst());
            }
            appendLines(lines);
            lastFlushAt = now;
        } catch (Exception e) {
            log.error("[IronWall] DDoS flush failed: {}", e.getMessage());
        }
    }

    /** 每 60 秒：驱逐陈旧 IP/路径/集群槽位，控制内存上界。 */
    @Scheduled(fixedRate = 60_000L)
    public void sweepStale() {
        if (!enabled) return;
        long now = System.currentTimeMillis();
        ipWindows.entrySet().removeIf(e -> now - e.getValue().lastSeen > 180_000L);
        pathWindows.entrySet().removeIf(e -> now - e.getValue().lastSeen > 300_000L);
        clusters.entrySet().removeIf(e -> now - e.getValue().lastSeen > Math.max(240_000L, clusterWindowSeconds * 2000L));
        lastFloodScoreAt.entrySet().removeIf(e -> now - e.getValue() > 3600_000L);
        lastSevereScoreAt.entrySet().removeIf(e -> now - e.getValue() > 3600_000L);
        lastEndpointEventAt.entrySet().removeIf(e -> now - e.getValue() > 3600_000L);
        attackSources.entrySet().removeIf(e -> now - e.getValue() > 6 * 3600_000L);
        if (now - lastDistinctResetAt >= 60_000L) {
            long distinct = distinctIpsWindow.getAndSet(0);
            lastDistinctResetAt = now;
            if (distinct > globalIpsSurge) {
                pushEvent("全站IP激增", "-", "/", "60s 去重 IP " + distinct, "EVENT");
            }
        }
    }

    // ==================== 溯源取证 ====================

    /** 面板摘要（轻量）。 */
    public Map<String, Object> summary() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", enabled);
        m.put("observed_requests", observedRequests.get());
        m.put("tracked_ips", ipWindows.size());
        m.put("flood_events", floodEvents.get());
        m.put("severe_events", severeEvents.get());
        m.put("endpoint_events", endpointFloodEvents.get());
        m.put("cluster_events", clusterEvents.get());
        m.put("scored_by_ddos", scoredByDdos.get());
        m.put("blocked_by_ddos", blockedByDdos.get());
        m.put("active_floods", activeFloodCount());
        m.put("since", Instant.ofEpochMilli(startedAt).toString());
        return m;
    }

    /** 完整溯源报告：Top 来源（geo/ASN/代理判定）、僵尸网络集群、攻击源交叉、事件尾部。 */
    public Map<String, Object> forensicReport() {
        long now = System.currentTimeMillis();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("summary", summary());
        List<Map<String, Object>> sources = new ArrayList<>();
        for (Map<String, Object> top : topIps(20, now)) {
            String ip = String.valueOf(top.get("ip"));
            Map<String, Object> item = new LinkedHashMap<>(top);
            try {
                item.put("geo", threatIntelService == null ? null : threatIntelService.geoFromCache(ip));
                item.put("likely_proxy", threatIntelService != null && threatIntelService.isLikelyProxyCached(ip));
            } catch (Exception ignored) {
                item.put("geo", null);
            }
            item.put("is_attack_source", attackSources.containsKey(ip));
            sources.add(item);
        }
        out.put("top_sources", sources);
        List<Map<String, Object>> cl = new ArrayList<>();
        clusters.values().stream()
                .sorted((a, b) -> Integer.compare(b.members.size(), a.members.size()))
                .limit(10)
                .forEach(e -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("path_prefix", e.pathPrefix);
                    item.put("tls", e.tls);
                    item.put("ua_hash", e.uaHash);
                    item.put("member_count", e.members.size());
                    item.put("sample_ips", e.sample(8));
                    item.put("first_seen", Instant.ofEpochMilli(e.firstSeen).toString());
                    item.put("last_seen", Instant.ofEpochMilli(e.lastSeen).toString());
                    cl.add(item);
                });
        out.put("clusters", cl);
        out.put("top_paths", topPaths(10, now));
        List<String> events = new ArrayList<>();
        synchronized (eventRing) {
            events.addAll(eventRing);
        }
        out.put("recent_events", events.size() > 50 ? events.subList(events.size() - 50, events.size()) : events);
        return out;
    }

    /** 单 IP 溯源：观测窗口速率 + geo + 攻击源标记 + 现有滥用报告。 */
    public Map<String, Object> forensicForIp(String ip) {
        Map<String, Object> out = new LinkedHashMap<>();
        RateWindow w = ipWindows.get(ip);
        out.put("ip", ip);
        out.put("current_rps", w == null ? 0 : (long) w.avgRate(windowSeconds, System.currentTimeMillis() / 1000));
        try {
            out.put("geo", threatIntelService == null ? null : threatIntelService.geoFromCache(ip));
            out.put("likely_proxy", threatIntelService != null && threatIntelService.isLikelyProxyCached(ip));
            out.put("report_markdown", threatIntelService == null ? null : threatIntelService.buildAbuseReport(ip));
        } catch (Exception ignored) {
            out.put("geo", null);
        }
        out.put("is_attack_source", attackSources.containsKey(ip));
        out.put("blocked", attackGuardService.isBlocked(ip));
        return out;
    }

    public boolean isEnabled() {
        return enabled;
    }

    // ==================== 内部工具 ====================

    private int activeFloodCount() {
        long sec = System.currentTimeMillis() / 1000;
        int count = 0;
        for (RateWindow w : ipWindows.values()) {
            if (w.avgRate(windowSeconds, sec) >= perIpFloodRps) count++;
        }
        return count;
    }

    private List<Map<String, Object>> topIps(int n, long now) {
        long sec = now / 1000;
        List<RateWindow> values = new ArrayList<>(ipWindows.values());
        List<Map<String, Object>> out = new ArrayList<>();
        values.stream()
                .sorted((a, b) -> Double.compare(b.avgRate(windowSeconds, sec), a.avgRate(windowSeconds, sec)))
                .limit(n * 4)
                .forEach(w -> {
                    if (out.size() >= n) return;
                    String ip = w.lastIp;
                    if (ip == null) return;
                    long rps = (long) w.avgRate(windowSeconds, sec);
                    if (rps <= 0) return;
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("ip", ip);
                    item.put("rps", rps);
                    item.put("path", w.lastPath == null ? "/" : w.lastPath);
                    out.add(item);
                });
        return out;
    }

    private List<Map<String, Object>> topPaths(int n, long now) {
        long sec = now / 1000;
        List<Map.Entry<String, RateWindow>> entries = new ArrayList<>(pathWindows.entrySet());
        entries.sort((a, b) -> Double.compare(b.getValue().avgRate(windowSeconds, sec), a.getValue().avgRate(windowSeconds, sec)));
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < Math.min(n, entries.size()); i++) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("path", entries.get(i).getKey());
            item.put("rps", (long) entries.get(i).getValue().avgRate(windowSeconds, sec));
            out.add(item);
        }
        return out;
    }

    private void pushEvent(String kind, String ip, String path, String detail, String action) {
        String line = "{\"type\":\"event\",\"ts\":" + System.currentTimeMillis() + ",\"kind\":\"" + kind
                + "\",\"ip\":\"" + sjson(ip == null ? "-" : ip) + "\",\"path\":\"" + sjson(path == null ? "/" : path)
                + "\",\"detail\":\"" + sjson(detail == null ? "" : detail) + "\",\"action\":\"" + action + "\"}";
        synchronized (eventRing) {
            if (eventRing.size() >= EVENT_RING_CAP) eventRing.pollFirst();
            eventRing.addLast(line);
        }
    }

    private String sjson(String v) {
        if (v == null) return "";
        StringBuilder sb = new StringBuilder(v.length() + 8);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '"') sb.append('\\').append('"');
            else if (c == '\\') sb.append('\\').append('\\');
            else sb.append(c);
        }
        return sb.toString();
    }

    private void appendLines(List<String> lines) {
        try {
            File f = new File(logPath);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            try (FileWriter writer = new FileWriter(f, StandardCharsets.UTF_8, true)) {
                for (String line : lines) {
                    writer.write(line);
                    writer.write(System.lineSeparator());
                }
            }
        } catch (Exception e) {
            log.error("[IronWall] DDoS log append failed: {}", e.getMessage());
        }
    }

    private String safeResolveTls(HttpServletRequest request) {
        try {
            return tlsProfileResolver.resolve(request);
        } catch (Exception e) {
            return null;
        }
    }

    private String pathPrefix(String path) {
        if (path == null || path.isBlank()) return "/";
        String[] parts = path.split("/");
        StringBuilder sb = new StringBuilder();
        int used = 0;
        for (String p : parts) {
            if (p.isEmpty()) continue;
            sb.append('/').append(p);
            if (++used >= 2) break;
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    private String clusterKey(String tls, String ua, String prefix) {
        return (tls == null ? "none" : tls) + "|" + uaHash(ua) + "|" + prefix;
    }

    private String uaHash(String ua) {
        return sha256Hex16(ua == null ? "none" : ua);
    }

    private String sha256Hex16(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", out[i]));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(data.hashCode());
        }
    }

    // ==================== 数据结构 ====================

    /** 60 槽/秒环形计数窗；synchronized 粒度仅限单 IP/路径，热路径无全局锁。 */
    static final class RateWindow {
        final long[] ring = new long[RING_SLOTS];
        volatile long lastSec;
        volatile long lastSeen;
        volatile String lastIp;
        volatile String lastPath;

        synchronized void add(long sec) {
            int idx = (int) Math.floorMod(sec, RING_SLOTS);
            if (lastSec == 0 || sec - lastSec >= RING_SLOTS) {
                if (sec != lastSec) Arrays.fill(ring, 0);
            } else if (sec != lastSec) {
                for (long s = lastSec + 1; s <= sec; s++) {
                    ring[(int) Math.floorMod(s, RING_SLOTS)] = 0;
                }
            }
            lastSec = sec;
            ring[idx]++;
        }

        synchronized double avgRate(int seconds, long sec) {
            if (lastSec <= 0) return 0;
            long sum = 0;
            int n = Math.min(Math.max(seconds, 1), RING_SLOTS);
            long base = sec;
            for (int i = 0; i < n; i++) {
                sum += ring[(int) Math.floorMod(base - i, RING_SLOTS)];
            }
            return (double) sum / n;
        }
    }

    static final class ClusterEntry {
        final String pathPrefix;
        final String tls;
        final String uaHash;
        final long firstSeen;
        volatile long lastSeen;
        volatile long lastTriggerAt;
        final Set<String> members = ConcurrentHashMap.newKeySet(CLUSTER_MEMBER_CAP);

        ClusterEntry(String pathPrefix, String tls, String uaHash, long firstSeen) {
            this.pathPrefix = pathPrefix;
            this.tls = tls;
            this.uaHash = uaHash;
            this.firstSeen = firstSeen;
            this.lastSeen = firstSeen;
        }

        void touch(String ip, long now) {
            if (members.size() < CLUSTER_MEMBER_CAP) members.add(ip);
            lastSeen = now;
        }

        String sample(int n) {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            for (String ip : members) {
                if (i++ >= n) break;
                if (sb.length() > 0) sb.append(',');
                sb.append(ip);
            }
            return sb.toString();
        }
    }
}
