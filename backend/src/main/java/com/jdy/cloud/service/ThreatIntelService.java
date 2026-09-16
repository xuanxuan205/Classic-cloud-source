package com.jdy.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.security.AttackGuardService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * IronWall v1.17 溯源情报与证据报告服务（合法威慑，非攻击）。
 *
 * 1) IP 情报查询（GeoIP/ISP/ASN，经公开 API，默认关闭，带缓存与超时）；
 * 2) 生成完整攻击证据链报告（Markdown/JSON），可直接提交 ISP 滥用举报
 * 或作为网警报案材料附件。不进行任何反向攻击动作。
 */
@Slf4j
@Service
public class ThreatIntelService {

    private static final DateTimeFormatter REPORT_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AttackGuardService attackGuardService;
    private final AttackLogRepository attackLogRepository;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final Map<String, CacheEntry> coordCache = new ConcurrentHashMap<>();

    /** IronWall v1.28.5: 私有/保留地址段，无需查询公网情报。 */
    private static final java.util.regex.Pattern PRIVATE_IP = java.util.regex.Pattern.compile(
            "^(10\\.|127\\.|0\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.)");

    /**
     * IronWall v1.32.0: 代理/机房/云厂商 AS 关键词库。
     * 仅用于本地字符串判定，绝不发起网络请求。
     */
    private static final Set<String> PROXY_KEYWORDS = Set.of(
            "oracle", "google", "zenlayer", "ihor", "cogent", "datacenter", "hosting",
            "cloud", "aws", "digitalocean", "vultr", "linode", "hetzner", "ovh", "alibaba",
            "tencent", "huawei", "microsoft", "azure", "gcp", "censys", "shodan", "m247",
            "vpn", "proxy", "leaseweb", "contabo", "ionos");

    // IronWall v1.42.0: 移动/家宽运营商出口关键词（ASN 与 ISP/ORG 双向匹配）
    private static final Set<String> MOBILE_KEYWORDS = Set.of(
            "china mobile", "china unicom", "china telecom", "chinatelecom", "chinanet",
            "cmnet", "unicom", "china broadnet", "中国移动", "中国联通", "中国电信", "广电",
            "as4134", "as4837", "as9808", "as56040", "as56041", "as17621", "as17623",
            "as24444", "as24445", "as139220", "as23724", "as17816", "as9394");

    private final ExecutorService geoExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ironwall-geo-warmup");
        t.setDaemon(true);
        return t;
    });
    private final Set<String> warmingUp = ConcurrentHashMap.newKeySet();

    @Value("${app.security.defense-engine.threat-intel.enabled:false}")
    private boolean intelEnabled;

    @Value("${app.security.defense-engine.threat-intel.provider:ip-api}")
    private String provider;

    @Value("${app.security.defense-engine.threat-intel.cache-ttl-hours:24}")
    private int cacheTtlHours;

    /** 溯源报告署名的站点域名，由 {@code app.site.domain} 提供。 */
    @Value("${app.site.domain:}")
    private String siteDomain;

    public ThreatIntelService(AttackGuardService attackGuardService, AttackLogRepository attackLogRepository) {
        this.attackGuardService = attackGuardService;
        this.attackLogRepository = attackLogRepository;
    }

    /** IronWall v1.42.0: 启动时回填运营商出口判定器，供攻击防护分级调用。 */
    @PostConstruct
    void attachToGuard() {
        try {
            attackGuardService.attachThreatIntel(this);
        } catch (Exception e) {
            log.warn("[IronWall] threat-intel attach failed: {}", e.getMessage());
        }
    }

    public boolean isEnabled() {
        return intelEnabled;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> lookupIp(String ip) {
        if (!intelEnabled || ip == null || ip.isBlank()) return null;
        if (isPrivateIp(ip)) return localGeo();
        if (!lookupIpSafe(ip)) return null;
        CacheEntry cached = cache.get(ip);
        long now = System.currentTimeMillis();
        if (cached != null && now - cached.timestamp < Math.max(1, cacheTtlHours) * 3600_000L) {
            return cached.data;
        }
        try {
            String url = "ip-api".equalsIgnoreCase(provider)
                    ? "http://ip-api.com/json/" + encode(ip) + "?fields=status,message,country,regionName,city,isp,org,as,lat,lon,proxy,hosting,query&lang=zh-CN"
                    : null;
            if (url == null) return null;
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) return null;
            Map<String, Object> data = MAPPER.readValue(response.body(), Map.class);
            cache.put(ip, new CacheEntry(data, now));
            return data;
        } catch (Exception e) {
            log.warn("[IronWall] threat intel lookup failed for {}: {}", ip, e.getMessage());
            return null;
        }
    }

    /**
     * IronWall v1.26.1: 管理后台攻击地图专用坐标查询。独立于 threat-intel.enabled，
     * 供管理员 3D 攻击地图使用；查询失败由调用方降级为近似坐标，绝不影响页面。
     */
    public Map<String, Object> lookupForMap(String ip) {
        if (ip == null || ip.isBlank()) return null;
        if (!lookupIpSafe(ip)) return null;
        CacheEntry cached = coordCache.get(ip);
        long now = System.currentTimeMillis();
        if (cached != null && now - cached.timestamp < Math.max(1, cacheTtlHours) * 3600_000L) {
            return cached.data;
        }
        try {
            String url = "ip-api".equalsIgnoreCase(provider)
                    ? "http://ip-api.com/json/" + encode(ip) + "?fields=status,message,country,regionName,city,lat,lon,query&lang=zh-CN"
                    : null;
            if (url == null) return null;
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(3)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) return null;
            Map<String, Object> data = MAPPER.readValue(response.body(), Map.class);
            coordCache.put(ip, new CacheEntry(data, now));
            return data;
        } catch (Exception e) {
            log.warn("[IronWall] map geo lookup failed for {}: {}", ip, e.getMessage());
            return null;
        }
    }

    /** IronWall v1.28.5: 判断私有/保留地址。 */
    public boolean isPrivateIp(String ip) {
        if (ip == null) return false;
        String t = ip.trim();
        if (PRIVATE_IP.matcher(t).find()) return true;
        String lower = t.toLowerCase();
        return "::1".equals(lower) || lower.startsWith("fe80") || lower.startsWith("fc") || lower.startsWith("fd");
    }

    /** 本地/私有地址的固定定位结果。 */
    public Map<String, Object> localGeo() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("country", "本地网络");
        m.put("region", "");
        m.put("city", "");
        m.put("isp", "私有/内网地址");
        m.put("display", "本地 / 私有网络地址");
        return m;
    }

    /**
     * IronWall v1.32.0: 代理/机房来源纯函数判定。
     * proxy/hosting 字段为 true，或 as/isp/org 命中关键词库即判定为代理/机房来源。
     * 仅用于放大「已确认攻击」的记分，绝不据此封锁正常流量。
     */
    public boolean isLikelyProxy(Map<String, Object> geo) {
        if (geo == null) return false;
        Object proxy = geo.get("proxy");
        Object hosting = geo.get("hosting");
        if (Boolean.TRUE.equals(proxy) || Boolean.TRUE.equals(hosting)) return true;
        return containsProxyKeyword(geo.get("as"))
                || containsProxyKeyword(geo.get("isp"))
                || containsProxyKeyword(geo.get("org"));
    }

    /**
     * IronWall v1.32.0: 仅本地缓存判定（绝不发起网络请求）。
     * 缓存未命中返回 false，调用方异步预热后下一击生效；私有/本地地址恒为 false。
     */
    public boolean isLikelyProxyCached(String ip) {
        return isLikelyProxy(geoFromCache(ip));
    }

    /**
     * IronWall v1.42.0: 移动/家宽运营商出口判定（纯函数，无 I/O）。
     * proxy/hosting 为真（机房/代理）一律不算运营商出口，防止攻击者借关键词伪装享受熔断保护。
     */
    public boolean isMobileCarrier(Map<String, Object> geo) {
        if (geo == null) {
            return false;
        }
        if (Boolean.TRUE.equals(geo.get("proxy")) || Boolean.TRUE.equals(geo.get("hosting"))) {
            return false;
        }
        return containsMobileKeyword(geo.get("as"))
                || containsMobileKeyword(geo.get("isp"))
                || containsMobileKeyword(geo.get("org"));
    }

    /** 仅本地缓存判定（绝不发起网络请求）；未识别返回 false（按默认严格策略，安全方向）。 */
    public boolean isMobileCarrierCached(String ip) {
        return isMobileCarrier(geoFromCache(ip));
    }

    private boolean containsMobileKeyword(Object value) {
        if (value == null) {
            return false;
        }
        String lower = value.toString().toLowerCase(Locale.ROOT);
        for (String keyword : MOBILE_KEYWORDS) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsProxyKeyword(Object value) {
        if (value == null) return false;
        String lower = value.toString().toLowerCase(Locale.ROOT);
        for (String keyword : PROXY_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * 仅返回缓存中的位置情报（绝不发起网络请求），供封禁列表/攻击流水等批量场景快速展示。
     * 返回 null 表示尚未识别（调用方展示"识别中"，后台预热会自动补全）。
     */
    public Map<String, Object> geoFromCache(String ip) {
        if (ip == null || ip.isBlank()) return null;
        if (isPrivateIp(ip)) return localGeo();
        CacheEntry cached = cache.get(ip);
        if (cached == null) return null;
        return withDisplay(cached.data);
    }

    /**
     * 实时查询位置情报（带 24h 缓存），返回带有 display 字段的结果；
     * 查询失败返回 null，绝不影响主流程。
     */
    public Map<String, Object> lookupGeo(String ip) {
        Map<String, Object> geo = lookupIp(ip);
        if (geo == null) return null;
        return withDisplay(geo);
    }

    private Map<String, Object> withDisplay(Map<String, Object> geo) {
        if (geo == null) return null;
        Map<String, Object> m = new LinkedHashMap<>(geo);
        StringBuilder sb = new StringBuilder();
        Object country = geo.get("country");
        Object region = geo.get("regionName");
        Object city = geo.get("city");
        Object isp = geo.get("isp");
        if (country != null) sb.append(country);
        if (region != null && !region.toString().isBlank()) sb.append(" ").append(region);
        if (city != null && !city.toString().isBlank()) sb.append(" ").append(city);
        if (sb.length() == 0) sb.append("未知地区");
        if (isp != null && !isp.toString().isBlank()) sb.append(" · ").append(isp);
        m.put("display", sb.toString());
        return m;
    }

    /**
     * IronWall v1.28.5: 后台异步预热位置情报（单飞+去重），
     * 列表接口先用 geoFromCache 返回，预热完成后下次刷新自动补全。
     */
    public void warmUpGeoAsync(Collection<String> ips) {
        if (!intelEnabled || ips == null || ips.isEmpty()) return;
        for (String ip : ips) {
            if (ip == null || ip.isBlank() || isPrivateIp(ip)) continue;
            if (cache.containsKey(ip) || !warmingUp.add(ip)) continue;
            final String target = ip;
            geoExecutor.submit(() -> {
                try {
                    lookupGeo(target);
                } catch (Exception e) {
                    log.debug("[IronWall] geo warmup failed for {}: {}", target, e.getMessage());
                } finally {
                    warmingUp.remove(target);
                }
            });
        }
    }

    public String buildAbuseReport(String ip) {
        StringBuilder sb = new StringBuilder();
        sb.append("# 攻击溯源与处置报告\n\n");
        sb.append("- 生成时间: ").append(LocalDateTime.now().format(REPORT_TIME)).append("\n");
        sb.append("- 防护引擎: ").append(AttackGuardService.ENGINE_FULL_NAME).append("\n");
        // 站点域名由配置提供。
        String site = siteDomain == null ? "" : siteDomain.trim();
        sb.append("- 目标站点: ").append(site.isEmpty() ? "(未配置)" : site).append("\n");
        sb.append("- 攻击来源 IP: ").append(ip).append("\n");
        sb.append("- 威胁画像: ").append(attackGuardService.classifyThreat(ip).name()).append("\n\n");

        Map<String, Object> geo = lookupIp(ip);
        if (geo != null) {
            sb.append("## 来源情报\n\n");
            sb.append("- 国家/地区: ").append(geo.get("country")).append(" ").append(geo.get("regionName")).append(" ").append(geo.get("city")).append("\n");
            sb.append("- ISP: ").append(geo.get("isp")).append("\n");
            sb.append("- 组织: ").append(geo.get("org")).append("\n");
            sb.append("- ASN: ").append(geo.get("as")).append("\n\n");
        }

        List<AttackLog> logs;
        try {
            logs = attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(ip);
        } catch (Exception e) {
            logs = List.of();
        }
        // IronWall v1.17.2: 相邻完全相同（同秒/同路径/同载荷）的流水聚合为一行，报告更可读
        List<EvidenceRow> aggregated = new ArrayList<>();
        for (AttackLog a : logs) {
            EvidenceRow row = new EvidenceRow(a);
            if (!aggregated.isEmpty() && aggregated.get(aggregated.size() - 1).sameAs(row)) {
                aggregated.get(aggregated.size() - 1).count++;
            } else {
                aggregated.add(row);
            }
        }
        if (logs.isEmpty()) {
            sb.append("（暂无落库流水）\n");
        } else {
            sb.append("## 攻击证据链（最近 ").append(logs.size()).append(" 条，聚合后 ").append(aggregated.size()).append(" 组）\n\n");
            sb.append("| 时间 | 类型 | 方法 | 路径 | 载荷 | 次数 | 记分 | 处置 |\n");
            sb.append("|---|---|---|---|---|---|---|---|\n");
            for (EvidenceRow r : aggregated) {
                sb.append("| ").append(r.time).append(" | ").append(escapeMd(r.type))
                        .append(" | ").append(escapeMd(r.method)).append(" | ").append(escapeMd(r.path))
                        .append(" | ").append(escapeMd(r.payload)).append(" | ").append(r.count)
                        .append(" | ").append(r.score).append(" | ").append(escapeMd(r.action)).append(" |\n");
            }
        }
        sb.append("\n## 已采取的防御措施\n\n");
        sb.append("- 自动警告、拖延消耗（Tarpit）、按严重度封禁升级；重复再犯升级 IP 段封禁。\n");
        sb.append("- 本报告为合法防御产生的日志证据，用于向 ISP 滥用邮箱举报或向公安机关报案。\n\n");
        sb.append("## 建议处置\n\n");
        sb.append("1. 保持该 IP / IP 段在封禁名单中；\n");
        sb.append("2. 将本报告发送至该 IP 所属 ISP 的 abuse 邮箱；\n");
        sb.append("3. 如涉及数据泄露或持续性定向攻击，携带本报告向属地网警报案。\n");
        return sb.toString();
    }

    public Map<String, Object> buildAttackerProfile(String ip) {
        Map<String, Object> profile = new java.util.LinkedHashMap<>();
        profile.put("ip", ip);
        profile.put("threat_profile", attackGuardService.classifyThreat(ip).name());
        profile.put("blocked", attackGuardService.isBlocked(ip));
        profile.put("segment_blocked", attackGuardService.isBlockedSegment(ip));
        profile.put("tarpit", attackGuardService.shouldTarpit(ip));
        profile.put("geo", lookupIp(ip));
        try {
            profile.put("evidence_count", attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(ip).size());
        } catch (Exception e) {
            profile.put("evidence_count", 0);
        }
        return profile;
    }

    private String encode(String value) {
        return value.replace(" ", "");
    }

    /**
     * IronWall v1.47.7: 只有格式合法的字面 IP 才允许拼进外部查询 URL，
     * 阻断任意字符串带来的 URL 路径注入面（host 固定，fail-closed）。
     */
    private static boolean lookupIpSafe(String ip) {
        return ip.length() <= 64 && ip.matches("[0-9a-fA-F:.]+");
    }

    private String escapeMd(String value) {
        if (value == null) return "";
        return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }

    private static final class EvidenceRow {
        final String time, type, method, path, payload, score, action;
        int count = 1;

        EvidenceRow(AttackLog a) {
            this.time = a.getCreatedAt() == null ? "" : a.getCreatedAt().format(REPORT_TIME);
            this.type = a.getAttackType() == null ? "" : a.getAttackType();
            this.method = a.getMethod() == null ? "" : a.getMethod();
            this.path = a.getPath() == null ? "" : a.getPath();
            this.payload = a.getPayload() == null ? "" : a.getPayload();
            this.score = a.getScore() == null ? "" : String.valueOf(a.getScore());
            this.action = a.getAction() == null ? "" : a.getAction();
        }

        boolean sameAs(EvidenceRow o) {
            return time.equals(o.time) && type.equals(o.type) && method.equals(o.method)
                    && path.equals(o.path) && payload.equals(o.payload)
                    && score.equals(o.score) && action.equals(o.action);
        }
    }

    private static final class CacheEntry {
        final Map<String, Object> data;
        final long timestamp;

        CacheEntry(Map<String, Object> data, long timestamp) {
            this.data = data;
            this.timestamp = timestamp;
        }
    }
}
