package com.jdy.cloud.service;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.security.AttackGuardService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.17.2: 滥用报告契约测试（时间格式与重复流水聚合）。
 */
@ExtendWith(MockitoExtension.class)
class ThreatIntelServiceTest {

    @Mock
    private AttackGuardService attackGuardService;

    @Mock
    private AttackLogRepository attackLogRepository;

    private ThreatIntelService service;

    @BeforeEach
    void setUp() {
        service = new ThreatIntelService(attackGuardService, attackLogRepository);
    }

    private AttackLog log(LocalDateTime time, String type, String method, String path, String payload, int score, String action) {
        AttackLog a = new AttackLog();
        a.setIp("203.0.113.66");
        a.setAttackType(type);
        a.setMethod(method);
        a.setPath(path);
        a.setPayload(payload);
        a.setScore(score);
        a.setAction(action);
        a.setCreatedAt(time);
        return a;
    }

    @Test
    void buildAbuseReport_shouldAggregateDuplicatesAndFormatTime() {
        when(attackGuardService.classifyThreat("203.0.113.66"))
                .thenReturn(AttackGuardService.ThreatProfile.SCANNER);
        LocalDateTime t1 = LocalDateTime.of(2026, 8, 16, 0, 13, 11);
        LocalDateTime t2 = LocalDateTime.of(2026, 8, 16, 0, 13, 14);
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.66")).thenReturn(List.of(
                log(t1, "爬虫扫描", "GET", "/api/files/list", "自动化客户端访问: curl/8.7.1", 4, "WARN"),
                log(t1, "爬虫扫描", "GET", "/api/files/list", "自动化客户端访问: curl/8.7.1", 4, "WARN"),
                log(t2, "爬虫扫描", "DELETE", "/api/files/144", "自动化客户端访问: curl/8.7.1", 6, "WARN")
        ));

        String report = service.buildAbuseReport("203.0.113.66");

        assertTrue(report.contains("IronWall " + AttackGuardService.ENGINE_VERSION));
        assertTrue(report.contains("2026-08-16 00:13:11"), "时间应为 yyyy-MM-dd HH:mm:ss 格式");
        assertFalse(report.contains("T00:13:11"), "不应再出现 ISO T 分隔时间");
        assertTrue(report.contains("聚合后 2 组"), "两条相同流水应聚合为 1 组");
        assertTrue(report.contains("| 2 |"), "聚合组应包含次数 2");
        assertTrue(report.contains("威胁画像: SCANNER"));
    }

    @Test
    void buildAbuseReport_shouldHandleEmptyEvidence() {
        when(attackGuardService.classifyThreat("203.0.113.67"))
                .thenReturn(AttackGuardService.ThreatProfile.UNKNOWN);
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.67")).thenReturn(List.of());

        String report = service.buildAbuseReport("203.0.113.67");

        assertTrue(report.contains("暂无落库流水"));
        assertTrue(report.contains("IronWall " + AttackGuardService.ENGINE_VERSION));
    }

    // ===== IronWall v1.28.5: IP 自动定位 =====

    @Test
    void isPrivateIp_shouldDetectPrivateRanges() {
        assertTrue(service.isPrivateIp("192.168.1.1"));
        assertTrue(service.isPrivateIp("10.0.0.1"));
        assertTrue(service.isPrivateIp("172.16.0.1"));
        assertTrue(service.isPrivateIp("172.31.255.255"));
        assertTrue(service.isPrivateIp("127.0.0.1"));
        assertTrue(service.isPrivateIp("169.254.1.1"));
        assertFalse(service.isPrivateIp("203.0.113.5"));
        assertFalse(service.isPrivateIp("198.51.100.30"));
        assertFalse(service.isPrivateIp("172.15.0.1"));
    }

    @Test
    void localGeo_shouldCarryDisplay() {
        assertEquals("本地 / 私有网络地址", service.localGeo().get("display"));
    }

    @Test
    void geoFromCache_privateIp_shouldReturnLocalWithoutNetwork() {
        assertNotNull(service.geoFromCache("192.168.1.5"));
        assertEquals("本地 / 私有网络地址", service.geoFromCache("192.168.1.5").get("display"));
    }

    @Test
    void geoFromCache_unknownPublicIp_shouldReturnNullFast() {
        assertNull(service.geoFromCache("203.0.113.5"));
    }

    @Test
    void geoFromCache_blankIp_shouldReturnNull() {
        assertNull(service.geoFromCache(null));
        assertNull(service.geoFromCache("  "));
    }

    // ===== IronWall v1.32.0: 代理/机房来源纯函数判定 =====

    private Map<String, Object> geo(String as, String isp, String org, Boolean proxy, Boolean hosting) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("as", as);
        m.put("isp", isp);
        m.put("org", org);
        m.put("proxy", proxy);
        m.put("hosting", hosting);
        return m;
    }

    @Test
    void isLikelyProxy_shouldFlagHostingAndKeywordSources() {
        assertTrue(service.isLikelyProxy(geo(null, null, null, true, null)));
        assertTrue(service.isLikelyProxy(geo(null, null, null, null, true)));
        assertTrue(service.isLikelyProxy(geo("AS13335 CLOUDFLARENET", null, null, null, null)));
        assertTrue(service.isLikelyProxy(geo(null, "M247 Ltd", null, null, null)));
        assertTrue(service.isLikelyProxy(geo(null, null, "Cogent Communications", null, null)));
        assertTrue(service.isLikelyProxy(geo(null, "Zenlayer Inc", null, false, false)));
    }

    @Test
    void isLikelyProxy_shouldNotFlagResidentialOrUnknownSources() {
        assertFalse(service.isLikelyProxy(null));
        assertFalse(service.isLikelyProxy(geo("AS4134 CHINANET-BACKBONE", "China Telecom", "电信宽带", false, false)));
        assertFalse(service.isLikelyProxy(geo(null, null, null, false, false)));
        assertFalse(service.isLikelyProxy(geo(null, null, null, null, null)));
    }

    @Test
    void isLikelyProxyCached_shouldNeverResolveNetwork() {
        assertFalse(service.isLikelyProxyCached("192.168.1.5"), "私有地址恒不判定为代理");
        assertFalse(service.isLikelyProxyCached("203.0.113.5"), "缓存未命中应快速返回 false（不发网络请求）");
        assertFalse(service.isLikelyProxyCached(null));
        assertFalse(service.isLikelyProxyCached("  "));
    }
}
