package com.jdy.cloud.security;

import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.service.ThreatIntelService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.35.0: DDoS 分层防御与溯源取证契约测试。
 */
@ExtendWith(MockitoExtension.class)
class DdosDefenseServiceTest {

    @Mock
    private AttackLogRepository attackLogRepository;
    @Mock
    private ThreatIntelService threatIntelService;

    private AttackGuardService attackGuardService;
    private DdosDefenseService service;

    @BeforeEach
    void setUp() throws Exception {
        attackGuardService = new AttackGuardService(attackLogRepository);
        set(attackGuardService, "enabled", true);
        set(attackGuardService, "fail2banBridgeEnabled", true);
        service = new DdosDefenseService(attackGuardService, new TlsProfileResolver(), threatIntelService);
        set(service, "enabled", true);
        set(service, "windowSeconds", 1);
        set(service, "perIpFloodRps", 3);
        set(service, "perIpSevereRps", 6);
        set(service, "endpointFloodRps", 1000);
        set(service, "clusterMemberMinRps", 1);
        set(service, "clusterMinIps", 3);
        set(service, "clusterWindowSeconds", 120);
        set(service, "clusterEvidenceBoost", 10);
        set(service, "globalIpsSurge", 100000);
        set(service, "maxTrackedIps", 20000);
        set(service, "maxScorePerCycle", 300);
    }

    private static void set(Object target, String field, Object value) throws Exception {
        var f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    private MockHttpServletRequest req(String ip, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(ip);
        request.addHeader("User-Agent", "bot/1.0");
        return request;
    }

    @Test
    void observe_shouldScoreL7FloodAboveThreshold() {
        String ip = "203.0.113.200";
        for (int i = 0; i < 5; i++) {
            service.observe(req(ip, "/api/files/list"), ip, false, false);
        }
        assertTrue(attackGuardService.scoreOf(ip) >= 5, "洪水阈值以上应记 DDoS 分");
        assertEquals(5, attackGuardService.scoreOf(ip), "单窗去重只记一次 5 分");
    }

    @Test
    void observe_shouldScoreSevereFloodWithHigherWeight() {
        String ip = "203.0.113.201";
        for (int i = 0; i < 8; i++) {
            service.observe(req(ip, "/api/auth/login"), ip, false, false);
        }
        assertEquals(15, attackGuardService.scoreOf(ip), "洪水 5 分 + 严重洪水 10 分递进升级");
    }

    @Test
    void observe_shouldNeverScoreTrustedSession() {
        String ip = "203.0.113.202";
        for (int i = 0; i < 10; i++) {
            service.observe(req(ip, "/api/files/list"), ip, true, false);
        }
        assertEquals(0, attackGuardService.scoreOf(ip), "登录态/白名单只计数不记分");
        assertTrue(service.summary().get("observed_requests") instanceof Number);
    }

    @Test
    void observe_shouldRecordButNotScoreBlockedTraffic() {
        String ip = "203.0.113.203";
        for (int i = 0; i < 10; i++) {
            service.observe(req(ip, "/api/files/list"), ip, false, true);
        }
        assertEquals(0, attackGuardService.scoreOf(ip), "已封禁流量只记录不记分");
    }

    @Test
    void cluster_shouldBoostEvidenceOnlyWhenMinIpsReached() {
        String[] ips = {"203.0.113.210", "198.51.100.210", "192.0.2.210"};
        for (String ip : ips) {
            for (int i = 0; i < 3; i++) {
                service.observe(req(ip, "/api/search"), ip, false, false);
            }
        }
        service.evaluateClusters();
        for (String ip : ips) {
            assertTrue(attackGuardService.scoreOf(ip) >= 15,
                    "集群证据加成应叠加于自身洪水分之上: " + ip + " score=" + attackGuardService.scoreOf(ip));
        }
    }

    @Test
    void scoreQuota_shouldCapDatabaseWritesPerCycle() throws Exception {
        set(service, "maxScorePerCycle", 2);
        String[] ips = {"203.0.113.220", "198.51.100.220", "192.0.2.220", "203.0.113.221"};
        for (String ip : ips) {
            for (int i = 0; i < 5; i++) {
                service.observe(req(ip, "/api/files/list"), ip, false, false);
            }
        }
        int scored = 0;
        for (String ip : ips) {
            if (attackGuardService.scoreOf(ip) > 0) scored++;
        }
        assertTrue(scored <= 2, "周期配额应限制记分 IP 数（实际 " + scored + "）");
    }

    @Test
    void killSwitch_shouldDisableEverything() throws Exception {
        set(service, "enabled", false);
        String ip = "203.0.113.230";
        for (int i = 0; i < 20; i++) {
            service.observe(req(ip, "/api/files/list"), ip, false, false);
        }
        assertEquals(0, attackGuardService.scoreOf(ip), "总开关关闭时零处置");
    }

    @Test
    void flush_shouldWriteTotalsAndEventsToLogFile() throws Exception {
        Path logFile = Files.createTempFile("ironwall-ddos-test", ".log");
        try {
            set(service, "logPath", logFile.toString());
            String ip = "203.0.113.240";
            for (int i = 0; i < 8; i++) {
                service.observe(req(ip, "/api/files/list"), ip, false, false);
            }
            service.flushToLog();
            String content = Files.readString(logFile);
            assertTrue(content.contains("\"type\":\"totals\""), "落盘应含全局计数行");
            assertTrue(content.contains("203.0.113.240"), "落盘应含洪水来源 IP");
        } finally {
            Files.deleteIfExists(logFile);
        }
    }

    @Test
    void forensics_shouldReportSourcesAndAttackCrossReference() {
        String ip = "203.0.113.250";
        for (int i = 0; i < 5; i++) {
            service.observe(req(ip, "/api/files/list"), ip, false, false);
        }
        service.markAttack(ip, "/api/files/list", "SQL注入");
        var report = service.forensicReport();
        assertNotNull(report.get("top_sources"));
        assertNotNull(report.get("clusters"));
        var perIp = service.forensicForIp(ip);
        assertEquals(Boolean.TRUE, perIp.get("is_attack_source"), "攻击源交叉标记应可见");
        assertNotNull(service.summary().get("active_floods"));
    }
}
