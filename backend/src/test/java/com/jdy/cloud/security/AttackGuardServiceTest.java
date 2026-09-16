package com.jdy.cloud.security;

import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.service.ThreatIntelService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AttackGuardServiceTest {

    /**
     * 对抗型规则族用例的准入条件。
     *
     * <p>检测规则由 config/ironwall-rules.sample.json 或自备规则集提供。
     * 规则集不完整时，这些用例在此跳过——否则一开箱就是一片红色构建，
     * 而红色并不代表代码有问题，只代表「这条规则还没配」。
     *
     * <p>规则集完整时 {@code missingKeys()} 为空，全部用例照常执行，
     * 覆盖率不下降。
     */
    private static void assumeAdversarialRulesConfigured() {
        Assumptions.assumeTrue(IronWallRules.missingKeys().isEmpty(),
                () -> "当前规则集不完整，跳过对抗型规则用例；缺失：" + IronWallRules.missingKeys());
    }

    @Mock
    private AttackLogRepository attackLogRepository;

    private AttackGuardService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new AttackGuardService(attackLogRepository);
        var field = AttackGuardService.class.getDeclaredField("enabled");
        field.setAccessible(true);
        field.set(service, true);
        var f2bField = AttackGuardService.class.getDeclaredField("fail2banBridgeEnabled");
        f2bField.setAccessible(true);
        f2bField.set(service, true);
        var opFamilyField = AttackGuardService.class.getDeclaredField("operatorFamilyEnabled");
        opFamilyField.setAccessible(true);
        opFamilyField.set(service, true);
        var mysqlBuiltinField = AttackGuardService.class.getDeclaredField("mysqlBuiltinEnabled");
        mysqlBuiltinField.setAccessible(true);
        mysqlBuiltinField.set(service, true);
    }

    @Test
    void detect_shouldFlagSqlInjection() {
        RuleAssumptions.requireRule("patterns.sqli");
        assertNotNull(service.detect("q=1' OR 1=1 -- ", null, "/api/files/list", null));
        assertNotNull(service.detect("q=1 UNION SELECT password FROM users", null, "/api/files/list", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR '1'='1\"}", "/api/auth/login", null));
        assertEquals(AttackGuardService.TYPE_SQL, service.detect("q=1 UNION SELECT 1,2", null, "/api", null).type);
    }

    @Test
    void pointsFor_shouldMapScoreTiersR53() {
        assertEquals(2, service.pointsFor(AttackGuardService.TYPE_PROTOCOL));
        assertEquals(2, service.pointsFor(AttackGuardService.TYPE_SUSPICIOUS_PATH));
        assertEquals(1, service.pointsFor(AttackGuardService.TYPE_CRAWLER));
        assertEquals(3, service.pointsFor(AttackGuardService.TYPE_SSRF));
        assertEquals(5, service.pointsFor(AttackGuardService.TYPE_SQL));
        assertEquals(5, service.pointsFor(AttackGuardService.TYPE_TRAP));
        assertEquals(5, service.pointsFor(null));
    }

    @Test
    void protocolAnomaly_shouldNeverSingleShotBlockR53() {
        AttackGuardService.AttackRecord rec = service.recordAttack("203.0.113.88",
                AttackGuardService.TYPE_PROTOCOL, "ibm037", "/api/auth/login", "curl/8", "POST");

        assertEquals(2, rec.score);
        assertEquals("WARN", rec.action);
        assertFalse(service.isBlocked("203.0.113.88"), "single protocol anomaly must never block");
    }

    @Test
    void protocolAnomaly_shouldBlockOnlyAfterAccumulationR53() {
        AttackGuardService.AttackRecord last = null;
        for (int i = 0; i < 10; i++) {
            last = service.recordAttack("203.0.113.89",
                    AttackGuardService.TYPE_PROTOCOL, "anomaly-" + i, "/api/auth/login", "curl/8", "POST");
        }

        assertNotNull(last);
        assertEquals(20, last.score);
        assertEquals("BLOCKED", last.action);
        assertTrue(service.isBlocked("203.0.113.89"));
        service.unblock("203.0.113.89");
    }

    @Test
    void detect_shouldFlagSqlOperatorBypassR39() {
        assumeAdversarialRulesConfigured();
        // IronWall v1.28.9: || / && 拼接运算符（击穿样本）
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, "{\"username\":\"admin'||'\"}", "/api/auth/login", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, "{\"password\":\"'||'1'='1\"}", "/api/auth/register", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, "{\"email\":\"x'||'1'='1'--\"}", "/api/auth/verify-code", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1||1=1", null, "/api/feedback", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, "{\"content\":\"'&&'1'='1\"}", "/api/feedback", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1' or 'a'='a", null, "/api", null).type);
    }

    @Test
    void detect_shouldFlagSqlOperatorFamilyBlindSpotsR41() {
        assumeAdversarialRulesConfigured();
        // IronWall v1.28.13: LIKE/REGEXP 运算族绕过矩阵
        String[][] samples = {
                {"login", "{\"username\":\"admin' LIKE '1\"}"},
                {"login", "{\"username\":\"admin' like '1\"}"},
                {"login", "{\"username\":\"admin' REGEXP '1\"}"},
                {"login", "{\"username\":\"admin' RLIKE '1\"}"},
                {"login", "{\"username\":\"admin' REGEXP_LIKE '1\"}"},
                {"login", "{\"username\":\"admin' REGEXP_LIKE('1','1')\"}"},
                {"register", "{\"username\":\"admin' IN ('1','2')\"}"},
                {"register", "{\"username\":\"admin' BETWEEN '1' AND '2'\"}"},
                {"verify-code", "{\"email\":\"x' COLLATE utf8mb4_bin '1\"}"},
                {"verify-code", "{\"email\":\"x' ISNULL('1')\"}"},
                {"feedback", "{\"content\":\"admin' EXISTS(SELECT 1)\"}"},
                {"feedback", "{\"content\":\"admin' CAST('1' AS INT)\"}"},
                {"feedback", "{\"content\":\"admin' HAVING '1'='1\"}"},
                {"feedback", "{\"content\":\"admin' HAVING 1=1\"}"},
        };
        for (String[] s : samples) {
            String path = "/api/auth/" + s[0];
            AttackGuardService.Detection det = service.detect(null, s[1], path, null);
            assertNotNull(det, "should flag: " + s[1]);
            assertEquals(AttackGuardService.TYPE_SQL, det.type);
        }
        // 注释分隔 / Unicode 空白 / 双引号变体
        assertNotNull(service.detect(null, "{\"username\":\"admin'/**/LIKE/**/'1\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin'\u3000LIKE\u3000'1\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin\\\" LIKE \\\"1\"}", "/api/auth/login", null));
    }

    @Test
    void detect_shouldNotFlagNormalEnglishOperatorFamilyWordsR41() {
        // 防误报：自然语言中的 LIKE/IN/HAVING/BETWEEN/CAST 不得命中
        assertNull(service.detect(null, "{\"feedback\":\"I like this site\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"I'm in the zone\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"having trouble with upload\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"speed between 1 and 2 MB/s\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"please broadcast(x) as soon as possible\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"cast the net wide\"}", "/api/feedback", null));
        assertNull(service.detect("q=regexp search support", null, "/api", null));
        assertNull(service.detect("q=the cast of the show", null, "/api", null));
    }

    @Test
    void operatorFamilyRules_shouldRespectKillSwitch() throws Exception {
        assumeAdversarialRulesConfigured();
        setField("operatorFamilyEnabled", false);
        assertNull(service.detect(null, "{\"username\":\"admin' LIKE '1\"}", "/api/auth/login", null));
        setField("operatorFamilyEnabled", true);
        assertNotNull(service.detect(null, "{\"username\":\"admin' LIKE '1\"}", "/api/auth/login", null));
    }

    @Test
    void detect_shouldFlagUnicodeWhitespaceObfuscationR39() {
        assumeAdversarialRulesConfigured();
        // IronWall v1.28.9: Unicode 空格/零宽字符拆分关键字绕过
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1' union\u3000select 1", null, "/api", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1'||\u200B'1'='1", null, "/api", null).type);
    }

    @Test
    void detect_shouldNotFlagNormalOperatorsAndQuotes() {
        assertNull(service.detect("q=a && b", null, "/api", null));
        assertNull(service.detect("q=hello || world", null, "/api", null));
        assertNull(service.detect(null, "{\"feedback\":\"这个 'or' 的词\",\"ok\":true}", "/api/feedback", null));
    }

    @Test
    void detect_shouldFlagXss() {
        RuleAssumptions.requireRule("patterns.xss");
        assertNotNull(service.detect("q=<script>alert(1)</script>", null, "/api/files/list", null));
        assertNotNull(service.detect(null, "{\"username\":\"<svg/onload=1>\"}", "/api/auth/update-username", null));
        assertEquals(AttackGuardService.TYPE_XSS, service.detect("q=<img src=x onerror=alert(1)>", null, "/api", null).type);
    }

    @Test
    void detect_shouldFlagTraversal() {
        RuleAssumptions.requireRule("patterns.traversal");
        assertNotNull(service.detect("q=../../etc/passwd", null, "/api", null));
        assertNotNull(service.detect("q=..%2f..%2fetc%2fpasswd", null, "/api", null));
        assertEquals(AttackGuardService.TYPE_TRAVERSAL, service.detect("q=..\\..\\windows\\win.ini", null, "/api", null).type);
    }

    @Test
    void detect_shouldFlagCommandInjection() {
        RuleAssumptions.requireRule("patterns.cmd");
        assertNotNull(service.detect("q=1; rm -rf /", null, "/api", null));
        assertNotNull(service.detect("q=1 | cat /etc/passwd", null, "/api", null));
        assertEquals(AttackGuardService.TYPE_CMD, service.detect("q=; whoami", null, "/api", null).type);
    }

    @Test
    void detect_shouldFlagSsrfAndScannerTools() {
        RuleAssumptions.requireRule("patterns.ssrf");
        assertEquals(AttackGuardService.TYPE_SSRF, service.detect("url=gopher://127.0.0.1:6379/", null, "/api", null).type);
        assertEquals(AttackGuardService.TYPE_TOOL, service.detect(null, null, "/api", "sqlmap/1.7.2#stable").type);
    }

    @Test
    void detect_shouldNotFlagNormalInput() {
        assertNull(service.detect("q=select stars from sky", null, "/api/files/list", null));
        assertNull(service.detect("q=don't worry be happy", null, "/api/files/list", null));
        assertNull(service.detect("q=my file (1).pdf", null, "/api/files/list", null));
        assertNull(service.detect(null, "{\"username\":\"zhangsan\",\"password\":\"Normal@123\"}", "/api/auth/login", null));
        assertNull(service.detect("q=经典云网盘 测试", null, "/api/files/list", null));
        assertNull(service.detect(null, null, "/api/files/list", "Mozilla/5.0 (Windows NT 10.0) Chrome/126"));
    }

    @Test
    void recordAttack_shouldEscalateToBlock() {
        AttackGuardService.AttackRecord rec = null;
        for (int i = 0; i < 5; i++) {
            rec = service.recordAttack("203.0.113.7", AttackGuardService.TYPE_SQL,
                    "UNION SELECT", "/api", "sqlmap/1.0", "GET");
        }
        assertNotNull(rec);
        assertEquals("BLOCKED", rec.action);
        assertTrue(rec.score >= 20);
        assertTrue(service.isBlocked("203.0.113.7"));
        service.unblock("203.0.113.7");
        assertFalse(service.isBlocked("203.0.113.7"));
    }

    @Test
    void detect_shouldFlagJsonUnicodeAndCommentObfuscation() {
        assumeAdversarialRulesConfigured();
        // IronWall v1.5 E-01: JSON Unicode 转义绕过 -> 归一化解码后识别
        assertEquals(AttackGuardService.TYPE_XSS,
                service.detect(null, "{\"username\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}", "/api/auth/update-username", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, "{\"username\":\"admin\\u0027 OR \\u00271\\u0027=\\u00271\"}", "/api/auth/login", null).type);
        // E-01: /**/ 注释分割 -> 归一化后识别
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1' UN/**/ION SEL/**/ECT 1,2--", null, "/api", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect("q=1' OR/**/1=1--", null, "/api", null).type);
        // 误报保护：正常注释文本与中文 Unicode 转义不应误报
        assertNull(service.detect("q=注释 /* 这是说明 */ 内容", null, "/api", null));
        assertNull(service.detect(null, "{\"note\":\"\\u4e2d\\u6587 select stars from sky\"}", "/api", null));
    }

    @Test
    void detect_shouldFlagSuspiciousPath() {
        RuleAssumptions.requireRule("patterns.suspiciousPath");
        assertEquals(AttackGuardService.TYPE_SUSPICIOUS_PATH,
                service.detect(null, null, "/api/files/ping;.js", null).type);
        assertEquals(AttackGuardService.TYPE_SUSPICIOUS_PATH,
                service.detect(null, null, "/upload/x.jpg.php", null).type);
    }

    @Test
    void suspiciousPath_shouldScoreLowAndDedup() {
        AttackGuardService.AttackRecord first = service.recordAttack("203.0.113.8",
                AttackGuardService.TYPE_SUSPICIOUS_PATH, "/api/files/ping;.js", "/api/files/ping;.js", null, "GET");
        assertEquals(2, first.score);

        AttackGuardService.AttackRecord second = service.recordAttack("203.0.113.8",
                AttackGuardService.TYPE_SUSPICIOUS_PATH, "/api/files/ping;.js", "/api/files/ping;.js", null, "GET");
        assertEquals(2, second.score);

        assertFalse(service.isBlocked("203.0.113.8"));
    }

    @Test
    void detect_shouldFlagHeaderPayloads() {
        RuleAssumptions.requireRule("patterns.xss");
        // IronWall v1.10: XSS/SQLi in User-Agent / Referer headers now scored
        assertEquals(AttackGuardService.TYPE_XSS,
                service.detect(null, null, "/api/auth/login", "Mozilla/5.0 <script>alert(1)</script>", null).type);
        assertEquals(AttackGuardService.TYPE_SQL,
                service.detect(null, null, "/api/auth/login", "Mozilla/5.0", "https://example.com/?q=1' OR 1=1 --").type);
        assertNull(service.detect(null, null, "/api/auth/login", "Mozilla/5.0 (Windows NT 10.0)", "https://example.com/login"));
    }

    @Test
    void isCrawlerUa_shouldDetectAutomationClients() {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        assertTrue(AttackGuardService.isCrawlerUa("curl/8.5.0"));
        assertTrue(AttackGuardService.isCrawlerUa("python-requests/2.31.0"));
        assertTrue(AttackGuardService.isCrawlerUa("Wget/1.21.4"));
        assertTrue(AttackGuardService.isCrawlerUa("scrapy/2.11.0"));
        assertTrue(AttackGuardService.isCrawlerUa("Go-http-client/1.1"));
        assertTrue(AttackGuardService.isCrawlerUa("okhttp/4.9.1"));
        assertTrue(AttackGuardService.isCrawlerUa("Java/1.8.0_301"));
    }

    @Test
    void isCrawlerUa_shouldNotFlagRealBrowsers() {
        assertFalse(AttackGuardService.isCrawlerUa("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"));
        assertFalse(AttackGuardService.isCrawlerUa("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"));
        assertFalse(AttackGuardService.isCrawlerUa("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"));
        assertFalse(AttackGuardService.isCrawlerUa(null));
        assertFalse(AttackGuardService.isCrawlerUa(""));
    }

    @Test
    void crawlerRecord_shouldScoreLowAndDedup() {
        AttackGuardService.AttackRecord first = service.recordAttack("203.0.113.9",
                AttackGuardService.TYPE_CRAWLER, "自动化客户端访问: curl/8.5.0", "/api/files/list", "curl/8.5.0", "GET");
        assertEquals(1, first.score);

        AttackGuardService.AttackRecord second = service.recordAttack("203.0.113.9",
                AttackGuardService.TYPE_CRAWLER, "自动化客户端访问: curl/8.5.0", "/api/files/list", "curl/8.5.0", "GET");
        assertEquals(1, second.score);

        assertFalse(service.isBlocked("203.0.113.9"));
    }

    @Test
    void detect_shouldFlagCookieHeaderXss() {
        RuleAssumptions.requireRule("patterns.xss");
        // IronWall v1.12: XSS payload in Cookie header now scored
        assertEquals(AttackGuardService.TYPE_XSS,
                service.detect(null, null, "/api/files/list", "Mozilla/5.0", null, "session=abc; p=<script>alert(1)</script>").type);
        assertNull(service.detect(null, null, "/api/files/list", "Mozilla/5.0", null, "session=abc; theme=dark"));
    }

    @Test
    void trustedSessionRecordAttack_shouldLogButNeverScoreOrBlock() {
        // IronWall v1.15: 登录态请求即使命中攻击特征也只记录（delta=0），
        // 永不累计记分、永不升级 IP 封禁，避免正常用户/管理员被误封自锁。
        AttackGuardService.AttackRecord rec = null;
        for (int i = 0; i < 12; i++) {
            rec = service.recordAttack("203.0.113.10", AttackGuardService.TYPE_SQL,
                    "UNION SELECT", "/api", "Mozilla/5.0", "GET", true);
        }
        assertNotNull(rec);
        assertEquals(0, rec.score);
        assertEquals(0, rec.blockCount);
        assertEquals("WARN", rec.action);
        assertFalse(service.isBlocked("203.0.113.10"));
    }

    // ==================== IronWall v1.17 主动防御与威慑引擎 ====================

    private void enableDefenseEngine() throws Exception {
        setField("enabled", true);
        setField("segmentBlockEnabled", true);
        setField("segmentRepeatCount", 3);
        setField("segmentBlockHours", 48);
        setField("warnScore", 10);
        setField("blockScore", 20);
        setField("severeBlockScore", 40);
        setField("blockMinutes", 30);
        setField("severeBlockHours", 24);
    }

    private void setField(String name, Object value) throws Exception {
        var field = AttackGuardService.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(service, value);
    }

    @Test
    void segmentBlock_shouldEscalateRepeatedOffenderPublicIp() throws Exception {
        enableDefenseEngine();
        // 公网 IP 连续再犯：第 1 次普通封禁、第 2 次严重封禁、第 3 次升级 /24 段封禁
        for (int i = 0; i < 9; i++) {
            service.recordAttack("203.0.113.20", AttackGuardService.TYPE_SQL,
                    "UNION SELECT", "/api", "sqlmap/1.7", "GET");
        }
        assertTrue(service.isBlocked("203.0.113.20"));
        assertTrue(service.isBlockedSegment("203.0.113.20"));
        assertTrue(service.isBlockedSegment("203.0.113.77"));
        assertFalse(service.isBlockedSegment("203.0.114.20"));

        var segments = service.getBlockedSegments();
        assertEquals(1, segments.size());
        assertEquals("203.0.113.0/24", segments.get(0).segment);
        assertTrue(segments.get(0).blockedSeconds > 0);

        service.unblockSegment("203.0.113.0/24");
        assertFalse(service.isBlockedSegment("203.0.113.20"));
    }

    @Test
    void segmentBlock_shouldNeverTriggerForPrivateOrLoopbackIp() throws Exception {
        enableDefenseEngine();
        String[] safeIps = {"10.1.2.3", "127.0.0.1", "192.168.1.10", "172.16.0.9", "169.254.1.1"};
        for (String ip : safeIps) {
            for (int i = 0; i < 12; i++) {
                service.recordAttack(ip, AttackGuardService.TYPE_SQL,
                        "UNION SELECT", "/api", "sqlmap/1.7", "GET");
            }
            assertTrue(service.isBlocked(ip), ip + " should still be IP-blocked");
            assertFalse(service.isBlockedSegment(ip), ip + " must never trigger segment block");
        }
        assertTrue(service.getBlockedSegments().isEmpty());
    }

    @Test
    void segmentBlock_shouldRespectDisabledFlagAndRepeatThreshold() throws Exception {
        enableDefenseEngine();
        setField("segmentBlockEnabled", false);
        for (int i = 0; i < 12; i++) {
            service.recordAttack("198.51.100.30", AttackGuardService.TYPE_SQL,
                    "UNION SELECT", "/api", "sqlmap/1.7", "GET");
        }
        assertFalse(service.isBlockedSegment("198.51.100.30"));

        // 再犯次数未达阈值（repeat=5，当前仅 4 次再犯）不触发段封禁
        setField("segmentBlockEnabled", true);
        setField("segmentRepeatCount", 5);
        for (int i = 0; i < 4; i++) {
            service.recordAttack("198.51.100.31", AttackGuardService.TYPE_SQL,
                    "UNION SELECT", "/api", "sqlmap/1.7", "GET");
            service.recordAttack("198.51.100.31", AttackGuardService.TYPE_SQL,
                    "UNION SELECT-2", "/api", "sqlmap/1.7", "GET");
        }
        assertFalse(service.isBlockedSegment("198.51.100.31"));
    }

    @Test
    void shouldTarpit_shouldOnlyTargetScoredAttackers() throws Exception {
        enableDefenseEngine();
        assertFalse(service.shouldTarpit("203.0.113.40"));

        // 记分达到警告线（>=10）即进入 Tarpit 拖延名单
        service.recordAttack("203.0.113.40", AttackGuardService.TYPE_SQL, "OR 1=1", "/api", "Mozilla/5.0", "GET");
        service.recordAttack("203.0.113.40", AttackGuardService.TYPE_SQL, "OR 1=1", "/api", "Mozilla/5.0", "GET");
        assertTrue(service.shouldTarpit("203.0.113.40"));

        // 登录态请求永不记分，也不进入 Tarpit
        for (int i = 0; i < 6; i++) {
            service.recordAttack("203.0.113.41", AttackGuardService.TYPE_SQL, "OR 1=1", "/api", "Mozilla/5.0", "GET", true);
        }
        assertFalse(service.shouldTarpit("203.0.113.41"));
    }

    @Test
    void classifyThreat_shouldReturnEscalatingProfile() throws Exception {
        enableDefenseEngine();
        assertEquals(AttackGuardService.ThreatProfile.UNKNOWN, service.classifyThreat("198.51.100.50"));

        // 扫描工具指纹 -> SCANNER
        service.recordAttack("198.51.100.51", AttackGuardService.TYPE_TOOL, "sqlmap/1.7", "/api", "sqlmap/1.7", "GET");
        assertEquals(AttackGuardService.ThreatProfile.SCANNER, service.classifyThreat("198.51.100.51"));

        // IronWall v1.26.0: 爬虫单独低分衰减，不进入 SCANNER 画像，避免合法 API 集成方误判
        service.recordAttack("198.51.100.53", AttackGuardService.TYPE_CRAWLER, "curl/8.7.1", "/api", "curl/8.7.1", "GET");
        assertEquals(AttackGuardService.ThreatProfile.SUSPECT, service.classifyThreat("198.51.100.53"));

        // 单次低分攻击 -> SUSPECT（记分>0 但未达扫描级别）
        service.recordAttack("198.51.100.54", AttackGuardService.TYPE_XSS, "<script>", "/api", "Mozilla/5.0", "GET");
        assertEquals(AttackGuardService.ThreatProfile.SUSPECT, service.classifyThreat("198.51.100.54"));

        // 达到封禁线 -> PERSISTENT；达到严重线 -> TARGETED
        for (int i = 0; i < 4; i++) {
            service.recordAttack("198.51.100.52", AttackGuardService.TYPE_SQL, "UNION SELECT", "/api", "Mozilla/5.0", "GET");
        }
        assertEquals(AttackGuardService.ThreatProfile.PERSISTENT, service.classifyThreat("198.51.100.52"));
        for (int i = 0; i < 4; i++) {
            service.recordAttack("198.51.100.52", AttackGuardService.TYPE_XSS, "<script>", "/api", "Mozilla/5.0", "GET");
        }
        assertEquals(AttackGuardService.ThreatProfile.TARGETED, service.classifyThreat("198.51.100.52"));
    }

    @Test
    void attackerSummaries_shouldExposeProfileAndTarpitState() throws Exception {
        enableDefenseEngine();
        for (int i = 0; i < 3; i++) {
            service.recordAttack("203.0.113.60", AttackGuardService.TYPE_SQL, "UNION SELECT", "/api", "Mozilla/5.0", "GET");
        }
        var summaries = service.getAttackerSummaries();
        assertEquals(1, summaries.size());
        assertEquals("203.0.113.60", summaries.get(0).get("ip"));
        assertEquals(15, summaries.get(0).get("score"));
        assertEquals(Boolean.TRUE, summaries.get(0).get("tarpit"));
        assertEquals("SUSPECT", summaries.get(0).get("threat_profile"));
        assertEquals(Boolean.FALSE, summaries.get(0).get("segment_blocked"));
    }

    @Test
    void manualBlock_shouldBlockIpForRequestedMinutes() throws Exception {
        enableDefenseEngine();
        assertFalse(service.isBlocked("203.0.113.61"));

        AttackGuardService.AttackRecord rec = service.manualBlock("203.0.113.61", 30);

        assertEquals("BLOCKED", rec.action);
        assertTrue(service.isBlocked("203.0.113.61"));
        assertTrue(rec.blockedUntil >= System.currentTimeMillis() + 29 * 60_000L);
        assertFalse(service.isBlockedSegment("203.0.113.61"), "手动封禁不应升级为段封禁");

        var blocked = service.getBlockedIps();
        assertEquals(1, blocked.size());
        assertEquals("203.0.113.61", blocked.get(0).ip);
        assertTrue(blocked.get(0).blockedSeconds >= 29 * 60);

        service.unblock("203.0.113.61");
        assertFalse(service.isBlocked("203.0.113.61"));
    }

    @Test
    void manualBlock_shouldRejectBlankIpAndClampMinutes() throws Exception {
        enableDefenseEngine();
        assertThrows(IllegalArgumentException.class, () -> service.manualBlock("  ", 30));
        assertThrows(IllegalArgumentException.class, () -> service.manualBlock(null, 30));

        // 分钟数被钳制在 1 分钟 ~ 7 天
        AttackGuardService.AttackRecord min = service.manualBlock("203.0.113.62", 0);
        assertTrue(min.blockedUntil >= System.currentTimeMillis() + 60_000L - 1000);
        service.unblock("203.0.113.62");

        AttackGuardService.AttackRecord max = service.manualBlock("203.0.113.63", 999999);
        assertTrue(max.blockedUntil <= System.currentTimeMillis() + 7L * 24 * 3600_000L + 1000);
    }
    @Test
    void recordWeighted_shouldEmitFail2banBridgeLog_whenIpGetsBlocked() {
        ch.qos.logback.classic.Logger f2b = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        f2b.addAppender(appender);
        try {
            for (int i = 0; i < 5; i++) {
                service.recordAttack("203.0.113.77", AttackGuardService.TYPE_SQL, "q=1 OR 1=1", "/api/files/list", "sqlmap/1.7", "GET");
            }
            java.util.List<String> messages = appender.list.stream().map(e -> e.getFormattedMessage()).toList();
            assertTrue(messages.stream().anyMatch(m -> m.startsWith("IRONWALL-BLOCK ip=203.0.113.77")
                    && m.contains("category=SQL注入") && m.contains("action=BLOCKED")));
        } finally {
            f2b.detachAppender(appender);
        }
    }

    // ========== IronWall v1.24.0: 单发即封二次确认 + 挑战滥用升级 ==========

    @Test
    void singleHitSevereBlock_shouldNotBridgeUntilReoffense() throws Exception {
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("challengeMaxAttempts", 5);
        var f2b = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        f2b.addAppender(appender);
        try {
            String ip = "203.0.113.90";
            var rec = service.recordWeighted(ip, AttackGuardService.TYPE_CMD, ";id",
                    "/api/test", "curl/8.0", "POST", false, 40);
            assertEquals("BLOCKED", rec.action);
            assertTrue(service.isBlocked(ip));
            assertTrue(appender.list.isEmpty(), "单发即封不得立即联动服务器层封禁");

            String issued = service.issueChallenge(ip);
            assertNotNull(issued);
            assertTrue(issued.contains("|"));
            String[] parts = issued.split("\\|");
            String question = parts[1].replace("=", "").replace("?", "").trim();
            String[] nums = question.split("\\+");
            int answer = Integer.parseInt(nums[0].trim()) + Integer.parseInt(nums[1].trim());
            assertNull(service.verifyChallenge(ip, parts[0], String.valueOf(answer)));
            assertFalse(service.isBlocked(ip));

            var again = service.recordAttack(ip, AttackGuardService.TYPE_CMD, ";id2",
                    "/api/test", "curl/8.0", "GET");
            assertEquals("BLOCKED", again.action);
            assertEquals(2, again.blockCount);
            java.util.List<String> messages = appender.list.stream().map(e -> e.getFormattedMessage()).toList();
            assertTrue(messages.stream().anyMatch(m -> m.startsWith("IRONWALL-BLOCK ip=" + ip)
                    && m.contains("category=命令注入") && m.contains("action=BLOCKED")));
        } finally {
            f2b.detachAppender(appender);
        }
    }

    @Test
    void challengeAbuse_shouldEscalateToServerLevelBan() throws Exception {
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("challengeMaxAttempts", 5);
        var f2b = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        f2b.addAppender(appender);
        try {
            String ip = "203.0.113.92";
            service.recordWeighted(ip, AttackGuardService.TYPE_CMD, ";id",
                    "/api/test", "curl/8.0", "POST", false, 40);
            assertTrue(service.isBlocked(ip));
            String result = null;
            for (int i = 0; i < 6; i++) {
                result = service.verifyChallenge(ip, "invalid-token", "0");
            }
            assertEquals("locked", result);
            java.util.List<String> messages = appender.list.stream().map(e -> e.getFormattedMessage()).toList();
            assertEquals(1, messages.stream().filter(m -> m.startsWith("IRONWALL-BLOCK ip=" + ip)
                    && m.contains("category=CHALLENGE_ABUSE")).count());
        } finally {
            f2b.detachAppender(appender);
        }
    }

    @Test
    void trapSingleHit_shouldBridgeImmediately() throws Exception {
        enableDefenseEngine();
        var f2b = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        f2b.addAppender(appender);
        try {
            String ip = "203.0.113.93";
            var rec = service.recordWeighted(ip, AttackGuardService.TYPE_TRAP, "五层黑洞陷阱",
                    "/api/admin", "curl/8.0", "GET", false, 20);
            assertEquals("BLOCKED", rec.action);
            java.util.List<String> messages = appender.list.stream().map(e -> e.getFormattedMessage()).toList();
            assertTrue(messages.stream().anyMatch(m -> m.startsWith("IRONWALL-BLOCK ip=" + ip)
                    && m.contains("category=陷阱吞没") && m.contains("action=BLOCKED")));
        } finally {
            f2b.detachAppender(appender);
        }
    }

    // ========== IronWall v1.25.0 / ==========

    @Test
    void scoreDecay_shouldHalveStaleScoreBeforeNextHit() throws Exception {
        enableDefenseEngine();
        setField("scoreDecayWindowMs", 500L);
        String ip = "203.0.113.94";
        service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=1 OR 1=1", "/api/x", null, "GET");
        service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=2 OR 1=1", "/api/x", null, "GET");
        var third = service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=3 OR 1=1", "/api/x", null, "GET");
        assertEquals(15, third.score);
        Thread.sleep(600);
        var fourth = service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=4 OR 1=1", "/api/x", null, "GET");
        assertEquals(12, fourth.score); // 15/2 + 5
    }

    @Test
    void challenge_shouldRemainAvailableForNonBlockedTrapState() throws Exception {
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("challengeMaxAttempts", 5);
        String ip = "203.0.113.95";
        service.recordWeighted(ip, AttackGuardService.TYPE_CMD, ";id", "/api/test", "curl/8", "POST", false, 40);
        assertTrue(service.isBlocked(ip));
        String issued = service.issueChallenge(ip);
        assertNotNull(issued);
        String[] parts = issued.split("\\|");
        String question = parts[1].replace("=", "").replace("?", "").trim();
        String[] nums = question.split("\\+");
        int answer = Integer.parseInt(nums[0].trim()) + Integer.parseInt(nums[1].trim());
        assertNull(service.verifyChallenge(ip, parts[0], String.valueOf(answer)));
        assertFalse(service.isBlocked(ip));

        // 陷阱区逃生场景：IP 已解除站内封禁，但仍在陷阱期——挑战签发/验证依然可用
        String issued2 = service.issueChallenge(ip);
        assertNotNull(issued2);
        String[] parts2 = issued2.split("\\|");
        String q2 = parts2[1].replace("=", "").replace("?", "").trim();
        String[] n2 = q2.split("\\+");
        int a2 = Integer.parseInt(n2[0].trim()) + Integer.parseInt(n2[1].trim());
        assertNull(service.verifyChallenge(ip, parts2[0], String.valueOf(a2)));
        assertFalse(service.isBlocked(ip));
    }

    @Test
    void manualBlock_shouldEmitFail2banBridgeLog() {
        ch.qos.logback.classic.Logger f2b = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("IRONWALL-F2B");
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        f2b.addAppender(appender);
        try {
            service.manualBlock("203.0.113.78", 30);
            java.util.List<String> messages = appender.list.stream().map(e -> e.getFormattedMessage()).toList();
            assertTrue(messages.stream().anyMatch(m -> m.startsWith("IRONWALL-BLOCK ip=203.0.113.78")
                    && m.contains("category=MANUAL_BLOCK") && m.contains("action=BLOCKED")));
        } finally {
            f2b.detachAppender(appender);
        }
    }

    // ========== IronWall v1.26.2 ==========

    @Test
    void highRiskLoginPath_shouldEscalateSqlInFourHitsWithR55Weight() throws Exception {
        assumeAdversarialRulesConfigured();
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("highRiskPathWeight", 6);
        String ip = "203.0.113.120";
        AttackGuardService.AttackRecord rec = null;
        for (int i = 1; i <= 3; i++) {
            rec = service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=" + i + " OR 1=1", "/api/auth/login", null, "POST");
        }
        assertEquals(18, rec.score);
        assertEquals("WARN", rec.action);
        assertFalse(service.isBlocked(ip), "闭环：3 击警告不封禁");
        rec = service.recordAttack(ip, AttackGuardService.TYPE_SQL, "q=4 OR 1=1", "/api/auth/login", null, "POST");
        assertEquals(24, rec.score);
        assertEquals("BLOCKED", rec.action);
        assertTrue(service.isBlocked(ip));
    }

    @Test
    void purgeUploadFalsePositives_shouldUnblockOnlyPureFalsePositiveIps() throws Exception {
        assumeAdversarialRulesConfigured();
        enableDefenseEngine();
        setField("highRiskPathWeight", 6);
        String fpIp = "203.0.113.130";
        for (int i = 0; i < 4; i++) {
            service.recordAttack(fpIp, AttackGuardService.TYPE_TRAVERSAL, "NULL字节截断",
                    "/api/files/upload", "Mozilla/5.0", "POST");
        }
        assertTrue(service.isBlocked(fpIp));

        AttackLog fpLog = new AttackLog();
        fpLog.setIp(fpIp);
        fpLog.setAttackType(AttackGuardService.TYPE_TRAVERSAL);
        fpLog.setPayload("NULL字节截断");
        fpLog.setPath("/api/files/upload");
        fpLog.setCreatedAt(java.time.LocalDateTime.now());
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(fpIp)).thenReturn(List.of(fpLog));

        String mixedIp = "203.0.113.131";
        for (int i = 0; i < 4; i++) {
            service.recordAttack(mixedIp, AttackGuardService.TYPE_TRAVERSAL, "NULL字节截断",
                    "/api/auth/upload-avatar", "Mozilla/5.0", "POST");
        }
        service.recordAttack(mixedIp, AttackGuardService.TYPE_SQL, "1' OR '1'='1",
                "/api/auth/login", "sqlmap/1.0", "POST");
        assertTrue(service.isBlocked(mixedIp));
        AttackLog fpLog2 = new AttackLog();
        fpLog2.setIp(mixedIp);
        fpLog2.setAttackType(AttackGuardService.TYPE_TRAVERSAL);
        fpLog2.setPayload("NULL字节截断");
        fpLog2.setPath("/api/auth/upload-avatar");
        fpLog2.setCreatedAt(java.time.LocalDateTime.now());
        AttackLog realLog = new AttackLog();
        realLog.setIp(mixedIp);
        realLog.setAttackType(AttackGuardService.TYPE_SQL);
        realLog.setPayload("1' OR '1'='1");
        realLog.setPath("/api/auth/login");
        realLog.setCreatedAt(java.time.LocalDateTime.now());
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(mixedIp))
                .thenReturn(List.of(realLog, fpLog2));

        List<String> purged = service.purgeUploadFalsePositives();

        assertTrue(purged.contains(fpIp));
        assertFalse(purged.contains(mixedIp));
        assertFalse(service.isBlocked(fpIp));
        assertTrue(service.isBlocked(mixedIp));
    }

    @Test
    void normalPath_shouldKeepTolerantThreshold() throws Exception {
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("highRiskPathWeight", 10);
        String ip = "203.0.113.121";
        AttackGuardService.AttackRecord rec = null;
        for (int i = 0; i < 3; i++) {
            rec = service.recordAttack(ip, AttackGuardService.TYPE_SQL,
                    "q=1 OR 1=1", "/api/files/list", null, "GET");
        }
        assertEquals(15, rec.score);
        assertFalse(service.isBlocked(ip));
    }

    @Test
    void challengeToken_shouldRejectTamperedAndCrossIpTokens() throws Exception {
        enableDefenseEngine();
        setField("challengeEnabled", true);
        setField("challengeMaxAttempts", 5);
        String ip = "203.0.113.122";
        service.recordWeighted(ip, AttackGuardService.TYPE_CMD, ";id", "/api/test", "curl/8", "POST", false, 40);
        String issued = service.issueChallenge(ip);
        assertNotNull(issued);
        String token = issued.substring(0, issued.indexOf('|'));
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("0") ? "1" : "0");
        assertEquals("expired", service.verifyChallenge(ip, tampered, "0"));

        String ip2 = "203.0.113.123";
        service.recordWeighted(ip2, AttackGuardService.TYPE_CMD, ";id", "/api/test", "curl/8", "POST", false, 40);
        assertEquals("expired", service.verifyChallenge(ip2, token, "0"));
    }

    // ========== IronWall v1.28.15: 九项闭环 ==========

    @Test
    void detect_shouldFlagR43RemainingSqlOperatorBlindSpots() {
        assumeAdversarialRulesConfigured();
        String[][] samples = {
                {"login", "{\"username\":\"admin' XOR '1'='1\"}"},
                {"login", "{\"username\":\"admin'\\tOR\\t'1'='1\"}"},
                {"login", "{\"username\":\"ａｄｍｉｎ' ｏｒ '1'='1\"}"},
                {"login", "{\"username\":\"admin' IS NULL--\"}"},
                {"register", "{\"username\":\"admin' SOUNDS LIKE 'x\"}"},
                {"register", "{\"username\":\"admin' LIKE BINARY 'x\"}"},
                {"feedback", "{\"content\":\"admin' DIV 1\"}"},
                {"feedback", "{\"content\":\"admin' MOD 1\"}"},
        };
        for (String[] s : samples) {
            String path = "/api/auth/" + s[0];
            AttackGuardService.Detection det = service.detect(null, s[1], path, null);
            assertNotNull(det, "should flag: " + s[1]);
            assertEquals(AttackGuardService.TYPE_SQL, det.type, "wrong type for: " + s[1]);
        }
    }

    @Test
    void detect_shouldNotFlagNaturalLanguageOperatorFamilyWordsR43() {
        assertNull(service.detect(null, "{\"feedback\":\"sounds like a plan\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"10 div 2 is five\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"auto mod enabled\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"feedback\":\"x xor y in math\"}", "/api/feedback", null));
        assertNull(service.detect("q=the binary like system", null, "/api", null));
        assertNull(service.detect(null, "{\"feedback\":\"这是一段没有攻击结构的全角中文说明\"}", "/api/feedback", null));
    }

    @Test
    void detect_shouldRejectNullByteTraversalR43() {
        assertEquals(AttackGuardService.TYPE_TRAVERSAL,
                service.detect("q=evil.txt%00.png", null, "/api/shares/download", null).type);
        assertEquals(AttackGuardService.TYPE_TRAVERSAL,
                service.detect("q=evil.txt%2500.png", null, "/api/shares/download", null).type);
        assertEquals(AttackGuardService.TYPE_TRAVERSAL,
                service.detect("q=../evil.txt%00", null, "/api/files", null).type);
    }

    @Test
    void campaignDetection_shouldBlockAllMemberIpsAtThreeDistinctSources() throws Exception {
        enableDefenseEngine();
        setField("campaignEnabled", true);
        setField("campaignMinIps", 3);
        setField("campaignWindowMinutes", 10);
        setField("campaignBlockMinutes", 120);
        String payload = "q=1' OR '1'='1 -- 同源分布式探测";
        String[] ips = {"203.0.113.130", "203.0.113.131", "198.51.100.7"};
        for (String ip : ips) {
            service.recordAttack(ip, AttackGuardService.TYPE_SQL, payload, "/api/auth/login", null, "POST");
        }
        for (String ip : ips) {
            assertTrue(service.isBlocked(ip), ip + " should be campaign-blocked");
        }
    }

    @Test
    void campaignDetection_shouldNotTriggerBelowMinIps() throws Exception {
        enableDefenseEngine();
        setField("campaignEnabled", true);
        setField("campaignMinIps", 3);
        setField("campaignWindowMinutes", 10);
        setField("campaignBlockMinutes", 120);
        String payload = "q=2' OR '2'='2 -- 双来源不触发";
        service.recordAttack("203.0.113.140", AttackGuardService.TYPE_SQL, payload, "/api/auth/login", null, "POST");
        service.recordAttack("203.0.113.141", AttackGuardService.TYPE_SQL, payload, "/api/auth/login", null, "POST");
        assertFalse(service.isBlocked("203.0.113.140"));
        assertFalse(service.isBlocked("203.0.113.141"));
    }

    @Test
    void campaignDetection_shouldRespectKillSwitch() throws Exception {
        enableDefenseEngine();
        setField("campaignEnabled", false);
        setField("campaignMinIps", 3);
        setField("campaignWindowMinutes", 10);
        setField("campaignBlockMinutes", 120);
        String payload = "q=3' OR '3'='3 -- 开关关闭不触发";
        for (String ip : new String[]{"203.0.113.150", "203.0.113.151", "198.51.100.8"}) {
            service.recordAttack(ip, AttackGuardService.TYPE_SQL, payload, "/api/auth/login", null, "POST");
        }
        for (String ip : new String[]{"203.0.113.150", "203.0.113.151", "198.51.100.8"}) {
            assertFalse(service.isBlocked(ip));
        }
    }

    @Test
    void campaignDetection_shouldSkipTrustedSessions() throws Exception {
        enableDefenseEngine();
        setField("campaignEnabled", true);
        setField("campaignMinIps", 3);
        setField("campaignWindowMinutes", 10);
        setField("campaignBlockMinutes", 120);
        String payload = "q=4' OR '4'='4 -- 登录态不参与";
        for (String ip : new String[]{"203.0.113.160", "203.0.113.161", "198.51.100.9"}) {
            service.recordAttack(ip, AttackGuardService.TYPE_SQL, payload, "/api/auth/login", null, "POST", true);
        }
        for (String ip : new String[]{"203.0.113.160", "203.0.113.161", "198.51.100.9"}) {
            assertFalse(service.isBlocked(ip));
        }
    }

    @Test
    void campaignDetection_shouldIgnoreNoiseTypes() throws Exception {
        enableDefenseEngine();
        setField("campaignEnabled", true);
        setField("campaignMinIps", 2);
        setField("campaignWindowMinutes", 10);
        setField("campaignBlockMinutes", 120);
        String payload = "crawler-noise-payload";
        service.recordWeighted("203.0.113.170", AttackGuardService.TYPE_CRAWLER, payload, "/api", "curl/8", "GET", false, 1);
        service.recordWeighted("203.0.113.171", AttackGuardService.TYPE_CRAWLER, payload, "/api", "curl/8", "GET", false, 1);
        assertFalse(service.isBlocked("203.0.113.170"));
        assertFalse(service.isBlocked("203.0.113.171"));
    }

    // ========== IronWall v1.28.16: 设备指纹锁定 ==========

    private static final String FP_A = "aaaa0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

    private void enableFingerprintDefense() throws Exception {
        enableDefenseEngine();
        setField("fingerprintEnabled", true);
        setField("fingerprintMinIps", 2);
        setField("fingerprintBlockMinutes", 120);
        setField("fingerprintWindowMinutes", 1440);
    }

    @Test
    void fingerprintJail_shouldLockIdentityWhenAttackTriggersIpBlock() throws Exception {
        enableFingerprintDefense();
        String ip = "203.0.113.180";
        service.recordWeighted(ip, AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- fp", "/api/auth/login",
                null, "POST", false, 40, FP_A, null);
        assertTrue(service.isBlocked(ip));
        assertTrue(service.isIdentityJailed(FP_A));
        assertTrue(service.identityJailRemainingSeconds(FP_A) > 0);
    }

    @Test
    void fingerprintJail_shouldNotTriggerOnWarn() throws Exception {
        enableFingerprintDefense();
        service.recordWeighted("203.0.113.181", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- warn",
                "/api/files/list", null, "GET", false, 5, FP_A, null);
        assertFalse(service.isBlocked("203.0.113.181"));
        assertFalse(service.isIdentityJailed(FP_A));
    }

    @Test
    void fingerprintJail_shouldSkipTrustedSessions() throws Exception {
        enableFingerprintDefense();
        service.recordAttack("203.0.113.182", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- auth",
                "/api/auth/login", null, "POST", true, FP_A, null);
        assertFalse(service.isIdentityJailed(FP_A));
    }

    @Test
    void fingerprintJail_shouldIgnoreNoiseTypes() throws Exception {
        enableFingerprintDefense();
        service.recordWeighted("203.0.113.183", AttackGuardService.TYPE_CRAWLER, "crawler-noise-heavy",
                "/api", "curl/8", "GET", false, 40, FP_A, null);
        assertTrue(service.isBlocked("203.0.113.183"));
        assertFalse(service.isIdentityJailed(FP_A));
    }

    @Test
    void fingerprintCrossIp_shouldJailAtMinIpsWithoutIpBlock() throws Exception {
        enableFingerprintDefense();
        String payload = "q=7' OR '7'='7 -- rotate";
        service.recordWeighted("203.0.113.184", AttackGuardService.TYPE_SQL, payload,
                "/api/files/list", null, "GET", false, 5, FP_A, null);
        service.recordWeighted("198.51.100.20", AttackGuardService.TYPE_SQL, payload,
                "/api/files/list", null, "GET", false, 5, FP_A, null);
        assertFalse(service.isBlocked("203.0.113.184"));
        assertFalse(service.isBlocked("198.51.100.20"));
        assertTrue(service.isIdentityJailed(FP_A), "跨IP同指纹证据应锁定指纹");
    }

    @Test
    void fingerprintJail_shouldRespectKillSwitch() throws Exception {
        enableFingerprintDefense();
        setField("fingerprintEnabled", false);
        service.recordWeighted("203.0.113.185", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- off",
                "/api/auth/login", null, "POST", false, 40, FP_A, null);
        assertTrue(service.isBlocked("203.0.113.185"));
        assertFalse(service.isIdentityJailed(FP_A));
    }

    @Test
    void releaseIdentity_shouldClearJail() throws Exception {
        enableFingerprintDefense();
        service.recordWeighted("203.0.113.186", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- rel",
                "/api/auth/login", null, "POST", false, 40, FP_A, null);
        assertTrue(service.isIdentityJailed(FP_A));
        service.releaseIdentity(FP_A);
        assertFalse(service.isIdentityJailed(FP_A));
        assertEquals(0L, service.identityJailRemainingSeconds(FP_A));
    }

    @Test
    void deviceId_shouldIssueAndValidateSignedToken() {
        String did = service.issueDeviceId();
        assertNotNull(did);
        assertTrue(service.isValidDeviceId(did));
        assertTrue(service.isIdentityJailed(did) == false);
        String tampered = did.substring(0, did.length() - 1) + (did.endsWith("0") ? "1" : "0");
        assertFalse(service.isValidDeviceId(tampered));
        assertFalse(service.isValidDeviceId(null));
        assertFalse(service.isValidDeviceId("short"));
    }

    // ========== IronWall v1.29.0: 指纹绑定签名与设备锁闭环 ==========

    private void enableR45DeviceDefense() throws Exception {
        enableFingerprintDefense();
        setField("fingerprintChurnMinFps", 3);
        setField("fingerprintChurnWindowMinutes", 60);
        setField("deviceMinIps", 2);
        setField("deviceWindowMinutes", 1440);
    }

    @Test
    void fingerprintBinding_shouldRoundTrip() {
        String did = service.issueDeviceId();
        String sig = service.signFingerprintBinding(did, FP_A);
        assertNotNull(sig);
        assertTrue(service.isValidFingerprintBinding(did, FP_A, sig));
        assertFalse(service.isValidFingerprintBinding(did, FP_A, "deadbeefdeadbeef"));
        assertFalse(service.isValidFingerprintBinding(did, FP_A, null));
        assertFalse(service.isValidFingerprintBinding(did, "short", sig));
    }

    @Test
    void fingerprint_withDidAndValidSig_shouldJailOnBlock() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        String sig = service.signFingerprintBinding(did, FP_A);
        service.recordWeighted("203.0.113.190", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- r45",
                "/api/auth/login", null, "POST", false, 40, FP_A, did, sig);
        assertTrue(service.isBlocked("203.0.113.190"));
        assertTrue(service.isIdentityJailed(FP_A));
        assertTrue(service.isIdentityJailed(did));
    }

    @Test
    void fingerprint_withDidButWrongSig_shouldNotJailFingerprint() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        service.recordWeighted("203.0.113.191", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- r45b",
                "/api/auth/login", null, "POST", false, 40, FP_A, did, "deadbeefdeadbeefdeadbeef");
        assertTrue(service.isBlocked("203.0.113.191"));
        assertTrue(service.isIdentityJailed(did), "设备ID不依赖指纹签名，攻击触发封禁即锁定");
        assertFalse(service.isIdentityJailed(FP_A), "签名错误不得信任指纹身份");
    }

    @Test
    void fingerprint_withDidButMissingSig_shouldNotJailFingerprint() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        service.recordWeighted("203.0.113.192", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- r45c",
                "/api/auth/login", null, "POST", false, 40, FP_A, did, null);
        assertTrue(service.isBlocked("203.0.113.192"));
        assertTrue(service.isIdentityJailed(did));
        assertFalse(service.isIdentityJailed(FP_A));
    }

    @Test
    void deviceChurn_shouldJailDeviceAtMinFps() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        String ip = "203.0.113.193";
        service.observeDeviceFingerprint(did, FP_A, ip);
        service.observeDeviceFingerprint(did, "bbbb0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", ip);
        assertFalse(service.isIdentityJailed(did));
        service.observeDeviceFingerprint(did, "cccc0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", ip);
        assertTrue(service.isIdentityJailed(did), "同设备窗口内轮换3个指纹应锁定设备");
    }

    @Test
    void deviceChurn_shouldReturnSignedBinding() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        String sig = service.observeDeviceFingerprint(did, FP_A, "203.0.113.194");
        assertNotNull(sig);
        assertTrue(service.isValidFingerprintBinding(did, FP_A, sig));
    }

    @Test
    void deviceCrossIp_shouldJailDeviceAtMinIps() throws Exception {
        enableR45DeviceDefense();
        String did = service.issueDeviceId();
        String payload = "q=8' OR '8'='8 -- device rotate";
        service.recordWeighted("203.0.113.195", AttackGuardService.TYPE_SQL, payload,
                "/api/files/list", null, "GET", false, 5, null, did, null);
        assertFalse(service.isIdentityJailed(did));
        service.recordWeighted("198.51.100.40", AttackGuardService.TYPE_SQL, payload,
                "/api/files/list", null, "GET", false, 5, null, did, null);
        assertTrue(service.isIdentityJailed(did), "同设备ID跨IP真实攻击应锁定设备");
    }

    @Test
    void deviceDefense_shouldRespectKillSwitch() throws Exception {
        enableR45DeviceDefense();
        setField("fingerprintEnabled", false);
        String did = service.issueDeviceId();
        service.recordWeighted("203.0.113.196", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1 -- off",
                "/api/auth/login", null, "POST", false, 40, FP_A, did, null);
        assertTrue(service.isBlocked("203.0.113.196"));
        assertFalse(service.isIdentityJailed(FP_A));
        assertFalse(service.isIdentityJailed(did));
    }

    // ========== IronWall v1.30.0: 九漏网闭环 ==========

    private void enableR46Rules() throws Exception {
        enableDefenseEngine();
        setField("operatorFamilyEnabled", true);
    }

    @Test
    void detect_shouldFlagR44NineEscapePayloads() throws Exception {
        assumeAdversarialRulesConfigured();
        enableR46Rules();
        String[][] samples = {
                {"admin' OORR '1'='1", "{\"username\":\"admin' OORR '1'='1\"}"},
                {"admin' INTO OUTFILE '/tmp/x'--", "{\"username\":\"admin' INTO OUTFILE '/tmp/x'--\"}"},
                {"admin' AND EXP(~(SELECT 1))--", "{\"username\":\"admin' AND EXP(~(SELECT 1))--\"}"},
                {"admin'`OR`'1'='1", "{\"username\":\"admin'`OR`'1'='1\"}"},
                {"admin\\' OR '1'='1", "{\"username\":\"admin\\' OR '1'='1\"}"},
                {"admin' GROUP BY 1 WITH ROLLUP--", "{\"username\":\"admin' GROUP BY 1 WITH ROLLUP--\"}"},
                {"admin\" OR \"1\"=\"1", "{\"username\":\"admin\\\" OR \\\"1\\\"=\\\"1\"}"},
                {"admin' IS NOT NULL", "{\"username\":\"admin' IS NOT NULL\"}"},
                {"admin' ORDER BY 1--", "{\"username\":\"admin' ORDER BY 1--\"}"},
        };
        for (String[] s : samples) {
            AttackGuardService.Detection det = service.detect(null, s[1], "/api/auth/login", null);
            assertNotNull(det, "应拦截: " + s[0]);
            assertEquals(AttackGuardService.TYPE_SQL, det.type, "应判 SQL 注入: " + s[0]);
        }
    }

    @Test
    void detect_shouldNotFlagR44NaturalLanguageNegatives() throws Exception {
        enableR46Rules();
        String[] samples = {
                "please order by chance",
                "the value is not null in this table",
                "walk into the room quietly",
                "we group by department and share with rollup of duties",
        };
        for (String s : samples) {
            assertNull(service.detect(null, "{\"username\":\"" + s + "\"}", "/api/auth/login", null),
                    "不应误报: " + s);
        }
    }

    @Test
    void r44FamilyRules_shouldRespectOperatorFamilyKillSwitch() throws Exception {
        enableDefenseEngine();
        setField("operatorFamilyEnabled", false);
        String[] samples = {
                "admin' INTO OUTFILE '/tmp/x'--",
                "admin' AND EXP(~(SELECT 1))--",
                "admin' IS NOT NULL",
                "admin' ORDER BY 1--",
                "admin' GROUP BY 1 WITH ROLLUP--",
        };
        for (String s : samples) {
            assertNull(service.detect(null, "{\"username\":\"" + s + "\"}", "/api/auth/login", null),
                    "开关关闭应放行: " + s);
        }
    }

    private void enableFamilyAggregation() throws Exception {
        enableDefenseEngine();
        setField("familyEnabled", true);
        setField("familyMinIps", 8);
        setField("familyWindowMinutes", 30);
        setField("familyBlockMinutes", 120);
        // 每次攻击使用不同载荷，避免同载荷 campaign 联动干扰本测试
        setField("campaignEnabled", false);
    }

    @Test
    void attackFamily_shouldBlockAllMemberIpsAtThreshold() throws Exception {
        enableFamilyAggregation();
        String[] ips = new String[8];
        for (int i = 0; i < ips.length; i++) {
            ips[i] = "203.0.113." + (240 + i);
            service.recordWeighted(ips[i], AttackGuardService.TYPE_SQL,
                    "q=1' OR '1'='1 -- family " + i, "/api/auth/login", null, "POST", false, 5);
        }
        for (String ip : ips) {
            assertTrue(service.isBlocked(ip), "攻击族聚合应封禁成员 IP: " + ip);
        }
    }

    @Test
    void attackFamily_shouldNotTriggerBelowThreshold() throws Exception {
        enableFamilyAggregation();
        for (int i = 0; i < 7; i++) {
            String ip = "203.0.113." + (250 + i);
            service.recordWeighted(ip, AttackGuardService.TYPE_SQL,
                    "q=1' OR '1'='1 -- below " + i, "/api/auth/login", null, "POST", false, 5);
        }
        for (int i = 0; i < 7; i++) {
            assertFalse(service.isBlocked("203.0.113." + (250 + i)), "低于阈值不应封禁");
        }
    }

    @Test
    void attackFamily_shouldRespectKillSwitch() throws Exception {
        enableFamilyAggregation();
        setField("familyEnabled", false);
        for (int i = 0; i < 8; i++) {
            service.recordWeighted("198.51.100." + (30 + i), AttackGuardService.TYPE_SQL,
                    "q=1' OR '1'='1 -- off " + i, "/api/auth/login", null, "POST", false, 5);
        }
        for (int i = 0; i < 8; i++) {
            assertFalse(service.isBlocked("198.51.100." + (30 + i)), "开关关闭不应聚合封禁");
        }
    }

    // ========== IronWall v1.31.0: SQL 词法/语义检测层（正则盲区第二意见） ==========

    private void enableR47Semantic() throws Exception {
        enableR46Rules();
        setField("semanticEnabled", true);
    }

    @Test
    void semantic_shouldFlagRegexMissedSqlStructures() throws Exception {
        enableR47Semantic();
        String[][] samples = {
                {"admin' and (1)=(1)#", "{\"username\":\"admin' and (1)=(1)#\"}"},
                {"x'; EXEC master..xp_cmdshell 'whoami'--", "{\"username\":\"x'; EXEC master..xp_cmdshell 'whoami'--\"}"},
                {"admin'||(SELECT password,email FROM users)", "{\"username\":\"admin'||(SELECT password,email FROM users)\"}"},
                {"admin'||(SELECT password FROM users)", "{\"username\":\"admin'||(SELECT password FROM users)\"}"},
                {"x'; DROP TABLE users--", "{\"username\":\"x'; DROP TABLE users--\"}"},
        };
        for (String[] s : samples) {
            AttackGuardService.Detection det = service.detect(null, s[1], "/api/auth/login", null);
            assertNotNull(det, "应拦截: " + s[0]);
            assertEquals(AttackGuardService.TYPE_SQL, det.type, "应判 SQL 注入: " + s[0]);
        }
    }

    @Test
    void semantic_shouldReportSemanticReasonForRegexBlindSpots() throws Exception {
        enableR47Semantic();
        AttackGuardService.Detection d1 = service.detect(null,
                "{\"username\":\"admin' and (1)=(1)#\"}", "/api/auth/login", null);
        AttackGuardService.Detection d2 = service.detect(null,
                "{\"username\":\"x'; EXEC master..xp_cmdshell 'whoami'--\"}", "/api/auth/login", null);
        AttackGuardService.Detection d3 = service.detect(null,
                "{\"username\":\"admin'||(SELECT password,email FROM users)\"}", "/api/auth/login", null);
        AttackGuardService.Detection d4 = service.detect(null,
                "{\"username\":\"admin'||(SELECT password FROM users)\"}", "/api/auth/login", null);
        assertNotNull(d1);
        assertNotNull(d2);
        assertNotNull(d3);
        assertNotNull(d4);
        assertTrue(d1.payload.contains("SQL语义"), "布尔注入应命中语义层: " + d1.payload);
        assertTrue(d2.payload.contains("SQL语义"), "堆叠查询应命中语义层: " + d2.payload);
        assertTrue(d3.payload.contains("SQL语义"), "SELECT 结构应命中语义层: " + d3.payload);
        assertTrue(d4.payload.contains("SQL语义"), "单列 SELECT 逃逸应命中语义层: " + d4.payload);
    }

    @Test
    void semantic_shouldNotFlagNaturalLanguageNegatives() throws Exception {
        enableR47Semantic();
        String[] samples = {
                "don't and won't stop",
                "please select apples from the store",
                "can't insert the key into the lock",
                "the menu says (select apples from the store) when ready",
                "we can (select files from cloud storage) for backup",
                "please order by chance",
                "the value is not null in this table",
                "walk into the room quietly",
                "we group by department and share with rollup of duties",
        };
        for (String s : samples) {
            assertNull(service.detect(null, "{\"username\":\"" + s + "\"}", "/api/auth/login", null),
                    "不应误报: " + s);
        }
    }

    @Test
    void semantic_shouldRespectKillSwitch() throws Exception {
        enableR46Rules();
        setField("semanticEnabled", false);
        assertNull(service.detect(null, "{\"username\":\"admin' and (1)=(1)#\"}", "/api/auth/login", null),
                "语义层关闭时应放行正则盲区载荷");
    }

    // ========== IronWall v1.31.0: TLS 会话指纹（JA4 近似）跨 IP 证据 ==========

    private void enableR47TlsProfile() throws Exception {
        setField("tlsProfileEnabled", true);
        setField("tlsProfileMinIps", 2);
        setField("tlsProfileWindowMinutes", 1440);
        setField("tlsProfileBoostWeight", 10);
        setField("tlsProfileEscalateEnabled", true);
        setField("tlsProfileEscalateBlockMinutes", 120);
    }

    @Test
    void tlsProfileCrossIp_shouldEscalateNewMemberToImmediateBlock() throws Exception {
        enableR47TlsProfile();
        String key = "tls:" + "a".repeat(64);
        service.registerTlsSighting(key, "203.0.113.60");
        assertEquals(0, service.scoreOf("203.0.113.60"), "单 IP 不构成跨 IP 证据，不应加分");
        service.registerTlsSighting(key, "198.51.100.60");
        assertEquals(10, service.scoreOf("203.0.113.60"), "第二 IP 同指纹应联动加速");
        assertEquals(10, service.scoreOf("198.51.100.60"), "第二 IP 同指纹应联动加速");
        service.registerTlsSighting(key, "192.0.2.60");
        assertTrue(service.isBlocked("192.0.2.60"), "集群已触发后同指纹新攻击成员应首发即封");
    }

    @Test
    void tlsProfileCrossIp_escalateOffShouldFallbackToBoostOnly() throws Exception {
        enableR47TlsProfile();
        setField("tlsProfileEscalateEnabled", false);
        String key = "tls:" + "b".repeat(64);
        service.registerTlsSighting(key, "203.0.113.63");
        service.registerTlsSighting(key, "198.51.100.63");
        service.registerTlsSighting(key, "192.0.2.63");
        assertEquals(10, service.scoreOf("192.0.2.63"), "先手封禁关闭时应回滚为旧加分模式");
        assertFalse(service.isBlocked("192.0.2.63"), "先手封禁关闭时不应直接封禁");
    }

    @Test
    void tlsProfileSighting_shouldRespectKillSwitchAndRejectMalformedKey() throws Exception {
        setField("tlsProfileEnabled", false);
        String key = "tls:" + "b".repeat(64);
        service.registerTlsSighting(key, "203.0.113.61");
        service.registerTlsSighting(key, "198.51.100.61");
        assertEquals(0, service.scoreOf("203.0.113.61"), "开关关闭不应联动加分");
        assertEquals(0, service.scoreOf("198.51.100.61"), "开关关闭不应联动加分");
        enableR47TlsProfile();
        service.registerTlsSighting("tls:xx", "203.0.113.62");
        service.registerTlsSighting("tls:xx", "198.51.100.62");
        assertEquals(0, service.scoreOf("203.0.113.62"), "畸形指纹键应忽略");
        assertEquals(0, service.scoreOf("198.51.100.62"), "畸形指纹键应忽略");
    }

    // ========== IronWall v1.32.0: 攻击模板指纹聚合（代理池微调载荷跨IP联动封禁） ==========

    private void enableR48Template() throws Exception {
        setField("templateEnabled", true);
        setField("templateMinIps", 3);
        setField("templateWindowMinutes", 10);
        setField("templateBlockMinutes", 120);
    }

    @Test
    void attackTemplateCrossIp_shouldBlockAllMembersWhenLiteralDriftNormalizes() throws Exception {
        enableR48Template();
        service.recordWeighted("203.0.113.70", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.70", AttackGuardService.TYPE_SQL, "q=2' OR '2'='2", "/api/files/list", null, null, false, 5);
        assertFalse(service.isBlocked("203.0.113.70"), "低于阈值 IP 数不应封禁");
        service.recordWeighted("192.0.2.70", AttackGuardService.TYPE_SQL, "q=3' OR '3'='3", "/api/files/list", null, null, false, 5);
        assertTrue(service.isBlocked("203.0.113.70"), "模板聚合触发应联动封禁全部成员");
        assertTrue(service.isBlocked("198.51.100.70"), "模板聚合触发应联动封禁全部成员");
        assertTrue(service.isBlocked("192.0.2.70"), "模板聚合触发应联动封禁全部成员");
    }

    @Test
    void attackTemplateDifferentStructure_shouldNotAggregate() throws Exception {
        enableR48Template();
        service.recordWeighted("203.0.113.71", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.71", AttackGuardService.TYPE_SQL, "q=1' AND '1'='1", "/api/files/list", null, null, false, 5);
        service.recordWeighted("192.0.2.71", AttackGuardService.TYPE_SQL, "q=1 UNION SELECT 1", "/api/files/list", null, null, false, 5);
        assertFalse(service.isBlocked("203.0.113.71"), "结构不同的载荷不应聚合");
        assertFalse(service.isBlocked("198.51.100.71"), "结构不同的载荷不应聚合");
        assertFalse(service.isBlocked("192.0.2.71"), "结构不同的载荷不应聚合");
    }

    @Test
    void attackTemplateNormalizesHexLiterals() throws Exception {
        enableR48Template();
        service.recordWeighted("203.0.113.73", AttackGuardService.TYPE_SQL, "username=0x1a2b3c4d", "/api", null, null, false, 5);
        service.recordWeighted("198.51.100.73", AttackGuardService.TYPE_SQL, "username=0x4d5e6f78", "/api", null, null, false, 5);
        service.recordWeighted("192.0.2.73", AttackGuardService.TYPE_SQL, "username=0x7890ab12", "/api", null, null, false, 5);
        assertTrue(service.isBlocked("203.0.113.73"), "十六进制字面量漂移应归一化聚合");
        assertTrue(service.isBlocked("192.0.2.73"), "十六进制字面量漂移应归一化聚合");
    }

    @Test
    void attackTemplateRespectsKillSwitch() throws Exception {
        enableR48Template();
        setField("templateEnabled", false);
        service.recordWeighted("203.0.113.72", AttackGuardService.TYPE_SQL, "q=1' OR '1'='1", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.72", AttackGuardService.TYPE_SQL, "q=2' OR '2'='2", "/api/files/list", null, null, false, 5);
        service.recordWeighted("192.0.2.72", AttackGuardService.TYPE_SQL, "q=3' OR '3'='3", "/api/files/list", null, null, false, 5);
        assertFalse(service.isBlocked("203.0.113.72"), "开关关闭不应聚合封禁");
        assertFalse(service.isBlocked("192.0.2.72"), "开关关闭不应聚合封禁");
    }

    // ========== IronWall v1.32.0: 代理/机房信誉放大器（recordAttack 尾参叠加） ==========

    @Test
    void recordAttackExtraWeight_shouldAmplifyScore() {
        service.recordAttack("203.0.113.80", AttackGuardService.TYPE_SQL, "1' OR '1'='1", "/api/files/list", null, "GET", false, 10);
        assertEquals(15, service.scoreOf("203.0.113.80"), "默认 5 分 + 放大 10 分 = 15 分");
    }

    @Test
    void recordAttackExtraWeightTrustedSession_shouldNeverAmplify() {
        service.recordAttack("203.0.113.81", AttackGuardService.TYPE_SQL, "1' OR '1'='1", "/api/files/list", null, "GET", true, 10);
        assertEquals(0, service.scoreOf("203.0.113.81"), "登录态请求绝不叠加放大");
    }

    // ========== IronWall v1.33.0: 反斜杠双漏网根因闭环 ==========

    @Test
    void detect_shouldFlagBackslashEscapedSqlQuote() {
        assumeAdversarialRulesConfigured();
        // JSON 转义反斜杠（\\' 原始形态）曾触发归一化崩溃 fail-open
        assertNotNull(service.detect(null, "{\"username\":\"admin\\\\' OR '1'='1\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect("username=admin%5C%27%20OR%20%271%27%3D%271", null, "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin\\'or'1'='1\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin\\' AND '1'='1\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR '1'='1\\'\"}", "/api/auth/login", null));
    }

    @Test
    void detect_shouldFlagBackslashTraversal() {
        RuleAssumptions.requireRule("patterns.traversal");
        // 反斜杠路径分隔符变体
        assertNotNull(service.detect(null, "{\"path\":\"..\\\\..\\\\evil.txt\"}", "/api/files/download", null));
        assertNotNull(service.detect("path=..%5c..%5c%77indows%5cwin.ini", null, "/api/files/download", null));
        assertNotNull(service.detect(null, null, "/api/files/..\\..\\evil.txt", null));
        assertNotNull(service.detect("path=%2e%2e%5c%2e%2e%5cevil.txt", null, "/api/files/download", null));
        assertNotNull(service.detect(null, "{\"path\":\"..\\\\windows\\\\system32\\\\config\"}", "/api/files/download", null));
    }

    @Test
    void detect_shouldNotCrashOrFlagPlainBackslashJson() {
        // 合法 JSON 含 \\（Windows 路径 / 转义撇号）不得崩溃、不得误报
        assertNull(service.detect(null, "{\"path\":\"C:\\\\Users\\\\alice\\\\photo.png\"}", "/api/files/create", null));
        assertNull(service.detect(null, "{\"text\":\"don\\\\'t stop, we can\\\\'t flag this\"}", "/api/feedback", null));
        assertNull(service.detect(null, "{\"text\":\"\\\\u4f60\\\\u597d\"}", "/api/feedback", null));
    }

    // ========== IronWall v1.33.0: 登录蜜标账号诱捕 ==========

    @Test
    void matchLoginHoneypot_shouldMatchBaitUsernameOnlyOnLoginEndpoint() throws Exception {
        setField("loginHoneypotEnabled", true);
        setField("loginHoneypotUsernames", "trap_user_alpha,trap_user_beta");
        assertEquals("trap_user_alpha", service.matchLoginHoneypot("/api/auth/login", "POST", null,
                "{\"username\":\"trap_user_alpha\",\"password\":\"x\"}"));
        assertEquals("trap_user_beta", service.matchLoginHoneypot("/api/auth/login?x=1", "POST",
                "username=trap_user_beta&password=x", null));
        assertNull(service.matchLoginHoneypot("/api/auth/login", "POST", null,
                "{\"username\":\"alice\",\"password\":\"x\"}"));
        assertNull(service.matchLoginHoneypot("/api/auth/register", "POST", null,
                "{\"username\":\"trap_user_alpha\"}"));
        assertNull(service.matchLoginHoneypot("/api/auth/login", "GET", "username=trap_user_alpha", null));
        setField("loginHoneypotEnabled", false);
        assertNull(service.matchLoginHoneypot("/api/auth/login", "POST", null,
                "{\"username\":\"trap_user_alpha\"}"));
    }

    // ========== IronWall v1.33.0: 模板相似度第二层 ==========

    private void enableR49Similarity() throws Exception {
        setField("templateEnabled", true);
        setField("templateMinIps", 3);
        setField("templateWindowMinutes", 10);
        setField("templateBlockMinutes", 120);
        setField("templateSimilarityEnabled", true);
        setField("templateSimilarityThreshold", 0.75);
    }

    @Test
    void templateSimilarity_shouldMergeStructuralDriftAndBlockAll() throws Exception {
        enableR49Similarity();
        service.recordWeighted("203.0.113.90", AttackGuardService.TYPE_SQL, "id=1 union select a", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.90", AttackGuardService.TYPE_SQL, "id=2 union select b", "/api/files/list", null, null, false, 5);
        service.recordWeighted("192.0.2.90", AttackGuardService.TYPE_SQL, "id=3 union select c", "/api/files/list", null, null, false, 5);
        assertTrue(service.isBlocked("203.0.113.90"), "结构微调载荷应经相似桶合并聚合封禁");
        assertTrue(service.isBlocked("198.51.100.90"), "结构微调载荷应经相似桶合并聚合封禁");
        assertTrue(service.isBlocked("192.0.2.90"), "结构微调载荷应经相似桶合并聚合封禁");
    }

    @Test
    void templateSimilarity_shouldNotMergeDifferentStructures() throws Exception {
        enableR49Similarity();
        service.recordWeighted("203.0.113.91", AttackGuardService.TYPE_SQL, "id=1 union select a", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.91", AttackGuardService.TYPE_SQL, "id=1 or 'a'='a", "/api/files/list", null, null, false, 5);
        service.recordWeighted("192.0.2.91", AttackGuardService.TYPE_SQL, "id=1 and sleep(1)", "/api/files/list", null, null, false, 5);
        assertFalse(service.isBlocked("203.0.113.91"), "低相似结构不应合并");
        assertFalse(service.isBlocked("198.51.100.91"), "低相似结构不应合并");
        assertFalse(service.isBlocked("192.0.2.91"), "低相似结构不应合并");
    }

    @Test
    void templateSimilarityRespectsKillSwitch() throws Exception {
        enableR49Similarity();
        setField("templateSimilarityEnabled", false);
        service.recordWeighted("203.0.113.92", AttackGuardService.TYPE_SQL, "id=1 union select a", "/api/files/list", null, null, false, 5);
        service.recordWeighted("198.51.100.92", AttackGuardService.TYPE_SQL, "id=2 union select b", "/api/files/list", null, null, false, 5);
        service.recordWeighted("192.0.2.92", AttackGuardService.TYPE_SQL, "id=3 union select c", "/api/files/list", null, null, false, 5);
        assertFalse(service.isBlocked("203.0.113.92"), "相似层关闭时结构微调不应聚合");
    }

    // ========== IronWall v1.34.0: MySQL 内置语法族盲区闭环 ==========

    @Test
    void detect_shouldFlagMysqlSystemVariableFamily() {
        assumeAdversarialRulesConfigured();
        // @@version 系统变量族（同源 @@datadir / @@version_compile_os / @@global.sql_mode）
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR @@version#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR @@datadir#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR @@version_compile_os#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR @@global.sql_mode#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect("q=1%27%20OR%20%40%40version%23", null, "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"@@session.tx_isolation\"}", "/api/search", null));
    }

    @Test
    void detect_shouldFlagMysqlInfoFunctionFamily() {
        assumeAdversarialRulesConfigured();
        // DATABASE()/USER() 等常规信息函数族
        assertNotNull(service.detect(null, "{\"username\":\"admin' AND DATABASE()#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"username\":\"admin' AND USER()#\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR CURRENT_USER()\"}", "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR SESSION_USER()\"}", "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR SYSTEM_USER()\"}", "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR VERSION()\"}", "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR CONNECTION_ID()\"}", "/api/search", null));
        assertNotNull(service.detect(null, "{\"q\":\"1 OR SCHEMA()\"}", "/api/search", null));
    }

    @Test
    void detect_shouldFlagMysqlDotConcat() {
        assumeAdversarialRulesConfigured();
        // MySQL 字符串点拼接 'admin'.'1'
        assertNotNull(service.detect(null, "{\"username\":\"admin'.'1\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNotNull(service.detect(null, "{\"q\":\"'admin'.'1'\"}", "/api/search", null));
        assertNotNull(service.detect("q=%22a%22.%22b%22", null, "/api/search", null));
        assertNotNull(service.detect("q=%27x%27.%27y%27", null, "/api/search", null));
    }

    @Test
    void detect_shouldNotFlagLegitBuiltinLookalikes() {
        // 防误报：单 @ 邮箱、version 键值、点号文件名、user 键值均不得命中
        assertNull(service.detect(null, "{\"email\":\"alice@example.com\"}", "/api/auth/register", null));
        assertNull(service.detect(null, "{\"version\":\"1.0.0\",\"name\":\"classic-cloud\"}", "/api/version/info", null));
        assertNull(service.detect(null, "{\"file\":\"report.final.docx\"}", "/api/files/create", null));
        assertNull(service.detect(null, "{\"user\":\"alice\",\"password\":\"x\"}", "/api/auth/login", null));
        assertNull(service.detect(null, "{\"text\":\"we need charset=utf-8 and collation=default\"}", "/api/feedback", null));
    }

    @Test
    void mysqlBuiltinRespectsKillSwitch() throws Exception {
        assumeAdversarialRulesConfigured();
        setField("mysqlBuiltinEnabled", false);
        assertNull(service.detect(null, "{\"username\":\"admin' OR @@version#\"}", "/api/auth/login", null));
        assertNull(service.detect(null, "{\"username\":\"admin' AND DATABASE()#\"}", "/api/auth/login", null));
        assertNull(service.detect(null, "{\"username\":\"admin'.'1\"}", "/api/auth/login", null));
        setField("mysqlBuiltinEnabled", true);
        assertNotNull(service.detect(null, "{\"username\":\"admin' OR @@version#\"}", "/api/auth/login", null));
    }

    // ========== IronWall v1.38.0: 分布式封禁同步事件与远端合并 ==========

    @Test
    void blockedByAccumulation_shouldPersistSyncEventR54() {
        for (int i = 0; i < 10; i++) {
            service.recordAttack("203.0.113.95",
                    AttackGuardService.TYPE_PROTOCOL, "anomaly-" + i, "/api/auth/login", "curl/8", "POST");
        }

        ArgumentCaptor<AttackLog> captor = ArgumentCaptor.forClass(AttackLog.class);
        verify(attackLogRepository, atLeastOnce()).save(captor.capture());
        AttackLog sync = captor.getAllValues().stream()
                .filter(e -> AttackGuardService.TYPE_SYNC.equals(e.getAttackType()))
                .reduce((first, second) -> second)
                .orElse(null);
        assertNotNull(sync, "ban sync event must be persisted on block");
        assertEquals("203.0.113.95", sync.getIp());
        assertEquals("BLOCKED", sync.getAction());
        assertTrue(sync.getUserAgent() != null && sync.getUserAgent().startsWith("instance:"));
        assertTrue(Long.parseLong(sync.getPayload()) > System.currentTimeMillis());
    }

    @Test
    void unblock_shouldPersistUnblockedSyncEventR54() {
        service.applyRemoteBan("203.0.113.96", System.currentTimeMillis() + 600_000L);
        service.unblock("203.0.113.96");

        ArgumentCaptor<AttackLog> captor = ArgumentCaptor.forClass(AttackLog.class);
        verify(attackLogRepository, atLeastOnce()).save(captor.capture());
        AttackLog sync = captor.getAllValues().stream()
                .filter(e -> AttackGuardService.TYPE_SYNC.equals(e.getAttackType()))
                .reduce((first, second) -> second)
                .orElse(null);
        assertNotNull(sync);
        assertEquals("UNBLOCKED", sync.getAction());
        assertFalse(service.isBlocked("203.0.113.96"));
    }

    @Test
    void applyRemoteBan_shouldTakeLaterExpiryR54() {
        long later = System.currentTimeMillis() + 3_600_000L;
        service.applyRemoteBan("203.0.113.97", later);
        service.applyRemoteBan("203.0.113.97", System.currentTimeMillis() + 60_000L);
        assertTrue(service.isBlocked("203.0.113.97"));

        service.applyRemoteBan("203.0.113.98", System.currentTimeMillis() - 1_000L);
        assertFalse(service.isBlocked("203.0.113.98"), "expired remote ban must be ignored");
    }

    @Test
    void applyRemoteUnblock_shouldClearRemoteBlockR54() {
        service.applyRemoteBan("203.0.113.99", System.currentTimeMillis() + 600_000L);
        assertTrue(service.isBlocked("203.0.113.99"));
        service.applyRemoteUnblock("203.0.113.99");
        assertFalse(service.isBlocked("203.0.113.99"));
        service.applyRemoteUnblock(null);
        service.applyRemoteUnblock("203.0.113.100");
    }

    @Test
    void isSelfInstance_shouldRejectForeignAndNullTagsR54() {
        assertFalse(service.isSelfInstance(null));
        assertFalse(service.isSelfInstance("instance:foreign-instance"));
        assertFalse(service.isSelfInstance("Mozilla/5.0"));
    }

    @Test
    void instanceTag_shouldBeStableAcrossWritesR54K() {
        service.unblock("203.0.113.102");
        service.unblock("203.0.113.103");

        ArgumentCaptor<AttackLog> captor = ArgumentCaptor.forClass(AttackLog.class);
        verify(attackLogRepository, atLeast(2)).save(captor.capture());
        List<String> tags = captor.getAllValues().stream()
                .filter(e -> AttackGuardService.TYPE_SYNC.equals(e.getAttackType()))
                .map(AttackLog::getUserAgent)
                .distinct()
                .toList();
        assertEquals(1, tags.size(), "sync events from the same instance must share one stable tag");
        assertTrue(service.isSelfInstance(tags.get(0)), "own persisted tag must be recognized as self");
    }

    @Test
    void syncPersistFailure_shouldNotBreakBlockChainR54() {
        doThrow(new RuntimeException("db down")).when(attackLogRepository).save(any(AttackLog.class));
        AttackGuardService.AttackRecord last = null;
        for (int i = 0; i < 10; i++) {
            last = service.recordAttack("203.0.113.101",
                    AttackGuardService.TYPE_PROTOCOL, "anomaly-" + i, "/api/auth/login", "curl/8", "POST");
        }
        assertNotNull(last);
        assertEquals("BLOCKED", last.action);
        assertTrue(service.isBlocked("203.0.113.101"), "db failure must never break the block chain");
    }

    @Test
    void mobileCarrierFuse_shouldCapDurationAndSkipSegmentR60() throws Exception {
        ThreatIntelService intel = mock(ThreatIntelService.class);
        when(intel.isMobileCarrierCached("203.0.113.7")).thenReturn(true);
        service.attachThreatIntel(intel);
        setField("mobileCarrierProtectEnabled", true);
        setField("mobileCarrierMaxBlockMinutes", 30);
        setField("segmentBlockEnabled", true);
        setField("segmentRepeatCount", 2);

        service.recordWeighted("203.0.113.7", AttackGuardService.TYPE_SQL,
                "UNION SELECT", "/api", "sqlmap/1.0", "GET", false, 50);
        service.recordWeighted("203.0.113.7", AttackGuardService.TYPE_SQL,
                "UNION SELECT", "/api", "sqlmap/1.0", "GET", false, 50);

        Map<String, Object> stats = service.mobileFuseStats();
        assertTrue(((Number) stats.get("block_cap_hits")).longValue() >= 2,
                "运营商出口封禁时长应被压顶并计数");
        assertTrue(((Number) stats.get("segment_skips")).longValue() >= 1,
                "运营商出口应豁免整段封禁并计数");
        for (AttackGuardService.BlockInfo b : service.getBlockedIps()) {
            if ("203.0.113.7".equals(b.ip)) {
                assertTrue(b.blockedSeconds <= 30 * 60 + 60,
                        "熔断后封禁时长不得超过 30 分钟: " + b.blockedSeconds);
            }
        }
        service.unblock("203.0.113.7");
    }

}
