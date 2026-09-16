package com.jdy.cloud.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * IronWall v1.11: crawler defense filter contract tests.
 */
@ExtendWith(MockitoExtension.class)
class CrawlerDefenseFilterTest {

    private static final String TEST_CHALLENGE_SECRET = "test-challenge-secret-32-bytes-minimum";

    @Mock private AttackGuardService attackGuardService;
    @Mock private RequestTrustResolver trustResolver;
    @Mock private TrapService trapService;
    @Mock private FilterChain chain;

    private CrawlerDefenseFilter filter;

    @BeforeEach
    void setUp() {
        filter = new CrawlerDefenseFilter(attackGuardService, trustResolver, trapService);
        ReflectionTestUtils.setField(filter, "enabled", true);
        ReflectionTestUtils.setField(filter, "maxApiRpm", 300);
        ReflectionTestUtils.setField(filter, "maxCrawlerRpm", 10);
        ReflectionTestUtils.setField(filter, "fingerprintEnabled", true);
        ReflectionTestUtils.setField(filter, "challengeEnabled", true);
        // IronWall v1.47.7: 按生产接线注入挑战密钥（空密钥现在 fail-closed 抛异常）
        ReflectionTestUtils.setField(filter, "challengeSecret", TEST_CHALLENGE_SECRET);
        when(attackGuardService.isEnabled()).thenReturn(true);
        lenient().when(attackGuardService.isBlocked(anyString())).thenReturn(false);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
    }

    @Test
    void shouldPassBrowserTraffic() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.1");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        request.addHeader("Accept", "application/json");
        request.addHeader("Accept-Language", "zh-CN,zh;q=0.9");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldBlockWhenCrawlerUaEscalatedToBlocked() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        AttackGuardService.AttackRecord blocked = new AttackGuardService.AttackRecord(
                "203.0.113.2", AttackGuardService.TYPE_CRAWLER, "ua", 20, 1, System.currentTimeMillis() + 3600_000L, "BLOCKED");
        when(attackGuardService.recordAttack(eq("203.0.113.2"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(false))).thenReturn(blocked);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.2");
        request.addHeader("User-Agent", "curl/8.5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAllowCrawlerUaWhenNotYetBlocked() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.3", AttackGuardService.TYPE_CRAWLER, "ua", 2, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.3"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(false))).thenReturn(warn);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.3");
        request.addHeader("User-Agent", "python-requests/2.31.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldBlockHighFrequencyApiAccess() throws Exception {
        ReflectionTestUtils.setField(filter, "maxApiRpm", 3);
        AttackGuardService.AttackRecord rec = new AttackGuardService.AttackRecord(
                "203.0.113.4", AttackGuardService.TYPE_CRAWLER, "high", 5, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.4"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), anyString(), eq(false))).thenReturn(rec);
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 4; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.4");
            request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(attackGuardService, atLeastOnce()).recordAttack(eq("203.0.113.4"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), anyString(), eq(false));
    }

    @Test
    void shouldSkipStaticAssets() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/avatar/avatar_1_1.png");
        request.setRemoteAddr("203.0.113.5");
        request.addHeader("User-Agent", "curl/8.5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldBlockSuspiciousUaBurst() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        ReflectionTestUtils.setField(filter, "maxCrawlerRpm", 2);
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.6", AttackGuardService.TYPE_CRAWLER, "ua", 2, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.6"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(false))).thenReturn(warn);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.6");
            request.addHeader("User-Agent", "curl/8.5.0");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
    }

    @Test
    void shouldBypassWhitelistedIpEntirely() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.7");
        request.addHeader("User-Agent", "curl/8.5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
        verify(attackGuardService, never()).isBlocked(anyString());
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
    }

    @Test
    void shouldRelaxAuthenticatedApiLimitTenfold() throws Exception {
        ReflectionTestUtils.setField(filter, "maxApiRpm", 3);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);

        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.8");
            request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(chain, times(5)).doFilter(any(), any());
        verify(attackGuardService, never()).recordAttack(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
    }

    @Test
    void shouldNotEscalateAuthenticatedCrawlerUaBurst() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        ReflectionTestUtils.setField(filter, "maxCrawlerRpm", 2);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.9", AttackGuardService.TYPE_CRAWLER, "ua", 0, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.9"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(true))).thenReturn(warn);

        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.9");
            request.addHeader("User-Agent", "curl/8.5.0");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            assertEquals(200, response.getStatus());
        }
        verify(attackGuardService, atLeastOnce()).recordAttack(eq("203.0.113.9"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), eq("GET"), eq(true));
    }

    @Test
    void shouldWarnAuthenticatedButNeverScoreWhenOverLimit() throws Exception {
        ReflectionTestUtils.setField(filter, "maxApiRpm", 3);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.10", AttackGuardService.TYPE_CRAWLER, "high", 0, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.10"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), anyString(), eq(true))).thenReturn(warn);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 31; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.10");
            request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        verify(attackGuardService, atLeastOnce()).recordAttack(eq("203.0.113.10"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), anyString(), eq(true));
    }

    @Test
    void shouldLetBlockedIpAuthenticatedPassThrough() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        when(attackGuardService.isBlocked("203.0.113.11")).thenReturn(true);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.11");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldExtraScoreBurstCrawlerThrottledByInterval() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        // IronWall v1.17.2: 持续超限的自动化客户端按 5 秒节流额外记分，快速升级封禁
        ReflectionTestUtils.setField(filter, "maxCrawlerRpm", 2);
        ReflectionTestUtils.setField(filter, "burstScoreIntervalMs", 5000L);
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.12", AttackGuardService.TYPE_CRAWLER, "ua", 2, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.12"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), anyString(), eq(false))).thenReturn(warn);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.12");
            request.addHeader("User-Agent", "curl/8.7.1");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }

        // 前 2 次未超限放行，第 3 次起 429；5 次基础记分 + 仅 1 次超限额外记分（5 秒节流）
        assertEquals(429, last.getStatus());
        verify(chain, times(2)).doFilter(any(), any());
        verify(attackGuardService, times(6)).recordAttack(eq("203.0.113.12"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), anyString(), eq(false));
    }

    @Test
    void shouldNotExtraScoreAuthenticatedCrawlerBurst() throws Exception {
        RuleAssumptions.requireRule("patterns.crawlerUa");
        // 登录态超限仅瞬时限流（429），绝不额外记分、绝不升级封禁
        ReflectionTestUtils.setField(filter, "maxCrawlerRpm", 1);
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.13", AttackGuardService.TYPE_CRAWLER, "ua", 0, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.13"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), anyString(), eq(true))).thenReturn(warn);

        // 登录态 crawlerLimit = 1*10 = 10；发 11 次，第 11 次起超限 429
        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 11; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.13");
            request.addHeader("User-Agent", "curl/8.7.1");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        // 只允许带 trustedSession=true 的基础记分，绝无 false 的额外记分
        verify(attackGuardService, times(11)).recordAttack(eq("203.0.113.13"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), anyString(), eq(true));
        verify(attackGuardService, never()).recordAttack(eq("203.0.113.13"),
                eq(AttackGuardService.TYPE_CRAWLER), anyString(), anyString(), anyString(), anyString(), eq(false));
    }

    @Test
    void shouldChallengeBrowserUaMimicWithoutJsProof() throws Exception {
        AttackGuardService.AttackRecord warn = new AttackGuardService.AttackRecord(
                "203.0.113.6", AttackGuardService.TYPE_CRAWLER, "mimic", 2, 0, 0, "WARN");
        when(attackGuardService.recordAttack(eq("203.0.113.6"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(false))).thenReturn(warn);

        MockHttpServletResponse last = new MockHttpServletResponse();
        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
            request.setRemoteAddr("203.0.113.6");
            request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
            request.addHeader("Accept", "*/*");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, chain);
            last = response;
        }
        assertEquals(429, last.getStatus());
        assertEquals("true", last.getHeader(CrawlerDefenseFilter.CHALLENGE_HEADER));
    }

    @Test
    void forgedCookieShouldChallengeWithoutTrappingFirstOffense() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.7");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        request.addHeader("Accept", "*/*");
        request.setCookies(new jakarta.servlet.http.Cookie(CrawlerDefenseFilter.JS_OK_COOKIE, "1"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        // IronWall v1.21.1: 首犯仅 429 + 记分，由前端静默换发签名 Cookie，不再误锁真实用户
        assertEquals(429, response.getStatus());
        assertEquals("true", response.getHeader(CrawlerDefenseFilter.CHALLENGE_HEADER));
        verify(chain, never()).doFilter(any(), any());
        verify(attackGuardService).recordAttack(eq("203.0.113.7"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), anyString(), eq(false));
        verify(trapService, never()).trap(anyString(), anyInt(), anyString(), anyString(), anyString(), anyString(), anyBoolean());
    }

    @Test
    void repeatedForgeryShouldTrapOnlyWhenEscalatedToBlocked() throws Exception {
        AttackGuardService.AttackRecord blocked = new AttackGuardService.AttackRecord(
                "203.0.113.9", AttackGuardService.TYPE_CRAWLER, "挑战cookie伪造", 20, 1,
                System.currentTimeMillis() + 3600_000L, "BLOCKED");
        when(attackGuardService.recordAttack(eq("203.0.113.9"), eq(AttackGuardService.TYPE_CRAWLER),
                anyString(), anyString(), anyString(), eq("GET"), eq(false))).thenReturn(blocked);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        request.setRemoteAddr("203.0.113.9");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        request.addHeader("Accept", "*/*");
        request.setCookies(new jakarta.servlet.http.Cookie(CrawlerDefenseFilter.JS_OK_COOKIE, "1"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        verify(trapService).trap(eq("203.0.113.9"), eq(2), anyString(), anyString(), anyString(), anyString(), eq(false));
    }

    @Test
    void challengeEndpointShouldIssueNonceAndVerifyShouldPass() throws Exception {
        MockHttpServletRequest challenge = new MockHttpServletRequest("GET", CrawlerDefenseFilter.CHALLENGE_PATH);
        challenge.setRemoteAddr("203.0.113.8");
        MockHttpServletResponse challengeResp = new MockHttpServletResponse();
        filter.doFilter(challenge, challengeResp, chain);
        assertEquals(200, challengeResp.getStatus());
        String nonce = challengeResp.getCookie(CrawlerDefenseFilter.JS_NONCE_COOKIE) != null
                ? challengeResp.getCookie(CrawlerDefenseFilter.JS_NONCE_COOKIE).getValue() : null;
        assertNotNull(nonce);

        MockHttpServletRequest verify = new MockHttpServletRequest("GET", CrawlerDefenseFilter.VERIFY_PATH);
        verify.setRemoteAddr("203.0.113.8");
        verify.setParameter("n", nonce);
        verify.setCookies(new jakarta.servlet.http.Cookie(CrawlerDefenseFilter.JS_NONCE_COOKIE, nonce));
        MockHttpServletResponse verifyResp = new MockHttpServletResponse();
        filter.doFilter(verify, verifyResp, chain);
        assertEquals(200, verifyResp.getStatus());
        assertNotNull(verifyResp.getCookie(CrawlerDefenseFilter.JS_OK_COOKIE));
        String signedOk = verifyResp.getCookie(CrawlerDefenseFilter.JS_OK_COOKIE).getValue();
        assertTrue(signedOk.contains("."));

        // 签名 iw_ok 正常通行，且不触发挑战/陷阱
        MockHttpServletRequest withProof = new MockHttpServletRequest("GET", "/api/files/list");
        withProof.setRemoteAddr("203.0.113.8");
        withProof.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        withProof.addHeader("Accept", "application/json");
        withProof.addHeader("Accept-Language", "zh-CN,zh;q=0.9");
        withProof.setCookies(new jakarta.servlet.http.Cookie(CrawlerDefenseFilter.JS_OK_COOKIE, signedOk));
        MockHttpServletResponse withProofResp = new MockHttpServletResponse();
        filter.doFilter(withProof, withProofResp, chain);
        assertEquals(200, withProofResp.getStatus());
    }

    @Test
    void challengeDifficulty_shouldScaleWithIpReputation() throws Exception {
        ReflectionTestUtils.setField(filter, "powDifficulty", 4);
        ReflectionTestUtils.setField(filter, "powDifficultyMax", 6);
        ReflectionTestUtils.setField(filter, "powReputationThreshold", 10);
        ReflectionTestUtils.setField(filter, "powReputationBoost", 2);

        // 新 IP：基线难度
        MockHttpServletRequest fresh = new MockHttpServletRequest("GET", CrawlerDefenseFilter.CHALLENGE_PATH);
        fresh.setRemoteAddr("203.0.113.60");
        MockHttpServletResponse freshResp = new MockHttpServletResponse();
        filter.doFilter(fresh, freshResp, chain);
        assertEquals(200, freshResp.getStatus());
        assertTrue(freshResp.getContentAsString().contains("\"difficulty\":4"), freshResp.getContentAsString());

        // 可疑 IP：难度上调但不超过上限
        when(attackGuardService.scoreOf("203.0.113.61")).thenReturn(15);
        MockHttpServletRequest suspect = new MockHttpServletRequest("GET", CrawlerDefenseFilter.CHALLENGE_PATH);
        suspect.setRemoteAddr("203.0.113.61");
        MockHttpServletResponse suspectResp = new MockHttpServletResponse();
        filter.doFilter(suspect, suspectResp, chain);
        assertEquals(200, suspectResp.getStatus());
        assertTrue(suspectResp.getContentAsString().contains("\"difficulty\":6"), suspectResp.getContentAsString());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldChallengeSensitiveMutationWithoutJsProof() throws Exception {
        ReflectionTestUtils.setField(filter, "requireJsProofForSensitive", true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.50");
        request.addHeader("User-Agent", "curl/8.5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("true", response.getHeader(CrawlerDefenseFilter.CHALLENGE_HEADER));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAllowSensitiveMutationWithValidJsProof() throws Exception {
        ReflectionTestUtils.setField(filter, "requireJsProofForSensitive", true);
        long exp = System.currentTimeMillis() / 1000L + 3600;
        String value = exp + "." + hmacHex("203.0.113.51|" + exp, TEST_CHALLENGE_SECRET);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.setRemoteAddr("203.0.113.51");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36");
        request.addHeader("Accept", "application/json");
        request.addHeader("Accept-Language", "zh-CN,zh;q=0.9");
        request.setCookies(new jakarta.servlet.http.Cookie(CrawlerDefenseFilter.JS_OK_COOKIE, value));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(request, response);
    }

    private String hmacHex(String data, String key) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(
                key.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] out = mac.doFinal(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
