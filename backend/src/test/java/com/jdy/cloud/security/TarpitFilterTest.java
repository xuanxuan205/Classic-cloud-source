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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.17: tarpit delay filter contract tests.
 * Only anonymous flagged attackers / honeypot paths are slowed; trusted traffic is untouched.
 */
@ExtendWith(MockitoExtension.class)
class TarpitFilterTest {

    @Mock private AttackGuardService attackGuardService;
    @Mock private RequestTrustResolver trustResolver;
    @Mock private FilterChain chain;

    private TarpitFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TarpitFilter(attackGuardService, trustResolver, healthyProbe(), 4);
        ReflectionTestUtils.setField(filter, "defenseEngineEnabled", true);
        ReflectionTestUtils.setField(filter, "tarpitEnabled", true);
        ReflectionTestUtils.setField(filter, "delayMs", 80L);
        ReflectionTestUtils.setField(filter, "maxDelayMs", 120L);
        lenient().when(attackGuardService.isEnabled()).thenReturn(true);
        lenient().when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.ANONYMOUS);
        lenient().when(attackGuardService.shouldTarpit(anyString())).thenReturn(false);
        lenient().when(attackGuardService.blockRemainingSeconds(anyString())).thenReturn(0L);
    }

    private MockHttpServletRequest apiRequest(String ip, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(ip);
        return request;
    }

    private static SystemHealthProbe healthyProbe() {
        return new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.0; }
            @Override protected double heapUsedRatio() { return 0.0; }
        };
    }

    private static SystemHealthProbe busyCpuProbe() {
        return new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.95; }
            @Override protected double heapUsedRatio() { return 0.0; }
        };
    }

    private static SystemHealthProbe busyHeapProbe() {
        return new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.0; }
            @Override protected double heapUsedRatio() { return 0.95; }
        };
    }

    @Test
    void normalAnonymousShouldPassImmediately() throws Exception {
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.40", "/api/files/list"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(200, response.getStatus());
        assertTrue(elapsed < 60, "normal traffic must not be delayed, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void flaggedAttackerShouldBeDelayed() throws Exception {
        when(attackGuardService.shouldTarpit("203.0.113.41")).thenReturn(true);
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.41", "/api/files/list"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed >= 70, "flagged attacker should be slowed, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void honeypotPathShouldBeDelayedEvenBeforeScoring() throws Exception {
        RuleAssumptions.requireRule("honeypot.paths");
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.42", "/api/.env"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed >= 70, "honeypot path should be slowed, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void authenticatedShouldNeverBeDelayed() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.AUTHENTICATED);
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.43", "/api/files/list"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed < 60, "authenticated traffic must never be delayed, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    @Test
    void whitelistedShouldNeverBeDelayed() throws Exception {
        when(trustResolver.resolve(any(), anyString())).thenReturn(RequestTrustResolver.Level.WHITELISTED);
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.44", "/api/.env"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed < 60, "whitelisted traffic must never be delayed, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    @Test
    // IronWall v1.47.2: 仅记分未封禁的 IP 下载不再硬 429，短延迟后放行（修复共享 IP 全屋误伤）
    void downloadEndpoint_scoredButNotBlockedIpShouldPassAfterShortDelay() throws Exception {
        when(attackGuardService.shouldTarpit("203.0.113.46")).thenReturn(true);
        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.46", "/api/shares/download/abc123"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(200, response.getStatus());
        assertTrue(elapsed >= 70, "scored downloads should be briefly delayed, elapsed=" + elapsed);
        assertTrue(elapsed < 5000, "scored downloads must not be delayed beyond 5s cap, elapsed=" + elapsed);
        verify(chain).doFilter(any(), any());
    }

    // IronWall v1.47.2: 真封禁 IP 下载 429，Retry-After 与剩余封禁时长一致
    @Test
    void downloadEndpoint_blockedIpShould429WithRealRetryAfter() throws Exception {
        when(attackGuardService.shouldTarpit("203.0.113.61")).thenReturn(true);
        when(attackGuardService.blockRemainingSeconds("203.0.113.61")).thenReturn(1200L);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.61", "/api/shares/download/abc123"), response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("1200", response.getHeader("Retry-After"));
        assertTrue(response.getContentAsString().contains("20分钟"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void disabledEngineShouldPassThrough() throws Exception {
        ReflectionTestUtils.setField(filter, "defenseEngineEnabled", false);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.45", "/api/files/list"), response, chain);

        assertEquals(200, response.getStatus());
        verify(chain).doFilter(any(), any());
    }

    @Test
    void underCpuPressure_shouldFailFastWith429InsteadOfSleep() throws Exception {
        RuleAssumptions.requireRule("honeypot.paths");
        filter = new TarpitFilter(attackGuardService, trustResolver, busyCpuProbe(), 4);
        ReflectionTestUtils.setField(filter, "defenseEngineEnabled", true);
        ReflectionTestUtils.setField(filter, "tarpitEnabled", true);
        ReflectionTestUtils.setField(filter, "delayMs", 3000L);
        ReflectionTestUtils.setField(filter, "maxDelayMs", 5000L);

        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.60", "/api/.env"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(429, response.getStatus());
        assertTrue(elapsed < 200, "pressure circuit must not sleep, elapsed=" + elapsed);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void underHeapPressure_shouldFailFastWith429InsteadOfSleep() throws Exception {
        filter = new TarpitFilter(attackGuardService, trustResolver, busyHeapProbe(), 4);
        ReflectionTestUtils.setField(filter, "defenseEngineEnabled", true);
        ReflectionTestUtils.setField(filter, "tarpitEnabled", true);
        ReflectionTestUtils.setField(filter, "delayMs", 3000L);
        ReflectionTestUtils.setField(filter, "maxDelayMs", 5000L);
        when(attackGuardService.shouldTarpit("203.0.113.61")).thenReturn(true);

        long start = System.currentTimeMillis();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(apiRequest("203.0.113.61", "/api/files/list"), response, chain);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(429, response.getStatus());
        assertTrue(elapsed < 200, "pressure circuit must not sleep, elapsed=" + elapsed);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void effectiveDelayMs_shouldRespectHardCap() {
        assertEquals(80, TarpitFilter.effectiveDelayMs(80, 120));
        assertEquals(1, TarpitFilter.effectiveDelayMs(-5, 120));
        assertEquals(60_000, TarpitFilter.effectiveDelayMs(120_000, 120_000));
        assertEquals(1, TarpitFilter.effectiveDelayMs(120_000, -1));
    }

    @Test
    void concurrentTarpit_shouldStayBoundedAndNeverHang() throws Exception {
        RuleAssumptions.requireRule("honeypot.paths");
        TarpitFilter concurrent = new TarpitFilter(attackGuardService, trustResolver, healthyProbe(), 8);
        ReflectionTestUtils.setField(concurrent, "defenseEngineEnabled", true);
        ReflectionTestUtils.setField(concurrent, "tarpitEnabled", true);
        ReflectionTestUtils.setField(concurrent, "delayMs", 50L);
        ReflectionTestUtils.setField(concurrent, "maxDelayMs", 50L);

        int tasks = 200;
        ExecutorService pool = Executors.newFixedThreadPool(64);
        CountDownLatch ready = new CountDownLatch(tasks);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < tasks; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    MockHttpServletResponse response = new MockHttpServletResponse();
                    ready.countDown();
                    go.await();
                    concurrent.doFilter(apiRequest("198.51.100." + (1 + idx % 250), "/api/.env"),
                            response, chain);
                    return response.getStatus();
                }));
            }
            ready.await(10, java.util.concurrent.TimeUnit.SECONDS);
            long start = System.currentTimeMillis();
            go.countDown();
            int ok = 0;
            int limited = 0;
            for (Future<Integer> f : futures) {
                int status = f.get(15, java.util.concurrent.TimeUnit.SECONDS);
                if (status == 200) ok++;
                else if (status == 429) limited++;
                else fail("unexpected status: " + status);
            }
            long elapsed = System.currentTimeMillis() - start;
            assertTrue(ok > 0, "some tarpit requests must pass after bounded delay");
            assertTrue(limited > 0, "over-limit requests must be rejected with 429");
            assertTrue(elapsed < 15_000, "200 concurrent tarpit requests must stay bounded, elapsed=" + elapsed);
        } finally {
            pool.shutdownNow();
        }
    }
}
