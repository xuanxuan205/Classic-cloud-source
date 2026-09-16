package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.38.0: 分享下载独立限流契约测试。
 * 单IP每分钟10次；单分享码每分钟30次；并发下精确计数不超卖、不放行超额请求。
 */
class ShareDownloadLimiterTest {

    private ShareDownloadLimiter limiter;

    @BeforeEach
    void setUp() throws Exception {
        limiter = new ShareDownloadLimiter();
        setField("downloadsPerClientPerMinute", 10);
        setField("downloadsPerCodePerMinute", 30);
    }

    private void setField(String name, Object value) throws Exception {
        var field = ShareDownloadLimiter.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(limiter, value);
    }

    @Test
    void concurrentSameIp_shouldAllowExactlyTen() throws Exception {
        int threads = 30;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                try {
                    go.await(5, TimeUnit.SECONDS);
                    limiter.checkAllowed("code-a", "203.0.113.90", true);
                    allowed.incrementAndGet();
                } catch (BusinessException e) {
                    assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), e.getCode());
                    rejected.incrementAndGet();
                } catch (Exception e) {
                    fail("unexpected exception: " + e);
                }
            }));
        }
        assertTrue(ready.await(5, TimeUnit.SECONDS));
        go.countDown();
        for (Future<?> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        assertEquals(10, allowed.get(), "ip limit must admit exactly 10 concurrent downloads");
        assertEquals(20, rejected.get(), "remaining 20 must be rejected with 429");
    }

    @Test
    void perCodeLimit_shouldApplyAcrossDistinctIps() throws Exception {
        setField("downloadsPerClientPerMinute", 100);
        setField("downloadsPerCodePerMinute", 5);

        int allowed = 0;
        int rejected = 0;
        for (int i = 0; i < 10; i++) {
            try {
                limiter.checkAllowed("code-b", "198.51.100." + (i + 1), true);
                allowed++;
            } catch (BusinessException e) {
                assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), e.getCode());
                rejected++;
            }
        }
        assertEquals(5, allowed);
        assertEquals(5, rejected);
    }

    @Test
    void blankIpAndCode_shouldUseUnknownKey() {
        assertDoesNotThrow(() -> limiter.checkAllowed(null, null));
        assertDoesNotThrow(() -> limiter.checkAllowed(" ", " "));
    }

    @Test
    void codeNormalization_shouldBeCaseInsensitive() throws Exception {
        setField("downloadsPerClientPerMinute", 100);
        setField("downloadsPerCodePerMinute", 1);
        limiter.checkAllowed("AbCd", "198.51.100.200", true);
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("abcd", "198.51.100.201", true));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }

    // IronWall v1.47.3: throttled exceptions carry the real remaining window seconds
    @Test
    void throttledDownload_carriesRealRetryAfter() throws Exception {
        setField("downloadsPerClientPerMinute", 2);
        setField("downloadsPerCodePerMinute", 100);
        limiter.checkAllowed("code-ra", "203.0.113.100", true);
        limiter.checkAllowed("code-ra", "203.0.113.100", true);
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("code-ra", "203.0.113.100", true));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
        assertNotNull(ex.getRetryAfterSeconds());
        assertTrue(ex.getRetryAfterSeconds() > 0 && ex.getRetryAfterSeconds() <= 60);
        assertNotNull(ex.getDetails());
        assertEquals(ex.getRetryAfterSeconds(), ex.getDetails().get("retry_after"));
    }

    // IronWall v1.47.3: authenticated users get independent buckets on the same exit IP
    @Test
    void authenticatedUsers_doNotShareClientBucketOnSameIp() throws Exception {
        setField("downloadsPerClientPerMinute", 2);
        setField("downloadsPerCodePerMinute", 100);
        limiter.checkAllowed("code-ub", "203.0.113.200", true, 1L);
        limiter.checkAllowed("code-ub", "203.0.113.200", true, 1L);
        assertThrows(BusinessException.class, () -> limiter.checkAllowed("code-ub", "203.0.113.200", true, 1L));
        assertDoesNotThrow(() -> limiter.checkAllowed("code-ub", "203.0.113.200", true, 2L));
        assertDoesNotThrow(() -> limiter.checkAllowed("code-ub", "203.0.113.200", true, 2L));
    }

    // IronWall v1.47.3: snapshot / reset used by the admin console
    @Test
    void snapshotAndReset_shouldReflectAndClearBuckets() throws Exception {
        setField("downloadsPerClientPerMinute", 1);
        setField("downloadsPerCodePerMinute", 100);
        limiter.checkAllowed("code-sr", "203.0.113.201", true);
        assertThrows(BusinessException.class, () -> limiter.checkAllowed("code-sr", "203.0.113.201", true));
        Map<String, Object> snap = limiter.snapshot();
        List<?> clients = (List<?>) snap.get("clients");
        assertFalse(clients.isEmpty());
        String key = (String) ((Map<?, ?>) clients.get(0)).get("key");
        assertTrue(limiter.reset(key));
        assertFalse(limiter.reset(key));
        assertDoesNotThrow(() -> limiter.checkAllowed("code-sr", "203.0.113.201", true));
        assertTrue(limiter.resetAll() >= 1);
        assertEquals(0, ((List<?>) limiter.snapshot().get("clients")).size());
        assertEquals(0, ((List<?>) limiter.snapshot().get("codes")).size());
    }

    @Test
    void unsignedDownloads_shouldGetHalfQuota() {
        int allowed = 0;
        int rejected = 0;
        for (int i = 0; i < 8; i++) {
            try {
                limiter.checkAllowed("code-c", "203.0.113.91");
                allowed++;
            } catch (BusinessException e) {
                assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), e.getCode());
                rejected++;
            }
        }
        assertEquals(5, allowed, "未签名下载应只有签名额度的 1/2");
        assertEquals(3, rejected);
    }

    /** IronWall v1.47.9: 超限文案必须与 Retry-After 秒数严格一致。 */
    @Test
    void throttledDownload_messageShouldMatchRetryAfterSeconds() throws Exception {
        setField("downloadsPerClientPerMinute", 1);
        setField("downloadsPerCodePerMinute", 100);
        limiter.checkAllowed("code-msg", "203.0.113.210", true);
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("code-msg", "203.0.113.210", true));
        Long retry = ex.getRetryAfterSeconds();
        assertNotNull(retry);
        assertTrue(ex.getMessage().contains(retry + "秒后再试"),
                "提示文案应包含与 Retry-After 一致的秒数");
    }
}
