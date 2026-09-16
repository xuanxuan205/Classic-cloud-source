package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.12: share-code enumeration rate limit contract tests.
 */
class ShareLookupLimiterTest {

    private ShareLookupLimiter limiter;

    @BeforeEach
    void setUp() {
        limiter = new ShareLookupLimiter();
        ReflectionTestUtils.setField(limiter, "lookupsPerMinute", 3);
    }

    @Test
    void shouldAllowWithinLimit() {
        assertDoesNotThrow(() -> {
            limiter.checkAllowed("203.0.113.10");
            limiter.checkAllowed("203.0.113.10");
            limiter.checkAllowed("203.0.113.10");
        });
    }

    @Test
    void shouldThrowWhenLimitExceeded() {
        limiter.checkAllowed("203.0.113.11");
        limiter.checkAllowed("203.0.113.11");
        limiter.checkAllowed("203.0.113.11");
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("203.0.113.11"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }

    @Test
    void shouldCountPerIpIndependently() {
        limiter.checkAllowed("203.0.113.12");
        limiter.checkAllowed("203.0.113.12");
        limiter.checkAllowed("203.0.113.12");
        // 另一 IP 不受影响
        assertDoesNotThrow(() -> limiter.checkAllowed("203.0.113.13"));
    }
}