package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.7: 分享密码爆破限频单元测试。
 */
class SharePasswordLimiterTest {

    private final SharePasswordLimiter limiter = new SharePasswordLimiter();

    @Test
    void shouldBlockShare_afterFiveFailures() {
        for (int i = 0; i < 5; i++) {
            limiter.recordFailure("a3f7d8ca", "198.51.100.33");
        }
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("a3f7d8ca", "198.51.100.33"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }

    @Test
    void differentShare_shouldNotBeBlocked() {
        for (int i = 0; i < 5; i++) {
            limiter.recordFailure("a3f7d8ca", "198.51.100.33");
        }
        assertDoesNotThrow(() -> limiter.checkAllowed("bbbbbbbb", "198.51.100.33"));
    }

    @Test
    void clear_shouldResetWindow() {
        for (int i = 0; i < 5; i++) {
            limiter.recordFailure("a3f7d8ca", "198.51.100.33");
        }
        limiter.clear("a3f7d8ca", "198.51.100.33");
        assertDoesNotThrow(() -> limiter.checkAllowed("a3f7d8ca", "198.51.100.33"));
    }

    @Test
    void ipGlobal_shouldBlockAfterTwentyFailures() {
        for (int i = 0; i < 20; i++) {
            limiter.recordFailure("code" + i, "198.51.100.33");
        }
        BusinessException ex = assertThrows(BusinessException.class,
                () -> limiter.checkAllowed("fresh-code", "198.51.100.33"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }
}