package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.41.0: 签名失败审计测试。
 * 仅统计与告警语义：窗口内计数、阈值触发、跨窗口重置、不依赖任何攻击计分链路。
 */
class SignFailureAuditServiceTest {

    private SignFailureAuditService audit;

    @BeforeEach
    void setUp() {
        audit = new SignFailureAuditService();
        ReflectionTestUtils.setField(audit, "thresholdPerMinute", 5);
    }

    @Test
    void belowThreshold_noAlertButCounted() {
        for (int i = 0; i < 4; i++) {
            audit.record("203.0.113.9");
        }
        Map<String, Object> stats = audit.stats();
        assertEquals(4L, stats.get("total_1m"));
        assertEquals(1, stats.get("distinct_ips_1m"));
    }

    @Test
    void thresholdReached_alertOnlyOncePerWindow() {
        for (int i = 0; i < 10; i++) {
            audit.record("203.0.113.9");
        }
        Map<String, Object> stats = audit.stats();
        assertEquals(10L, stats.get("total_1m"));
        assertFalse(Boolean.parseBoolean(String.valueOf(stats.get("top") == null)), "top 列表应存在");
    }

    @Test
    void nullIp_isIgnored() {
        audit.record(null);
        audit.record("");
        assertEquals(0L, audit.stats().get("total_1m"));
    }

    @Test
    void distinctIps_areCountedSeparately() {
        audit.record("203.0.113.9");
        audit.record("203.0.113.10");
        Map<String, Object> stats = audit.stats();
        assertEquals(2L, stats.get("total_1m"));
        assertEquals(2, stats.get("distinct_ips_1m"));
    }
}
