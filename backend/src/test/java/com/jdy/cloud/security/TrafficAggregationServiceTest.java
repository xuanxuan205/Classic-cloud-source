package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.38.0: 跨IP行为基线聚合观测契约测试。
 * 只告警不封禁；阈值以下静默；窗口过期后重新计数；快照反映集群数量。
 */
@ExtendWith(MockitoExtension.class)
class TrafficAggregationServiceTest {

    @Mock
    private AlertNotifierService alertNotifier;

    private TrafficAggregationService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new TrafficAggregationService(alertNotifier);
        setField("uaIpThreshold", 3);
        setField("tlsIpThreshold", 99);
        setField("deviceIpThreshold", 99);
        setField("windowMs", 30_000L);
    }

    private void setField(String name, Object value) throws Exception {
        var field = TrafficAggregationService.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(service, value);
    }

    @Test
    void sameUaAcrossManyIps_shouldAlertExactlyOncePerWindow() {
        String ua = "Mozilla/5.0 scanner-probe";
        service.observe(ua, null, null, "203.0.113.1");
        service.observe(ua, null, null, "203.0.113.2");
        verifyNoInteractions(alertNotifier);

        service.observe(ua, null, null, "203.0.113.3");
        verify(alertNotifier, times(1)).notify(eq("同UA多源聚合"), anyString(), contains("已关联 3 个来源IP"));

        service.observe(ua, null, null, "203.0.113.4");
        verify(alertNotifier, times(1)).notify(anyString(), anyString(), anyString());
    }

    @Test
    void belowThreshold_shouldStaySilent() {
        service.observe("ua-x", null, null, "203.0.113.11");
        service.observe("ua-x", null, null, "203.0.113.12");
        verifyNoInteractions(alertNotifier);
        Map<String, Object> snap = service.snapshot();
        assertEquals(0L, snap.get("ua_clusters"));
    }

    @Test
    void expiredWindow_shouldResetAndReAlert() throws Exception {
        String ua = "ua-expired";
        service.observe(ua, null, null, "203.0.113.21");
        service.observe(ua, null, null, "203.0.113.22");
        service.observe(ua, null, null, "203.0.113.23");
        verify(alertNotifier).notify(eq("同UA多源聚合"), anyString(), anyString());

        setField("windowMs", 1L);
        Thread.sleep(5L);
        service.sweep();
        service.observe(ua, null, null, "203.0.113.24");
        service.observe(ua, null, null, "203.0.113.25");
        service.observe(ua, null, null, "203.0.113.26");
        verify(alertNotifier, times(2)).notify(eq("同UA多源聚合"), anyString(), anyString());
    }

    @Test
    void blankIp_shouldBeIgnored() {
        service.observe("ua-any", null, null, null);
        service.observe("ua-any", null, null, "  ");
        verifyNoInteractions(alertNotifier);
        Map<String, Object> snap = service.snapshot();
        assertEquals(0, snap.get("tracked_keys"));
    }

    @Test
    void nullAlertNotifier_shouldNotBreakObservation() throws Exception {
        TrafficAggregationService silent = new TrafficAggregationService(null);
        var field = TrafficAggregationService.class.getDeclaredField("uaIpThreshold");
        field.setAccessible(true);
        field.set(silent, 2);
        var windowField = TrafficAggregationService.class.getDeclaredField("windowMs");
        windowField.setAccessible(true);
        windowField.set(silent, 30_000L);
        silent.observe("ua-silent", null, null, "203.0.113.31");
        silent.observe("ua-silent", null, null, "203.0.113.32");
        assertEquals(1L, silent.snapshot().get("ua_clusters"));
    }
}
