package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.38.0: 告警联动通知服务契约测试。
 * 同源5分钟节流、200条环形缓冲、快照字段、关闭开关时完全静默。
 */
class AlertNotifierServiceTest {

    private AlertNotifierService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new AlertNotifierService(null);
        setField("enabled", true);
    }

    private void setField(String name, Object value) throws Exception {
        var field = AlertNotifierService.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(service, value);
    }

    @Test
    void sameSourceWithinFiveMinutes_shouldBeThrottled() {
        service.notify("IP封禁", "203.0.113.50", "首次告警");
        service.notify("IP封禁", "203.0.113.50", "五分钟内第二次告警应被节流");

        Map<String, Object> snap = service.snapshot();
        assertEquals(1L, snap.get("total"));
        assertEquals(1, service.recent(20).size());
    }

    @Test
    void distinctSources_shouldAllBeRecorded() {
        service.notify("IP封禁", "203.0.113.51", "a");
        service.notify("IP封禁", "203.0.113.52", "b");
        service.notify("挑战滥用", "203.0.113.51", "c");

        assertEquals(3L, service.snapshot().get("total"));
        assertEquals(3, service.recent(20).size());
    }

    @Test
    void recentBuffer_shouldCapAt200() {
        for (int i = 0; i < 250; i++) {
            service.notify("TYPE-" + (i % 50), "203.0.113." + (i % 254 + 1), "detail-" + i);
        }
        assertEquals(250L, service.snapshot().get("total"));
        assertEquals(200, service.recent(300).size());
    }

    @Test
    void disabled_shouldBeFullySilent() throws Exception {
        setField("enabled", false);
        service.notify("IP封禁", "203.0.113.60", "x");

        Map<String, Object> snap = service.snapshot();
        assertEquals(0L, snap.get("total"));
        assertEquals(0, service.recent(20).size());
        assertEquals(false, snap.get("enabled"));
    }

    @Test
    void snapshot_shouldExposeConfigFlags() throws Exception {
        setField("webhookUrl", "");
        setField("adminEmail", "");

        Map<String, Object> snap = service.snapshot();
        assertEquals(true, snap.get("enabled"));
        assertEquals(false, snap.get("webhook_configured"));
        assertEquals(false, snap.get("email_configured"));
        assertNotNull(snap.get("recent"));
    }

    @Test
    void longDetail_shouldBeTruncatedTo300() {
        service.notify("IP封禁", "203.0.113.70", "x".repeat(5000));
        List<Map<String, Object>> recent = service.recent(5);
        assertEquals(300, String.valueOf(recent.get(0).get("detail")).length());
    }

    @Test
    void nullFields_shouldNotBreakNotify() {
        service.notify(null, null, null);
        Map<String, Object> snap = service.snapshot();
        assertEquals(1L, snap.get("total"));
        assertNull(service.recent(5).get(0).get("ip"));
    }
}
