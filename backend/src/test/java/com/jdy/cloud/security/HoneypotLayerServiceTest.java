package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.18: 五层蜜罐分层记分契约测试。
 */
@ExtendWith(MockitoExtension.class)
class HoneypotLayerServiceTest {

    @Mock private AttackGuardService attackGuardService;

    private HoneypotLayerService service;

    @BeforeEach
    void setUp() {
        service = new HoneypotLayerService(attackGuardService);
    }

    @Test
    void touchShouldRecordAttackWithLayerPayload() {
        int deepest = service.touch(HoneypotLayerService.L2_CREDENTIALS, "203.0.113.80",
                "/api/honeypot/login", "curl/8", "POST");

        assertEquals(HoneypotLayerService.L2_CREDENTIALS, deepest);
        verify(attackGuardService).recordWeighted(eq("203.0.113.80"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第2层"), eq("/api/honeypot/login"),
                eq("curl/8"), eq("POST"), eq(false), eq(10));
    }

    @Test
    void touchShouldAdvanceDeepestLayerPerIp() {
        service.touch(HoneypotLayerService.L1_PATH, "203.0.113.81", "/api/.env", null, "GET");
        service.touch(HoneypotLayerService.L3_CONSOLE, "203.0.113.81", "/api/honeypot/console", null, "GET");
        service.touch(HoneypotLayerService.L4_DATA, "203.0.113.81", "/api/honeypot/dump.sql", null, "GET");

        assertEquals(HoneypotLayerService.L4_DATA, service.stateOf("203.0.113.81").deepestLayer);
        assertEquals(3, service.stateOf("203.0.113.81").touches);
        assertEquals(0, service.stateOf("203.0.113.99").touches);
    }

    @Test
    void touchShouldSurviveRecordFailures() {
        doThrow(new RuntimeException("db down")).when(attackGuardService)
                .recordWeighted(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyBoolean(), anyInt());

        int deepest = service.touch(HoneypotLayerService.L2_CREDENTIALS, "203.0.113.82",
                "/api/honeypot/login", null, "GET");

        assertEquals(HoneypotLayerService.L2_CREDENTIALS, deepest);
    }
}
