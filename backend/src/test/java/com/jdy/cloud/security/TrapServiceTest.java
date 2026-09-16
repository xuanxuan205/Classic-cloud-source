package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.21: 五层黑洞陷阱服务契约测试（只进不出）。
 */
@ExtendWith(MockitoExtension.class)
class TrapServiceTest {

    @Mock
    private AttackGuardService attackGuardService;

    @Mock
    private RequestTrustResolver trustResolver;

    private TrapService service;

    @BeforeEach
    void setUp() {
        service = new TrapService(attackGuardService, trustResolver);
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "trapMinutes", 30L);
        AttackGuardService.AttackRecord blocked = new AttackGuardService.AttackRecord(
                "203.0.113.90", AttackGuardService.TYPE_TRAP, "trap", 20, 1,
                System.currentTimeMillis() + 30 * 60_000L, "BLOCKED");
        lenient().when(attackGuardService.recordWeighted(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), eq(false), anyInt())).thenReturn(blocked);
        lenient().when(trustResolver.isWhitelisted(anyString())).thenReturn(false);
    }

    @Test
    void trapShouldSwallowAndEscalate() {
        service.trap("203.0.113.90", 2, "挑战cookie伪造", "/api/files/list", "curl", "GET", false);

        assertTrue(service.isTrapped("203.0.113.90"));
        TrapService.TrapEntry entry = service.entryOf("203.0.113.90");
        assertNotNull(entry);
        assertEquals(2, entry.layer);
        assertTrue(entry.expiresAt > entry.enteredAt);
        verify(attackGuardService).recordWeighted(eq("203.0.113.90"), eq(AttackGuardService.TYPE_TRAP),
            contains("七层黑洞陷阱·第2层"), anyString(), anyString(), anyString(), eq(false), eq(20));
    }

    @Test
    void trapShouldBeIdempotentAndKeepEarliestEntry() {
        service.trap("203.0.113.91", 1, "first", "/a", "ua", "GET", false);
        long firstEntered = service.entryOf("203.0.113.91").enteredAt;
        service.trap("203.0.113.91", 3, "second", "/b", "ua", "GET", false);

        TrapService.TrapEntry entry = service.entryOf("203.0.113.91");
        assertEquals(3, entry.layer);
        assertEquals(firstEntered, entry.enteredAt);
        verify(attackGuardService, times(1)).recordWeighted(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), eq(false), anyInt());
    }

    @Test
    void trustedSessionNeverTrapped() {
        service.trap("203.0.113.92", 4, "x", "/a", "ua", "GET", true);

        assertFalse(service.isTrapped("203.0.113.92"));
        verify(attackGuardService, never()).recordWeighted(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyBoolean(), anyInt());
    }

    @Test
    void releaseShouldOpenExit() {
        service.trap("203.0.113.93", 2, "x", "/a", "ua", "GET", false);
        assertTrue(service.isTrapped("203.0.113.93"));

        service.release("203.0.113.93");

        assertFalse(service.isTrapped("203.0.113.93"));
        assertNull(service.entryOf("203.0.113.93"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void expiredTrapShouldAutoRelease() {
        service.trap("203.0.113.94", 2, "x", "/a", "ua", "GET", false);
        Map<String, TrapService.TrapEntry> traps =
                (Map<String, TrapService.TrapEntry>) ReflectionTestUtils.getField(service, "traps");
        traps.put("203.0.113.94", new TrapService.TrapEntry(
                2, "x", System.currentTimeMillis() - 10_000L, System.currentTimeMillis() - 1L));

        assertFalse(service.isTrapped("203.0.113.94"));
        assertNull(service.entryOf("203.0.113.94"));
    }
    @Test
    void whitelistedIpNeverTrapped() {
        when(trustResolver.isWhitelisted("203.0.113.95")).thenReturn(true);

        service.trap("203.0.113.95", 2, "x", "/a", "ua", "GET", false);

        assertFalse(service.isTrapped("203.0.113.95"));
        verify(attackGuardService, never()).recordWeighted(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyBoolean(), anyInt());
    }
}
