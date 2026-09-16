package com.jdy.cloud.security;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.service.ThreatIntelService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.26.0: 封禁专属页信息收口测试。
 * 页面只保留通用封禁警示与误封自助验证，不得泄露五层陷阱、端口、层数、引擎名或攻击流水等内部机制。
 */
@ExtendWith(MockitoExtension.class)
class BlockedIpPageServiceTest {

    @Mock
    private AttackGuardService attackGuardService;

    @Mock
    private AttackLogRepository attackLogRepository;

    @Mock
    private TrapService trapService;

    @Mock
    private DecoyPortTrapService decoyPortTrapService;

    @Mock
    private ThreatIntelService threatIntelService;

    private BlockedIpPageService service;

    @BeforeEach
    void setUp() {
        lenient().when(decoyPortTrapService.snapshot()).thenReturn(List.of());
        lenient().when(threatIntelService.lookupGeo(any())).thenReturn(null);
        service = new BlockedIpPageService(attackGuardService, attackLogRepository, trapService, decoyPortTrapService, threatIntelService);
    }

    @Test
    void render_shouldBeGenericAndNotLeakMechanisms() {
        when(attackGuardService.isBlocked("203.0.113.80")).thenReturn(true);
        when(attackGuardService.isBlockedSegment("203.0.113.80")).thenReturn(false);

        AttackLog log = new AttackLog();
        log.setIp("203.0.113.80");
        log.setAttackType("SQL注入");
        log.setPath("/api/files/list");
        log.setPayload("q=<script>alert(1)</script>");
        log.setAction("WARN");
        log.setCreatedAt(LocalDateTime.of(2026, 8, 16, 1, 0, 0));
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.80")).thenReturn(List.of(log));

        String html = service.render("203.0.113.80");

        assertTrue(html.contains("访问受限"));
        assertTrue(html.contains("已封禁"));
        assertTrue(html.contains("处置说明"));
        assertTrue(html.contains("处置原因"));
        assertTrue(html.contains("IW-INJECTION"));
        assertTrue(html.contains("203.0.113.80"));
        assertTrue(html.contains("访问行为及相关网络信息已记录"));

        assertFalse(html.contains("五层"));
        assertFalse(html.contains("七层"));
        assertFalse(html.contains("假端口"));
        assertFalse(html.contains("陷阱"));
        assertFalse(html.contains("黑洞"));
        assertFalse(html.contains("IronWall"));
        assertFalse(html.contains("威慑引擎"));
        assertFalse(html.contains("SQL注入"));
        assertFalse(html.contains("L1"));
        assertFalse(html.contains("L5"));
        assertFalse(html.contains("网段封禁"));
        assertFalse(html.contains("alert(1)"));
        assertFalse(html.contains("<script>"));
    }

    @Test
    void render_shouldNotExposeSegmentOrTrapState() {
        when(attackGuardService.isBlocked("203.0.113.81")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.81")).thenReturn(true);

        AttackGuardService.SegmentInfo seg = new AttackGuardService.SegmentInfo(
                "203.0.113.0/24", 3, System.currentTimeMillis() + 3600_000L, 3600L);
        when(attackGuardService.getBlockedSegments()).thenReturn(List.of(seg));
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.81")).thenReturn(List.of());

        String html = service.render("203.0.113.81");

        assertTrue(html.contains("已封禁"));
        assertTrue(html.contains("203.0.113.81"));
        assertFalse(html.contains("203.0.113.0/24"));
        assertFalse(html.contains("网段封禁"));
        assertFalse(html.contains("陷阱"));
    }

    @Test
    void render_shouldIncludeChallengeFormWhenIpBlockedOnly() {
        when(attackGuardService.isBlocked("203.0.113.84")).thenReturn(true);
        when(attackGuardService.isBlockedSegment("203.0.113.84")).thenReturn(false);
        when(attackGuardService.isChallengeEnabled()).thenReturn(true);
        when(attackGuardService.issueChallenge("203.0.113.84")).thenReturn("tok123|13 + 27 = ?");

        String html = service.render("203.0.113.84");

        assertTrue(html.contains("人机验证"));
        assertTrue(html.contains("13 + 27 = ?"));
        assertTrue(html.contains(BlockedIpPageFilter.VERIFY_PATH));
    }

    @Test
    void render_shouldNotIncludeChallengeFormWhenSegmentBlockedOrTrapped() {
        when(attackGuardService.isBlocked("203.0.113.85")).thenReturn(true);
        when(attackGuardService.isBlockedSegment("203.0.113.85")).thenReturn(true);
        when(trapService.entryOf("203.0.113.85")).thenReturn(null);

        String html = service.render("203.0.113.85");

        assertFalse(html.contains("人机验证 · 误封自助解除"));
        verify(attackGuardService, never()).issueChallenge(anyString());
    }

    @Test
    void render_shouldOfferEscapeChallengeWhenTrapAgeEnough() {
        ReflectionTestUtils.setField(service, "trapEscapeMinutes", 10L);
        when(attackGuardService.isBlocked("203.0.113.86")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.86")).thenReturn(false);
        long now = System.currentTimeMillis();
        TrapService.TrapEntry trap = new TrapService.TrapEntry(1, "测试陷阱", now - 11 * 60_000L, now + 20 * 60_000L);
        when(trapService.entryOf("203.0.113.86")).thenReturn(trap);
        when(attackGuardService.isChallengeEnabled()).thenReturn(true);
        when(attackGuardService.issueChallenge("203.0.113.86")).thenReturn("tok9|3 + 4 = ?");

        String html = service.render("203.0.113.86");

        assertTrue(html.contains("人机验证"));
        assertTrue(html.contains("3 + 4 = ?"));
    }

    @Test
    void render_shouldNotOfferEscapeChallengeWhenTrapTooYoung() {
        ReflectionTestUtils.setField(service, "trapEscapeMinutes", 10L);
        when(attackGuardService.isBlocked("203.0.113.87")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.87")).thenReturn(false);
        long now = System.currentTimeMillis();
        TrapService.TrapEntry trap = new TrapService.TrapEntry(1, "测试陷阱", now - 60_000L, now + 29 * 60_000L);
        when(trapService.entryOf("203.0.113.87")).thenReturn(trap);

        String html = service.render("203.0.113.87");

        assertFalse(html.contains("人机验证 · 误封自助解除"));
        verify(attackGuardService, never()).issueChallenge(anyString());
    }

    @Test
    void isActiveLockdown_shouldCoverTrapOnlyState() {
        when(attackGuardService.isBlocked("203.0.113.98")).thenReturn(false);
        when(attackGuardService.isBlockedSegment("203.0.113.98")).thenReturn(false);
        when(trapService.isTrapped("203.0.113.98")).thenReturn(true);
        assertTrue(service.isActiveLockdown("203.0.113.98"));
    }

    @Test
    void releaseTrap_shouldDelegateToTrapService() {
        service.releaseTrap("203.0.113.99");
        verify(trapService).release("203.0.113.99");
    }

    @Test
    void render_shouldHandleRepositoryFailure() {
        when(attackGuardService.isBlocked("203.0.113.82")).thenReturn(true);
        when(attackGuardService.isBlockedSegment("203.0.113.82")).thenReturn(false);
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.82"))
                .thenThrow(new RuntimeException("db down"));

        String html = service.render("203.0.113.82");

        assertTrue(html.contains("访问受限"));
        assertTrue(html.contains("已封禁"));
        assertFalse(html.contains("五层"));
        assertFalse(html.contains("七层"));
        assertFalse(html.contains("陷阱"));
    }

    /** IronWall v1.28.5: 专属页展示来源位置（不含经纬度与内部机制）。 */
    @Test
    void render_shouldShowSourceLocation() {
        when(attackGuardService.isBlocked("203.0.113.80")).thenReturn(true);
        when(attackGuardService.isBlockedSegment("203.0.113.80")).thenReturn(false);
        when(attackLogRepository.findTop100ByIpOrderByCreatedAtDesc("203.0.113.80")).thenReturn(List.of());
        when(threatIntelService.lookupGeo("203.0.113.80"))
                .thenReturn(java.util.Map.of("display", "中国 广东 深圳 · 电信"));

        String html = service.render("203.0.113.80");

        assertTrue(html.contains("来源位置"));
        assertTrue(html.contains("中国 广东 深圳 · 电信"));
        assertFalse(html.contains("\"lat\""));
    }
}
