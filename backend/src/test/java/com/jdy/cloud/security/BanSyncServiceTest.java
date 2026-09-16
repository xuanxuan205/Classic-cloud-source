package com.jdy.cloud.security;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.38.0: 分布式封禁联动对账契约测试。
 * 远端 BLOCKED/UNBLOCKED 合并、自环跳过、数据库异常 fail-open、开关关闭静默。
 */
@ExtendWith(MockitoExtension.class)
class BanSyncServiceTest {

    @Mock
    private AttackLogRepository attackLogRepository;
    @Mock
    private AttackGuardService attackGuardService;

    private BanSyncService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new BanSyncService(attackLogRepository, attackGuardService);
        var field = BanSyncService.class.getDeclaredField("enabled");
        field.setAccessible(true);
        field.set(service, true);
    }

    private AttackLog event(String ip, String action, String payload, String ua) {
        AttackLog log = new AttackLog();
        log.setIp(ip);
        log.setAction(action);
        log.setPayload(payload);
        log.setUserAgent(ua);
        log.setAttackType(AttackGuardService.TYPE_SYNC);
        return log;
    }

    @Test
    void remoteBlockedEvent_shouldMergeWithParsedExpiry() {
        long expiry = System.currentTimeMillis() + 600_000L;
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenReturn(List.of(event("203.0.113.80", "BLOCKED", String.valueOf(expiry), "instance:other")));
        when(attackGuardService.isSelfInstance("instance:other")).thenReturn(false);

        service.poll();

        verify(attackGuardService).applyRemoteBan("203.0.113.80", expiry);
        verify(attackGuardService, never()).applyRemoteUnblock(anyString());
    }

    @Test
    void remoteUnblockedEvent_shouldApplyRemoteUnblock() {
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenReturn(List.of(event("203.0.113.81", "UNBLOCKED", "0", "instance:other")));
        when(attackGuardService.isSelfInstance("instance:other")).thenReturn(false);

        service.poll();

        verify(attackGuardService).applyRemoteUnblock("203.0.113.81");
        verify(attackGuardService, never()).applyRemoteBan(anyString(), anyLong());
    }

    @Test
    void selfInstanceEvent_shouldBeSkipped() {
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenReturn(List.of(event("203.0.113.82", "BLOCKED", "9999999999999", "instance:self")));
        when(attackGuardService.isSelfInstance("instance:self")).thenReturn(true);

        service.poll();

        verify(attackGuardService, never()).applyRemoteBan(anyString(), anyLong());
        verify(attackGuardService, never()).applyRemoteUnblock(anyString());
    }

    @Test
    void malformedExpiry_shouldFallBackToZero() {
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenReturn(List.of(event("203.0.113.83", "BLOCKED", "not-a-number", "instance:other")));
        when(attackGuardService.isSelfInstance("instance:other")).thenReturn(false);

        service.poll();

        verify(attackGuardService).applyRemoteBan("203.0.113.83", 0L);
    }

    @Test
    void repositoryFailure_shouldFailOpenWithoutException() {
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenThrow(new RuntimeException("db down"));

        assertDoesNotThrow(() -> service.poll());
        verify(attackGuardService, never()).applyRemoteBan(anyString(), anyLong());
    }

    @Test
    void disabled_shouldNotTouchRepository() throws Exception {
        var field = BanSyncService.class.getDeclaredField("enabled");
        field.setAccessible(true);
        field.set(service, false);

        service.poll();

        verifyNoInteractions(attackLogRepository, attackGuardService);
    }

    @Test
    void newerUnblocked_shouldOverrideOlderBlockedR54K() {
        // 复现事故：旧 BLOCKED 事件 + 新 UNBLOCKED 事件；倒序回放后最终状态必须是解封。
        AttackLog olderBlocked = event("198.51.100.30", "BLOCKED",
                String.valueOf(System.currentTimeMillis() + 3_600_000L), "instance:legacy-a");
        AttackLog newerUnblocked = event("198.51.100.30", "UNBLOCKED", "0", "instance:legacy-b");
        when(attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC))
                .thenReturn(List.of(newerUnblocked, olderBlocked));
        when(attackGuardService.isSelfInstance(anyString())).thenReturn(false);

        service.poll();

        InOrder inOrder = inOrder(attackGuardService);
        inOrder.verify(attackGuardService).applyRemoteBan(eq("198.51.100.30"), anyLong());
        inOrder.verify(attackGuardService).applyRemoteUnblock("198.51.100.30");
    }
}
