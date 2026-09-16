package com.jdy.cloud.service;

import com.jdy.cloud.security.AttackGuardService;
import com.jdy.cloud.security.TrapService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * IronWall v1.26.1: 申诉端点限流回归测试。
 */
class AppealCenterServiceTest {

    @TempDir
    Path tempDir;

    private AppealCenterService newService(long minIntervalMs, int maxPendingPerIp) {
        AppealCenterService service = new AppealCenterService(mock(EmailService.class),
                new com.fasterxml.jackson.databind.ObjectMapper(),
                mock(AttackGuardService.class),
                mock(TrapService.class),
                tempDir.resolve("blocked-appeals.json").toString());
        ReflectionTestUtils.setField(service, "appealMinIntervalMs", minIntervalMs);
        ReflectionTestUtils.setField(service, "appealMaxPendingPerIp", maxPendingPerIp);
        ReflectionTestUtils.setField(service, "adminEmail", "");
        ReflectionTestUtils.setField(service, "mailUsername", "");
        return service;
    }

    @Test
    void submit_shouldRejectFrequentDuplicateWithinWindow() {
        AppealCenterService service = newService(3600000L, 3);
        AppealCenterService.AppealSubmitResult first = service.submit("203.0.113.10", "", "误封申诉");
        AppealCenterService.AppealSubmitResult second = service.submit("203.0.113.10", "", "重复申诉");

        assertEquals("ACCEPTED", first.code);
        assertNotNull(first.record);
        assertEquals("TOO_FREQUENT", second.code);
        assertNull(second.record);
    }

    @Test
    void submit_shouldRejectWhenPendingPerIpReachesLimit() throws Exception {
        AppealCenterService service = newService(1L, 1);
        assertEquals("ACCEPTED", service.submit("203.0.113.11", "", "第一次").code);
        Thread.sleep(5);
        AppealCenterService.AppealSubmitResult second = service.submit("203.0.113.11", "", "第二次");

        assertEquals("TOO_MANY_PENDING", second.code);
        assertNull(second.record);
    }

    @Test
    void resolve_processed_shouldImmediatelyUnblockIp() {
        AttackGuardService guard = mock(AttackGuardService.class);
        when(guard.getBlockedSegments()).thenReturn(List.of());
        TrapService trap = mock(TrapService.class);
        AppealCenterService service = new AppealCenterService(mock(EmailService.class),
                new com.fasterxml.jackson.databind.ObjectMapper(), guard, trap,
                tempDir.resolve("blocked-appeals.json").toString());
        ReflectionTestUtils.setField(service, "appealMinIntervalMs", 1L);
        ReflectionTestUtils.setField(service, "appealMaxPendingPerIp", 3);
        ReflectionTestUtils.setField(service, "adminEmail", "");
        ReflectionTestUtils.setField(service, "mailUsername", "");
        ReflectionTestUtils.setField(service, "fail2banUnbanEnabled", false);

        AppealCenterService.AppealRecord record = service.submit("203.0.113.20", "test@example.com", "误封申诉").record;
        AppealCenterService.AppealRecord resolved = service.resolve(record.id, "processed", "同意解封");

        assertNotNull(resolved);
        assertEquals("PROCESSED", resolved.status);
        assertNotNull(resolved.unbanNote);
        verify(guard).unblock("203.0.113.20");
        verify(trap).release("203.0.113.20");
    }
}
