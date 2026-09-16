package com.jdy.cloud.service;

import com.jdy.cloud.model.AuditLog;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.AuditLogRepository;
import com.jdy.cloud.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.47.11: 公开分享下载审计归属回归门禁。
 *
 * 访客下载必须记成 share_download（不是 download），文案必须写明访客身份，
 * 分享码只允许保留前缀，且 IP 解析开关必须保持 "system" 语义。
 */
@ExtendWith(MockitoExtension.class)
class AuditLogServiceShareDownloadTest {

    @Mock private AuditLogRepository auditLogRepository;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private AuditLogService auditLogService;

    private AuditLog capture(Long ownerId, String shareCode, String fileName) {
        when(userRepository.findById(ownerId)).thenReturn(Optional.of(user(ownerId, "alice")));
        auditLogService.logShareDownload(ownerId, shareCode, fileName);
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        return captor.getValue();
    }

    private static User user(Long id, String username) {
        User u = new User();
        u.setId(id);
        u.setUsername(username);
        return u;
    }

    @Test
    void shareDownload_shouldUseDedicatedActionCode() {
        AuditLog l = capture(1L, "deadbeefcafe12345678", "report.pdf");

        assertEquals("share_download", l.getAction(),
                "访客下载必须与站内 download 分属两种动作码");
        assertEquals("share", l.getTargetType());
        assertEquals("report.pdf", l.getTargetName());
        assertEquals(1L, l.getUserId().longValue(), "记录仍归属分享者，表示事件发生在谁的分享上");
        assertEquals("alice", l.getUsername());
        assertEquals("success", l.getStatus());
    }

    @Test
    void shareDownload_shouldStateVisitorAsTheActor() {
        AuditLog l = capture(1L, "deadbeefcafe12345678", "report.pdf");

        assertTrue(l.getDetail().contains("访客通过公开分享下载"),
                "详情必须显式标注下载者是访客，而非分享者本人");
        assertTrue(l.getDetail().contains("report.pdf"));
        assertTrue(l.getDetail().contains("分享者: alice"));
        // 旧文案「<分享者> 下载文件: xxx」会把访客动作误读成分享者本人下载，必须绝迹
        assertFalse(l.getDetail().contains("alice 下载文件"),
                "不得再输出把访客动作记成分享者本人下载的旧文案");
    }

    @Test
    void shareDownload_shouldMaskShareCodeToPrefix() {
        AuditLog l = capture(1L, "deadbeefcafe12345678", "report.pdf");

        assertTrue(l.getDetail().contains("deadbeef…"), "分享码应只保留前 8 位用于人工比对");
        assertFalse(l.getDetail().contains("deadbeefcafe12345678"),
                "完整分享码是访问凭证，绝不落库");
    }

    @Test
    void shareDownload_shouldTolerateShortOrMissingShareCode() {
        when(userRepository.findById(2L)).thenReturn(Optional.of(user(2L, "alice")));
        when(userRepository.findById(3L)).thenReturn(Optional.of(user(3L, "alice")));

        auditLogService.logShareDownload(2L, "abc123", "a.txt");
        auditLogService.logShareDownload(3L, null, "b.txt");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository, times(2)).save(captor.capture());
        List<AuditLog> logs = captor.getAllValues();

        assertTrue(logs.get(0).getDetail().contains("abc123"));
        assertFalse(logs.get(0).getDetail().contains("…"), "短码无需截断");
        assertTrue(logs.get(1).getDetail().contains("分享码: -"),
                "分享码缺失时降级为占位符，不得抛异常");
    }

    @Test
    void shareDownload_shouldFallBackToAnonymousOwnerWhenUserMissing() {
        when(userRepository.findById(404L)).thenReturn(Optional.empty());

        auditLogService.logShareDownload(404L, "deadbeef", "c.bin");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        assertEquals("unknown-404", captor.getValue().getUsername());
    }
}
