package com.jdy.cloud.service;

import com.jdy.cloud.model.NotificationSettings;
import com.jdy.cloud.repository.NotificationSettingsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * IronWall v1.47.10: 通知开关门控测试。
 * 开关必须真正决定邮件是否发送，且偏好读取异常时回落到宽松缺省而非静默丢通知。
 */
@ExtendWith(MockitoExtension.class)
class NotificationPreferenceServiceTest {

    @Mock private NotificationSettingsRepository notificationSettingsRepository;

    private NotificationPreferenceService service;

    @BeforeEach
    void setUp() {
        service = new NotificationPreferenceService(notificationSettingsRepository);
    }

    /** 未初始化用户：回落到数据库默认值（邮箱开 / 分享关）。 */
    @Test
    void shouldFallBackToDefaultsWhenNotConfigured() {
        when(notificationSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());

        assertTrue(service.emailNotifyEnabled(1L));
        assertTrue(service.storageAlertEnabled(1L));
        assertFalse(service.shareNotifyEnabled(1L));
        assertFalse(service.shouldEmailShareNotify(1L), "分享通知默认关闭，不应发信");
        assertTrue(service.shouldEmailStorageAlert(1L));
    }

    /** 已保存的偏好必须被尊重。 */
    @Test
    void shouldHonorStoredPreferences() {
        NotificationSettings s = new NotificationSettings();
        s.setUserId(2L);
        s.setEmailNotify(false);
        s.setStorageAlert(true);
        s.setShareNotify(true);
        when(notificationSettingsRepository.findByUserId(2L)).thenReturn(Optional.of(s));

        assertFalse(service.emailNotifyEnabled(2L));
        assertTrue(service.shareNotifyEnabled(2L));
        assertFalse(service.shouldEmailShareNotify(2L), "邮箱总开关关闭时不得发信");
        assertFalse(service.shouldEmailStorageAlert(2L), "邮箱总开关关闭时不得发信");
    }

    /** 列为 NULL（历史数据）时不能当作 false，应回落缺省。 */
    @Test
    void shouldFallBackWhenColumnIsNull() {
        NotificationSettings s = new NotificationSettings();
        s.setUserId(3L);
        s.setEmailNotify(null);
        when(notificationSettingsRepository.findByUserId(3L)).thenReturn(Optional.of(s));

        assertTrue(service.emailNotifyEnabled(3L));
    }

    /** 偏好读取异常不得阻断发送链路：回落到宽松缺省。 */
    @Test
    void shouldFallBackOnRepositoryFailure() {
        when(notificationSettingsRepository.findByUserId(4L))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("db down"));

        assertTrue(service.emailNotifyEnabled(4L));
        assertFalse(service.shareNotifyEnabled(4L));
        assertDoesNotThrow(() -> service.shouldEmailShareNotify(4L));
    }

    /** userId 为空时回落到缺省，不查库。 */
    @Test
    void shouldFallBackForNullUserId() {
        assertTrue(service.emailNotifyEnabled(null));
        assertFalse(service.shareNotifyEnabled(null));
    }
}
