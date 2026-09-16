package com.jdy.cloud.service;

import com.jdy.cloud.model.NotificationSettings;
import com.jdy.cloud.repository.NotificationSettingsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.function.Function;

/**
 * IronWall v1.47.10: 通知偏好的唯一读取入口。
 *
 * 个人中心的四个通知开关此前只被写入数据库、没有任何消费方（开关空转）。
 * 本服务把偏好读出来，供邮件/浏览器通知的发送方做门控：
 * email-notify 为总开关：关闭后一切“通知类邮件”都不再发送；
 * share / storage 为分类开关：与总开关同时开启才发送对应类别通知；
 * 读取失败或未初始化时回落到与数据库默认值一致的宽松缺省，
 * 避免因偏好读取异常而静默丢失本应送达的通知；
 * 安全类邮件（验证码、重置密码、登录提醒、申诉回执）不走本服务，永远发送。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationPreferenceService {

    public static final boolean DEFAULT_EMAIL_NOTIFY = true;
    public static final boolean DEFAULT_BROWSER_NOTIFY = true;
    public static final boolean DEFAULT_STORAGE_ALERT = true;
    public static final boolean DEFAULT_SHARE_NOTIFY = false;

    private final NotificationSettingsRepository notificationSettingsRepository;

    /** 邮箱通知总开关。 */
    public boolean emailNotifyEnabled(Long userId) {
        return flag(userId, NotificationSettings::getEmailNotify, DEFAULT_EMAIL_NOTIFY);
    }

    /** 浏览器通知开关（前端消费，后端仅透传持久化值）。 */
    public boolean browserNotifyEnabled(Long userId) {
        return flag(userId, NotificationSettings::getBrowserNotify, DEFAULT_BROWSER_NOTIFY);
    }

    /** 存储提醒开关。 */
    public boolean storageAlertEnabled(Long userId) {
        return flag(userId, NotificationSettings::getStorageAlert, DEFAULT_STORAGE_ALERT);
    }

    /** 分享通知开关（分享被下载/封禁）。 */
    public boolean shareNotifyEnabled(Long userId) {
        return flag(userId, NotificationSettings::getShareNotify, DEFAULT_SHARE_NOTIFY);
    }

    /** 分享类通知邮件是否送达：邮箱总开关 + 分享通知，双开才发。 */
    public boolean shouldEmailShareNotify(Long userId) {
        return emailNotifyEnabled(userId) && shareNotifyEnabled(userId);
    }

    /** 存储类提醒邮件是否送达：邮箱总开关 + 存储提醒，双开才发。 */
    public boolean shouldEmailStorageAlert(Long userId) {
        return emailNotifyEnabled(userId) && storageAlertEnabled(userId);
    }

    private boolean flag(Long userId, Function<NotificationSettings, Boolean> getter, boolean fallback) {
        if (userId == null) {
            return fallback;
        }
        try {
            // 行存在但列为 NULL（历史数据）时 map 得到空 Optional，同样回落缺省值
            return notificationSettingsRepository.findByUserId(userId)
                    .map(getter)
                    .orElse(fallback);
        } catch (Exception e) {
            log.warn("[IronWall] notification preference read failed, fallback={} userId={} err={}",
                    fallback, userId, e.getMessage());
            return fallback;
        }
    }
}
