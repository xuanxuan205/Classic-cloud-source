package com.jdy.cloud.service;

import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.SystemConfig;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.SystemConfigRepository;
import com.jdy.cloud.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IronWall v1.28.0: 回收站到期自动清理。
 * 每日 04:10 执行：删除超过保留天数（默认 30 天，管理员可在系统设置调整）的回收站文件，
 * 删除前向用户邮箱发送清理清单；存在分享引用的文件跳过并保留。同时清理 24 小时以上的孤儿分片。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RecycleCleanupService {

    private final FileRepository fileRepository;
    private final ShareRepository shareRepository;
    private final UserRepository userRepository;
    private final SystemConfigRepository systemConfigRepository;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final FileService fileService;
    // IronWall v1.47.10: 存储提醒开关门控（此前开关无消费方）
    private final NotificationPreferenceService notificationPreferenceService;

    @Value("${app.storage.recycle-retention-days:30}")
    private int defaultRetentionDays;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    @Scheduled(cron = "${app.storage.recycle-cleanup-cron:0 10 4 * * *}")
    public void scheduledCleanup() {
        try {
            int files = cleanup();
            int chunks = fileService.cleanupOrphanChunks();
            log.info("[IronWall] recycle cleanup done: files={} orphan_chunk_dirs={}", files, chunks);
        } catch (Exception e) {
            log.error("[IronWall] recycle cleanup failed: {}", e.getMessage());
        }
    }

    /** @return 实际删除的文件数 */
    public int cleanup() {
        int retentionDays = retentionDays();
        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        List<FileEntity> expired = fileRepository.findByStatusAndUpdatedAtBefore(0, cutoff);
        if (expired.isEmpty()) {
            return 0;
        }

        Map<Long, List<FileEntity>> byUser = new LinkedHashMap<>();
        for (FileEntity file : expired) {
            if (shareRepository.existsByFileId(file.getId())) {
                log.info("[IronWall] recycle cleanup skip (share referenced): file={}", file.getId());
                continue;
            }
            byUser.computeIfAbsent(file.getUserId(), k -> new ArrayList<>()).add(file);
        }

        int deleted = 0;
        for (Map.Entry<Long, List<FileEntity>> entry : byUser.entrySet()) {
            Long userId = entry.getKey();
            List<FileEntity> files = entry.getValue();
            sendCleanupNotice(userId, files);
            for (FileEntity file : files) {
                try {
                    permanentDelete(userId, file);
                    deleted++;
                } catch (Exception e) {
                    log.warn("[IronWall] recycle cleanup delete failed: file={} err={}", file.getId(), e.getMessage());
                }
            }
        }
        return deleted;
    }

    private void sendCleanupNotice(Long userId, List<FileEntity> files) {
        try {
            User user = userRepository.findById(userId).orElse(null);
            if (user == null || user.getEmail() == null || user.getEmail().isBlank()) {
                return;
            }
            // IronWall v1.47.10: 尊重“存储提醒”分类开关（与邮箱总开关双开才发）
            if (!notificationPreferenceService.shouldEmailStorageAlert(userId)) {
                log.info("[IronWall] recycle cleanup mail skipped by preference: userId={}", userId);
                return;
            }
            long totalSize = 0;
            StringBuilder list = new StringBuilder();
            int shown = 0;
            for (FileEntity f : files) {
                totalSize += f.getFileSize() == null ? 0 : f.getFileSize();
                if (shown < 20) {
                    list.append("<tr><td style=\"padding:6px 10px;border-bottom:1px solid #f3f4f6;\">")
                        .append(escape(f.getOriginalName()))
                        .append("</td><td style=\"padding:6px 10px;border-bottom:1px solid #f3f4f6;text-align:right;\">")
                        .append(humanSize(f.getFileSize() == null ? 0 : f.getFileSize()))
                        .append("</td></tr>");
                    shown++;
                }
            }
            String subject = "【经典云网盘】回收站自动清理通知";
            String html = "<div style=\"font-family:'Microsoft YaHei',Arial,sans-serif;max-width:560px;margin:0 auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;\">"
                    + "<div style=\"background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:22px 26px;\"><div style=\"color:#fff;font-size:17px;font-weight:700;\">经典云网盘官方 · 存储管理</div></div>"
                    + "<div style=\"padding:22px 26px;color:#374151;font-size:14px;line-height:1.9;\">"
                    + "<p style=\"margin:0 0 14px;\">您的回收站中有 <b>" + files.size() + "</b> 个文件（共 " + humanSize(totalSize) + "）已超过 " + retentionDays() + " 天保留期，系统已自动彻底删除：</p>"
                    + "<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">" + list + "</table>"
                    + "<p style=\"margin:16px 0 0;color:#9ca3af;\">彻底删除后无法恢复，请定期检查回收站。</p>"
                    + "</div>"
                    + "<div style=\"padding:14px 26px;background:#f9fafb;color:#9ca3af;font-size:12px;\">本邮件由经典云网盘存储系统自动发送，请勿直接回复。</div></div>";
            emailService.sendHtml(user.getEmail(), subject, html,
                    "您的回收站有 " + files.size() + " 个文件已超过保留期并自动彻底删除。");
        } catch (Exception e) {
            log.warn("[IronWall] recycle cleanup notice failed: user={} err={}", userId, e.getMessage());
        }
    }

    private void permanentDelete(Long userId, FileEntity file) throws Exception {
        Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();
        fileRepository.delete(file);
        long refs = fileRepository.countByFilename(file.getFilename());
        if (refs <= 0) {
            Path filePath = uploadPath.resolve(file.getFilename()).normalize();
            if (filePath.startsWith(uploadPath)) {
                Files.deleteIfExists(filePath);
            }
        }
        auditLogService.logDeleteFile(userId, file.getOriginalName(), "system", true);
    }


    private int retentionDays() {
        try {
            SystemConfig config = systemConfigRepository.findByConfigKey("recycle_retention_days").orElse(null);
            if (config != null && config.getConfigValue() != null) {
                int v = Integer.parseInt(config.getConfigValue().trim());
                if (v >= 1 && v <= 365) return v;
            }
        } catch (Exception ignored) { }
        return defaultRetentionDays;
    }

    private String humanSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f MB", bytes / 1024.0 / 1024.0);
        return String.format("%.2f GB", bytes / 1024.0 / 1024.0 / 1024.0);
    }

    private String escape(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
