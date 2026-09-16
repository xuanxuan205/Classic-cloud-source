package com.jdy.cloud.service;

import com.jdy.cloud.dto.AnnouncementRequest;
import com.jdy.cloud.util.SecurityUtils;
import com.jdy.cloud.dto.UpdateUserRequest;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.*;
import com.jdy.cloud.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.util.Set;
import java.util.List;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdminService {

    // IronWall v1.11: 存储/角色/状态修改白名单（防越权篡改存储空间与身份）
    private static final Set<String> ALLOWED_ROLES = Set.of("user", "admin");
    private static final Set<String> ALLOWED_STATUSES = Set.of("active", "banned");
    private static final long MAX_STORAGE_LIMIT = 1099511627776L;
    // IronWall v1.45: 对外可见公告（置顶+已发布）合计 10 条封顶——第 11 条发布时自动淘汰最早的一条
    private static final int MAX_VISIBLE_ANNOUNCEMENTS = 10;

    private final UserRepository userRepository;
    private final FileRepository fileRepository;
    private final ShareRepository shareRepository;
    private final AnnouncementRepository announcementRepository;
    private final FolderRepository folderRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final com.jdy.cloud.security.TokenVersionService tokenVersionService;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    // IronWall v1.47.10: 通知开关门控（此前开关无消费方）
    private final NotificationPreferenceService notificationPreferenceService;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    public Map<String, Object> getDashboardStats() {
        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countByUserStatus("active");
        long totalFiles = fileRepository.countByStatusNot(-1);
        java.time.LocalDateTime todayStart = java.time.LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        long todayUploads = fileRepository.countByCreatedAtAfter(todayStart);
        long totalShares = shareRepository.count();
        long todayShares = shareRepository.countByCreatedAtAfter(todayStart);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalUsers", totalUsers);
        stats.put("activeUsers", activeUsers);
        stats.put("totalFiles", totalFiles);
        stats.put("todayUploads", todayUploads);
        stats.put("totalShares", totalShares);
        stats.put("todayShares", todayShares);

        // IronWall v1.47.4: 全站存储汇总（用户 used/limit 口径，与用户端仪表盘一致）
        long storageUsed = userRepository.sumStorageUsed();
        long storageTotal = userRepository.sumStorageLimit();
        long storageRemaining = Math.max(0L, storageTotal - storageUsed);
        stats.put("storageUsed", storageUsed);
        stats.put("storageTotal", storageTotal);
        stats.put("storageRemaining", storageRemaining);
        return stats;
    }

    // === User Management ===
    public Page<User> getUsers(int page, int size) {
        return getUsers(page, size, null);
    }

    /** IronWall v1.47.6: 管理端用户搜索（用户名/邮箱/靓号，空关键词回退全量）。 */
    public Page<User> getUsers(int page, int size, String keyword) {
        PageRequest pageable = PageRequest.of(page, size);
        String kw = keyword == null ? "" : keyword.trim();
        if (kw.isEmpty()) {
            return userRepository.findAll(pageable);
        }
        return userRepository.searchByKeyword(kw, pageable);
    }

    public java.util.List<User> getUnverifiedUsers() {
        return userRepository.findAll().stream()
                // IronWall v1.28.2: 认证状态为空也视为待认证，避免历史账号在认证列表“隐形”
                .filter(u -> !"verified".equalsIgnoreCase(u.getVerificationStatus()))
                .toList();
    }

    @Transactional
    public void verifyUser(Long userId) {
        verifyUserWithBadge(userId, "已认证");
    }

    @Transactional
    public void verifyUserWithBadge(Long userId, String badge) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        user.setVerificationStatus("verified");
        user.setVerificationBadge(badge);
        userRepository.save(user);
    }


    @Transactional
    public void unverifyUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        // IronWall v1.28.2: 官方管理员账号始终保留「官方认证」，不允许被取消
        if ("admin".equalsIgnoreCase(user.getRole())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "管理员账号为官方认证，不可取消");
        }
        user.setVerificationStatus("unverified");
        userRepository.save(user);
    }

    @Transactional
    public void updateUser(Long userId, UpdateUserRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        String oldRole = user.getRole();
        String oldStatus = user.getUserStatus();

        // IronWall v1.11: 管理端字段全量白名单校验，防止越权/异常数据篡改存储空间与角色状态
        if (request.getUsername() != null) {
            String username = request.getUsername().trim();
            if (!SecurityUtils.isSafeUsername(username)) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                        "用户名仅支持中英文、数字、下划线、短横线、点号和空格（2-30字符）");
            }
            user.setUsername(username);
        }
        if (request.getEmail() != null) {
            String email = request.getEmail().trim();
            if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "邮箱格式不正确");
            }
            userRepository.findByEmail(email).ifPresent(other -> {
                if (!other.getId().equals(userId)) {
                    throw new BusinessException(ErrorCode.EMAIL_EXISTS);
                }
            });
            user.setEmail(email);
        }
        if (request.getRole() != null) {
            if (!ALLOWED_ROLES.contains(request.getRole())) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "角色只能是 user 或 admin");
            }
            user.setRole(request.getRole());
        }
        if (request.getUserStatus() != null) {
            if (!ALLOWED_STATUSES.contains(request.getUserStatus())) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "状态只能是 active 或 banned");
            }
            user.setUserStatus(request.getUserStatus());
        }
        if (request.getStorageLimit() != null) {
            long limit = request.getStorageLimit();
            long used = user.getStorageUsed() == null ? 0L : user.getStorageUsed();
            if (limit < 0 || limit > MAX_STORAGE_LIMIT) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "存储空间必须在 0 ~ 1TB 之间");
            }
            if (limit < used) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "存储上限不能低于用户已用空间");
            }
            user.setStorageLimit(limit);
        }
        if (request.getUploadLimit() != null) {
            int limit = request.getUploadLimit();
            if (limit < 1 || limit > 100000) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "上传次数限制必须在 1 ~ 100000 之间");
            }
            user.setUploadLimit(limit);
        }

        userRepository.save(user);

        // IronWall v1.20: 角色或封禁状态变更立即吊销旧 JWT（防降级/封禁后旧令牌继续越权）
        boolean roleChanged = oldRole != null && !oldRole.equals(user.getRole());
        boolean statusChanged = oldStatus != null && !oldStatus.equals(user.getUserStatus());
        if (roleChanged || statusChanged) {
            tokenVersionService.bump(user.getId());
        }

        // IronWall v1.27.5: 封禁/解封状态变更通过邮件通知用户（发送失败不影响管理操作）
        if (statusChanged) {
            notifyUserStatusChange(user);
        }
    }

    /**
     * IronWall v1.27.5: 用户封禁/解封邮件通知。
     */
    private void notifyUserStatusChange(User user) {
        String email = user.getEmail();
        if (email == null || email.isBlank()) {
            return;
        }
        // IronWall v1.47.10: 尊重“邮箱通知”总开关——关闭后不再发送通知类邮件
        if (!notificationPreferenceService.emailNotifyEnabled(user.getId())) {
            log.info("[IronWall] account status mail skipped by preference: userId={}", user.getId());
            return;
        }
        try {
            if ("banned".equalsIgnoreCase(user.getUserStatus())) {
                emailService.sendHtml(email, "【经典云网盘】账号封禁通知",
                        buildBannedHtml(user.getUsername()), buildBannedText(user.getUsername()));
            } else if ("active".equalsIgnoreCase(user.getUserStatus())) {
                emailService.send(email, "【经典云网盘】账号解封通知", buildUnbannedText(user.getUsername()));
            }
        } catch (Exception e) {
            log.warn("[IronWall] 封禁/解封邮件通知发送失败: userId={}, err={}", user.getId(), e.getMessage());
        }
    }

    private String buildBannedText(String username) {
        return "尊敬的 " + (username == null ? "用户" : username) + "：\n\n"
                + "很遗憾地通知您，您的经典云网盘账号因违反《服务条款》或存在异常行为，已被暂停使用（封禁）。\n\n"
                + "封禁期间，您将无法登录和使用任何服务。\n"
                + "如果您认为这是一次误封，请通过以下方式联系官方管理员：\n"
                + contactTextBlock() + "\n"
                + "此邮件由系统自动发送，请勿直接回复。\n"
                + "© 2026 经典云网盘 Classic Cloud. All rights reserved.";
    }

    private String buildBannedHtml(String username) {
        String name = username == null ? "用户" : username;
        return "<div style=\"max-width:600px;margin:0 auto;padding:24px;font-family:'Microsoft YaHei',Arial,sans-serif;color:#333;\">"
                + "<div style=\"background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;padding:20px 24px;border-radius:12px 12px 0 0;\"><h2 style=\"margin:0;font-size:20px;\">经典云网盘官方</h2><p style=\"margin:6px 0 0;opacity:.9;font-size:14px;\">账号封禁通知</p></div>"
                + "<div style=\"border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px;padding:24px;line-height:1.8;font-size:14px;\">"
                + "<p>尊敬的 <b>" + name + "</b>：</p>"
                + "<p>很遗憾地通知您，您的经典云网盘账号因违反《服务条款》或存在异常行为，已被暂停使用（封禁）。</p>"
                + "<p>封禁期间，您将无法登录和使用任何服务。如果您认为这是一次误封，请通过以下方式联系官方管理员：</p>"
                + contactHtmlBlock()
                + "</div>"
                + "<p style=\"text-align:center;color:#9ca3af;font-size:12px;margin-top:16px;\">此邮件由系统自动发送，请勿直接回复。<br/>© 2026 经典云网盘 Classic Cloud. All rights reserved.</p>"
                + "</div>";
    }

    private String buildUnbannedText(String username) {
        return "尊敬的 " + (username == null ? "用户" : username) + "：\n\n"
                + "好消息！您的经典云网盘账号已完成审核并解除封禁，现已恢复正常使用。\n\n"
                + "请遵守《服务条款》相关规定，感谢您的理解与配合。\n\n"
                + "此邮件由系统自动发送，请勿直接回复。\n"
                + "© 2026 经典云网盘 Classic Cloud. All rights reserved.";
    }

    @Transactional
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        userRepository.deleteById(userId);
    }

    // === File Management ===
    public Page<FileEntity> getFiles(int page, int size) {
        return getFiles(page, size, null);
    }

    /** IronWall v1.47.6: 管理端文件搜索（文件名或归属用户，保持排除已删除）。 */
    public Page<FileEntity> getFiles(int page, int size, String keyword) {
        PageRequest pageable = PageRequest.of(page, size);
        String kw = keyword == null ? "" : keyword.trim();
        if (kw.isEmpty()) {
            // IronWall v1.47.0: 已永久删除(-1)的文件不再出现在管理列表（历史遗留 -1 行由清理任务消化）
            return fileRepository.findByStatusNot(-1, pageable);
        }
        java.util.List<Long> userIds = userRepository.findIdsByKeyword(kw);
        if (userIds == null || userIds.isEmpty()) {
            return fileRepository.findByOriginalNameContainingIgnoreCaseAndStatusNot(kw, -1, pageable);
        }
        return fileRepository.searchByKeywordOrUserIds(kw, userIds, pageable);
    }

    /**
     * IronWall v1.47.0: 文件状态白名单 1=正常 0=封禁 -1=永久删除。
     * -1 执行真实硬删除：删除单文件分享行 + 文件行 + 物理文件（去重引用计数）+ 回退配额 + 审计。
     */
    @Transactional
    public void updateFileStatus(Long fileId, int status) {
        if (status != -1 && status != 0 && status != 1) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "无效的文件状态");
        }
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        if (status == -1) {
            permanentDeleteFile(file);
            return;
        }
        file.setStatus(status);
        fileRepository.save(file);
        if (status == 0) {
            auditLogService.logAdminAction(0L, "file-ban", "file", String.valueOf(fileId), "管理员封禁文件", "system");
        }
    }

    /** 孤儿行清理：消化历史版本留下的 status=-1 文件（幂等，每小时一次）。 */
    @Scheduled(fixedDelay = 3_600_000L, initialDelay = 120_000L)
    @Transactional
    public void purgeLegacyDeletedFiles() {
        try {
            List<FileEntity> legacy = fileRepository.findByStatus(-1);
            if (legacy == null || legacy.isEmpty()) {
                return;
            }
            for (FileEntity file : legacy) {
                try {
                    permanentDeleteFile(file);
                } catch (Exception e) {
                    log.warn("[IronWall] purge legacy deleted file failed: file={} err={}", file.getId(), e.getMessage());
                }
            }
            log.warn("[IronWall] purged {} legacy admin-deleted files", legacy.size());
        } catch (Exception e) {
            log.warn("[IronWall] purge legacy deleted files scan failed: {}", e.getMessage());
        }
    }

    /** 永久删除：分享行 → 文件行 → 物理文件（引用计数去重） → 配额回退 → 审计。 */
    private void permanentDeleteFile(FileEntity file) {
        Long userId = file.getUserId();
        String storedName = file.getFilename();
        String originalName = file.getOriginalName();
        long size = file.getFileSize() == null ? 0L : file.getFileSize();

        // 1) 单文件分享同步删除（公开链接立即失效）；文件夹分享内该文件由状态过滤自动隐藏
        shareRepository.deleteByFileId(file.getId());
        // 2) 文件行
        fileRepository.delete(file);
        // 3) 物理文件：仅当无其他记录引用同一物理文件（秒传去重）时删除
        try {
            long refs = fileRepository.countByFilename(storedName);
            if (refs <= 0 && storedName != null && !storedName.isBlank()) {
                Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();
                Path filePath = uploadPath.resolve(storedName).normalize();
                if (filePath.startsWith(uploadPath)) {
                    Files.deleteIfExists(filePath);
                }
            }
        } catch (IOException e) {
            log.warn("[IronWall] admin delete physical file failed: file={} err={}", file.getId(), e.getMessage());
        }
        // 4) 配额即时回退（StorageReconciler 启动时兜底对齐）
        if (userId != null && size > 0) {
            userRepository.incrementStorageUsed(userId, -size);
        }
        // 5) 审计
        auditLogService.logDeleteFile(userId != null ? userId : 0L, originalName, "admin", true);
    }

    // === Share Management ===
    public Page<Share> getShares(int page, int size) {
        return getShares(page, size, null);
    }

    /** IronWall v1.47.6: 管理端分享搜索（分享码或归属用户，空关键词回退全量）。 */
    public Page<Share> getShares(int page, int size, String keyword) {
        PageRequest pageable = PageRequest.of(page, size);
        String kw = keyword == null ? "" : keyword.trim();
        if (kw.isEmpty()) {
            return shareRepository.findAll(pageable);
        }
        java.util.List<Long> userIds = userRepository.findIdsByKeyword(kw);
        if (userIds == null || userIds.isEmpty()) {
            return shareRepository.findByShareCodeContainingIgnoreCase(kw, pageable);
        }
        return shareRepository.findByShareCodeContainingIgnoreCaseOrUserIdIn(kw, userIds, pageable);
    }

    @Transactional
    public void updateShareStatus(Long shareId, int status) {
        // IronWall v1.27.6: 状态白名单 1=正常 0=失效 -1=删除 -2=封禁
        if (status < -2 || status > 1) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "无效的分享状态");
        }
        Share share = shareRepository.findById(shareId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SHARE_NOT_FOUND));
        int oldStatus = share.getStatus() != null ? share.getStatus() : 1;
        share.setStatus(status);
        shareRepository.save(share);

        // IronWall v1.27.6: 分享被违规封禁(-2)时邮件通知分享创建者（发送失败不影响管理操作）
        if (status == -2 && oldStatus != -2) {
            notifyShareBanned(share);
        }
    }

    /**
     * IronWall v1.27.6: 公开分享违规封禁邮件通知。
     */
    private void notifyShareBanned(Share share) {
        Long userId = share.getUserId();
        if (userId == null) {
            return;
        }
        // IronWall v1.47.10: 尊重“分享通知”分类开关（与邮箱总开关双开才发）
        if (!notificationPreferenceService.shouldEmailShareNotify(userId)) {
            log.info("[IronWall] share banned mail skipped by preference: userId={}", userId);
            return;
        }
        userRepository.findById(userId).ifPresent(user -> {
            String email = user.getEmail();
            if (email == null || email.isBlank()) {
                return;
            }
            try {
                emailService.sendHtml(email, "【经典云网盘】分享封禁通知",
                        buildShareBannedHtml(user.getUsername(), share),
                        buildShareBannedText(user.getUsername(), share));
            } catch (Exception e) {
                log.warn("[IronWall] 分享封禁邮件通知发送失败: shareId={}, err={}", share.getId(), e.getMessage());
            }
        });
    }

    /** 站点域名由配置提供（{@code app.site.domain}）。 */
    @Value("${app.site.domain:}")
    private String siteDomain;

    @Value("${app.site.base-url:}")
    private String siteBaseUrl;

    /** 对外联系方式由配置提供（{@code app.site.contact-email} / {@code app.site.contact-qq}）。 */
    @Value("${app.site.contact-email:}")
    private String contactEmail;

    @Value("${app.site.contact-qq:}")
    private String contactQq;

    /**
     * 站点根地址：优先取 app.site.base-url；未配置时由 app.site.domain 推导为 https 地址；
     * 两者皆空时返回空串（分享链接退化为相对路径，需部署者补齐配置）。
     */
    private String siteBaseUrl() {
        if (siteBaseUrl != null && !siteBaseUrl.isBlank()) {
            String trimmed = siteBaseUrl.trim();
            return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
        }
        if (siteDomain != null && !siteDomain.isBlank()) {
            return "https://" + siteDomain.trim();
        }
        return "";
    }

    /** 纯文本联系方式块；两项均未配置时返回空串。 */
    private String contactTextBlock() {
        StringBuilder sb = new StringBuilder();
        if (contactEmail != null && !contactEmail.isBlank()) {
            sb.append("官方邮箱：").append(contactEmail.trim()).append('\n');
        }
        if (contactQq != null && !contactQq.isBlank()) {
            sb.append("官方QQ：").append(contactQq.trim()).append('\n');
        }
        return sb.toString();
    }

    /** HTML 联系方式块；两项均未配置时返回空串。 */
    private String contactHtmlBlock() {
        StringBuilder sb = new StringBuilder();
        if (contactEmail != null && !contactEmail.isBlank()) {
            sb.append("官方邮箱：").append(contactEmail.trim());
        }
        if (contactQq != null && !contactQq.isBlank()) {
            if (sb.length() > 0) {
                sb.append("<br/>");
            }
            String qq = contactQq.trim();
            sb.append("官方QQ：<a href=\"").append(qq).append("\">").append(qq).append("</a>");
        }
        if (sb.length() == 0) {
            return "";
        }
        return "<p>" + sb + "</p>";
    }

    private String shareLink(Share share) {
        return siteBaseUrl() + "/share/" + (share.getShareCode() == null ? "" : share.getShareCode());
    }

    private String buildShareBannedText(String username, Share share) {
        return "尊敬的 " + (username == null ? "用户" : username) + "：\n\n"
                + "很遗憾地通知您，您创建的公开分享因包含违规内容，已被官方管理员封禁。\n\n"
                + "分享码：" + share.getShareCode() + "\n"
                + "分享链接：" + shareLink(share) + "\n\n"
                + "封禁期间，其他用户将无法访问该分享内容。\n"
                + "如果您认为这是一次误封，请通过以下方式联系官方管理员：\n"
                + contactTextBlock() + "\n"
                + "请自觉遵守《服务条款》相关规定，感谢您的理解与配合。\n\n"
                + "此邮件由系统自动发送，请勿直接回复。\n"
                + "© 2026 经典云网盘 Classic Cloud. All rights reserved.";
    }

    private String buildShareBannedHtml(String username, Share share) {
        String name = username == null ? "用户" : username;
        return "<div style=\"max-width:600px;margin:0 auto;padding:24px;font-family:'Microsoft YaHei',Arial,sans-serif;color:#333;\">"
                + "<div style=\"background:linear-gradient(135deg,#ef4444,#f97316);color:#fff;padding:20px 24px;border-radius:12px 12px 0 0;\"><h2 style=\"margin:0;font-size:20px;\">经典云网盘官方</h2><p style=\"margin:6px 0 0;opacity:.9;font-size:14px;\">分享封禁通知</p></div>"
                + "<div style=\"border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px;padding:24px;line-height:1.8;font-size:14px;\">"
                + "<p>尊敬的 <b>" + name + "</b>：</p>"
                + "<p>很遗憾地通知您，您创建的公开分享因包含违规内容，已被官方管理员封禁。</p>"
                + "<table style=\"width:100%;background:#f8fafc;border-radius:8px;padding:12px 16px;font-size:13px;\">"
                + "<tr><td style=\"padding:6px 0;color:#64748b;width:80px;\">分享码</td><td style=\"padding:6px 0;color:#0f172a;font-weight:600;\">" + share.getShareCode() + "</td></tr>"
                + "<tr><td style=\"padding:6px 0;color:#64748b;\">分享链接</td><td style=\"padding:6px 0;color:#2563eb;word-break:break-all;\">" + shareLink(share) + "</td></tr>"
                + "</table>"
                + "<p>封禁期间，其他用户将无法访问该分享内容。如果您认为这是一次误封，请通过以下方式联系官方管理员：</p>"
                + contactHtmlBlock()
                + "<p>请自觉遵守《服务条款》相关规定，感谢您的理解与配合。</p>"
                + "</div>"
                + "<p style=\"text-align:center;color:#9ca3af;font-size:12px;margin-top:16px;\">此邮件由系统自动发送，请勿直接回复。<br/>© 2026 经典云网盘 Classic Cloud. All rights reserved.</p>"
                + "</div>";
    }

    // === Announcements ===
    public Page<Announcement> getAnnouncements(int page, int size) {
        return announcementRepository.findAll(PageRequest.of(page, size));
    }

    @Transactional
    public Announcement createAnnouncement(Long adminId, AnnouncementRequest request) {
        String title = SecurityUtils.stripHtmlTags(request.getTitle());
        String content = SecurityUtils.stripHtmlTags(request.getContent());
        if (title == null || title.isEmpty() || title.length() > 100) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "公告标题无效（长度1-100）");
        }
        if (content == null || content.isEmpty() || content.length() > 5000) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "公告内容无效（长度1-5000）");
        }
        Announcement ann = new Announcement();
        ann.setTitle(title);
        ann.setContent(content);
        ann.setStatus(normalizeStatus(request.getStatus()));
        ann.setCreatedBy(adminId);
        if ("scheduled".equals(ann.getStatus())) {
            ann.setUpdatedAt(parsePublishAt(request.getPublishAt()));
        }
        Announcement saved = announcementRepository.save(ann);
        capIfVisible(saved);
        return saved;
    }

    @Transactional
    public Announcement updateAnnouncement(Long id, AnnouncementRequest request) {
        Announcement ann = announcementRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
        String title = SecurityUtils.stripHtmlTags(request.getTitle());
        String content = SecurityUtils.stripHtmlTags(request.getContent());
        if (title == null || title.isEmpty() || title.length() > 100) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "公告标题无效（长度1-100）");
        }
        if (content == null || content.isEmpty() || content.length() > 5000) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "公告内容无效（长度1-5000）");
        }
        ann.setTitle(title);
        ann.setContent(content);
        if (request.getStatus() != null) ann.setStatus(normalizeStatus(request.getStatus()));
        if ("scheduled".equals(ann.getStatus())) {
            ann.setUpdatedAt(parsePublishAt(request.getPublishAt()));
        }
        Announcement saved = announcementRepository.save(ann);
        capIfVisible(saved);
        return saved;
    }

    public void deleteAnnouncement(Long id) {
        if (!announcementRepository.existsById(id)) {
            throw new BusinessException(ErrorCode.NOT_FOUND);
        }
        announcementRepository.deleteById(id);
    }

    /**
     * 对外可见公告（置顶+已发布）只保留最新 10 条（created_at 降序，由仓储查询保证），超出的物理删除。
     * 草稿与定时公告不参与封顶。
     */
    private void capPublishedAnnouncements() {
        java.util.List<Announcement> visible = announcementRepository
                .findByStatusInOrderByCreatedAtDesc(java.util.List.of("pinned", "published"));
        if (visible.size() <= MAX_VISIBLE_ANNOUNCEMENTS) {
            return;
        }
        for (int i = MAX_VISIBLE_ANNOUNCEMENTS; i < visible.size(); i++) {
            announcementRepository.delete(visible.get(i));
        }
    }

    private void capIfVisible(Announcement saved) {
        if ("published".equals(saved.getStatus()) || "pinned".equals(saved.getStatus())) {
            capPublishedAnnouncements();
        }
    }

    private String normalizeStatus(String status) {
        String s = status == null || status.trim().isEmpty() ? "published" : status.trim();
        if (!Set.of("published", "pinned", "scheduled", "draft").contains(s)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "公告状态无效");
        }
        return s;
    }

    private java.time.LocalDateTime parsePublishAt(String publishAt) {
        if (publishAt == null || publishAt.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "定时发布必须填写发布时间");
        }
        java.time.LocalDateTime t;
        try {
            t = java.time.LocalDateTime.parse(publishAt.trim());
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "定时发布时间格式不正确");
        }
        if (!t.isAfter(java.time.LocalDateTime.now())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "定时发布时间必须晚于当前时间");
        }
        return t;
    }

    /**
     * 定时发布扫描：每 30 秒将到期的 scheduled 公告转为 published（到达发布时刻自动上线）。
     */
    @Scheduled(fixedDelay = 30_000L)
    @Transactional
    public void publishDueAnnouncements() {
        java.util.List<Announcement> scheduled = announcementRepository.findByStatus("scheduled");
        if (scheduled == null || scheduled.isEmpty()) {
            return;
        }
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        boolean anyPublished = false;
        for (Announcement a : scheduled) {
            if (a.getUpdatedAt() != null && !a.getUpdatedAt().isAfter(now)) {
                a.setStatus("published");
                a.setUpdatedAt(now);
                announcementRepository.save(a);
                anyPublished = true;
            }
        }
        if (anyPublished) {
            capPublishedAnnouncements();
        }
    }

    // === Download Stats ===
    public Map<String, Object> getDownloadStats() {
        return Map.of("totalDownloads", fileRepository.sumDownloadCount());
    }

    // === Logs ===
    public Page<LoginHistory> getLogs(String level, int page, int size) {
        if (level != null && !level.isEmpty()) {
            return loginHistoryRepository.findByStatus(level, PageRequest.of(page, size));
        }
        return loginHistoryRepository.findAllByOrderByTimeDesc(PageRequest.of(page, size));
    }
}
