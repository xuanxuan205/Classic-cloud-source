package com.jdy.cloud.service;

import com.jdy.cloud.model.AuditLog;
import com.jdy.cloud.util.ClientIpUtils;
import com.jdy.cloud.repository.AuditLogRepository;
import com.jdy.cloud.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    private String resolveUsername(Long userId) {
        if (userId == null) return "system";
        return userRepository.findById(userId).map(u -> u.getUsername()).orElse("unknown-" + userId);
    }

    private String getClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                // IronWall v1.6: 审计日志同样使用统一真实 IP 解析，杜绝 XFF 首段伪造
                return ClientIpUtils.getClientIp(request);
            }
        } catch (Exception e) {
            // ignore
        }
        return "unknown";
    }

    @Async
    public void log(AuditLog entry) {
        try {
            auditLogRepository.save(entry);
        } catch (Exception e) {
            log.error("Failed to save audit log: {}", e.getMessage());
        }
    }

    public AuditLog build(String action, Long userId, String username, String ip, String device, String status) {
        AuditLog log = new AuditLog();
        log.setAction(action);
        log.setUserId(userId);
        log.setUsername(username);
        log.setIp(ip != null && !"system".equals(ip) ? ip : getClientIp());
        log.setDevice(device);
        log.setStatus(status != null ? status : "success");
        return log;
    }

    // Convenience methods for common actions
    public void logLogin(Long userId, String ip, String device, String status) {
        String username = resolveUsername(userId);
        AuditLog l = build("login", userId, username, ip, device, status);
        l.setTargetType("user");
        l.setTargetId(userId);
        l.setDetail(username + " " + ("success".equals(status) ? "登录成功" : "登录失败"));
        log(l);
    }

    public void logUpload(Long userId, String fileName, Long fileSize, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("upload", userId, username, ip, null, "success");
        l.setTargetType("file");
        l.setTargetName(fileName);
        l.setDetail(username + " 上传文件: " + fileName + " (" + formatSize(fileSize) + ")");
        log(l);
    }

    public void logDeleteFile(Long userId, String fileName, String ip, boolean permanent) {
        String username = resolveUsername(userId);
        AuditLog l = build(permanent ? "delete_permanent" : "delete_file", userId, username, ip, null, "success");
        l.setTargetType("file");
        l.setTargetName(fileName);
        l.setDetail(username + " " + (permanent ? "永久删除" : "删除") + "文件: " + fileName);
        log(l);
    }

    public void logRestoreFile(Long userId, String fileName, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("restore_file", userId, username, ip, null, "success");
        l.setTargetType("file");
        l.setTargetName(fileName);
        l.setDetail(username + " 恢复文件: " + fileName);
        log(l);
    }

    public void logCreateFolder(Long userId, String folderName, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("create_folder", userId, username, ip, null, "success");
        l.setTargetType("folder");
        l.setTargetName(folderName);
        l.setDetail(username + " 创建文件夹: " + folderName);
        log(l);
    }

    public void logDeleteFolder(Long userId, String folderName, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("delete_folder", userId, username, ip, null, "success");
        l.setTargetType("folder");
        l.setTargetName(folderName);
        l.setDetail(username + " 删除文件夹: " + folderName);
        log(l);
    }

    public void logCreateShare(Long userId, String shareCode, String fileName, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("create_share", userId, username, ip, null, "success");
        l.setTargetType("share");
        l.setTargetName(fileName);
        l.setDetail(username + " 创建分享: " + fileName + " (code: " + shareCode + ")");
        log(l);
    }

    public void logDeleteShare(Long userId, String shareCode, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("delete_share", userId, username, ip, null, "success");
        l.setTargetType("share");
        l.setTargetName(shareCode);
        l.setDetail(username + " 删除分享: " + shareCode);
        log(l);
    }

    public void logDownload(Long userId, String fileName, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("download", userId, username, ip, null, "success");
        l.setTargetType("file");
        l.setTargetName(fileName);
        l.setDetail(username + " 下载文件: " + fileName);
        log(l);
    }

    /**
     * IronWall v1.47.11: 公开分享下载审计（与站内 download 分离）。
     *
     * 旧实现复用 logDownload(分享者ID, ...)，把「事件发生在谁的分享上」当成了
     * 「谁执行了这个动作」：用户列显示分享者昵称、详情写「<分享者> 下载文件: xxx」，
     * 而 IP 列却是访客真实地址，三者自相矛盾，管理员会误判为分享者本人下载。
     *
     * 现在：
     * action 独立为 share_download，与站内 download 分属两种语义，可单独筛选统计；
     * 详情显式标注「访客通过公开分享下载」，并回填分享者与分享码前缀便于溯源；
     * userId / username 仍归属分享者，表示这条记录属于谁的分享；
     * ip 保持传 "system" 以触发 build() 回落到真实请求 IP —— 访客 IP 是其唯一身份线索，不可丢失。
     */
    public void logShareDownload(Long shareOwnerId, String shareCode, String fileName) {
        String ownerName = resolveUsername(shareOwnerId);
        AuditLog l = build("share_download", shareOwnerId, ownerName, "system", null, "success");
        l.setTargetType("share");
        l.setTargetName(fileName);
        l.setDetail("访客通过公开分享下载: " + fileName
                + "（分享者: " + ownerName + "，分享码: " + shortShareCode(shareCode) + "）");
        log(l);
    }

    /** 分享码是访问凭证，日志只保留前缀用于人工比对，完整值永不落库。 */
    private static String shortShareCode(String shareCode) {
        if (shareCode == null || shareCode.isEmpty()) return "-";
        return shareCode.length() <= 8 ? shareCode : shareCode.substring(0, 8) + "…";
    }

    public void logUpdateProfile(Long userId, String field, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("update_profile", userId, username, ip, null, "success");
        l.setTargetType("user");
        l.setTargetId(userId);
        l.setDetail(username + " 修改个人资料: " + field);
        log(l);
    }

    public void logChangePassword(Long userId, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("change_password", userId, username, ip, null, "success");
        l.setTargetType("user");
        l.setTargetId(userId);
        l.setDetail(username + " 修改了密码");
        log(l);
    }

    public void logUpdateSettings(Long adminId, String key, String ip) {
        String adminName = resolveUsername(adminId);
        AuditLog l = build("update_settings", adminId, adminName, ip, null, "success");
        l.setTargetType("settings");
        l.setTargetName(key);
        l.setDetail(adminName + " 修改系统设置: " + key);
        log(l);
    }

    public void logRegister(Long userId, String ip) {
        String username = resolveUsername(userId);
        AuditLog l = build("register", userId, username, ip, null, "success");
        l.setTargetType("user");
        l.setTargetId(userId);
        l.setDetail(username + " 注册了新账号");
        log(l);
    }

    public void logAdminAction(Long adminId, String action, String targetType, String targetName, String detail, String ip) {
        String adminName = resolveUsername(adminId);
        AuditLog l = build(action, adminId, adminName, ip, null, "success");
        l.setTargetType(targetType);
        l.setTargetName(targetName);
        l.setDetail(adminName + " " + detail);
        log(l);
    }

    // Query methods
    public Page<AuditLog> getLogs(String action, Long userId, String keyword, int page, int size) {
        if ((action == null || action.isEmpty() || "all".equals(action))
                && userId == null
                && (keyword == null || keyword.isEmpty())) {
            return auditLogRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size));
        }
        return auditLogRepository.searchLogs(
                (action == null || action.isEmpty() || "all".equals(action)) ? null : action,
                userId,
                (keyword == null || keyword.isEmpty()) ? null : keyword,
                PageRequest.of(page, size));
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1073741824) return String.format("%.1f MB", bytes / 1048576.0);
        return String.format("%.1f GB", bytes / 1073741824.0);
    }
}
