package com.jdy.cloud.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.security.AttackGuardService;
import com.jdy.cloud.security.TrapService;
import com.jdy.cloud.util.SecurityUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * IronWall v1.26.1: 封禁申诉中心。
 * 提交申诉：持久化到 JSON 文件，并发送管理员通知与申诉回执。
 * 管理员处理：查询申诉，标记已处理/已驳回，并向申诉人发送结果邮件。
 */
@Slf4j
@Service
public class AppealCenterService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}$");
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final long NOTIFY_INTERVAL_MS = 10 * 60 * 1000L;

    private final EmailService emailService;
    private final ObjectMapper objectMapper;
    private final AttackGuardService attackGuardService;
    private final TrapService trapService;
    private final Path storePath;
    private final Map<String, Long> notifiedAt = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAcceptedAt = new ConcurrentHashMap<>();
    private final Object submitLock = new Object();

    @Value("${app.admin.email:}")
    private String adminEmail;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    // IronWall v1.27.8: 申诉通过后是否联动 fail2ban 立即解封
    @Value("${app.security.defense-engine.appeal-fail2ban-unban:true}")
    private boolean fail2banUnbanEnabled;

    // IronWall v1.26.1: 申诉端点限流（每 IP 限频窗口 + 每 IP 待审上限）
    // IronWall v1.28.9: 默认窗口由 1 小时收紧为 60 秒，正常误封用户可及时重复申诉
    @Value("${app.security.defense-engine.blocked-page.appeal-min-interval-ms:60000}")
    private long appealMinIntervalMs;

    @Value("${app.security.defense-engine.blocked-page.appeal-max-pending-per-ip:3}")
    private int appealMaxPendingPerIp;

    public AppealCenterService(EmailService emailService,
                               ObjectMapper objectMapper,
                               AttackGuardService attackGuardService,
                               TrapService trapService,
                               @Value("${app.security.defense-engine.blocked-page.appeal-store:./logs/blocked-appeals.json}") String storePath) {
        this.emailService = emailService;
        this.objectMapper = objectMapper;
        this.attackGuardService = attackGuardService;
        this.trapService = trapService;
        this.storePath = Paths.get(storePath).toAbsolutePath().normalize();
    }

    /**
     * IronWall v1.26.1: 受限申诉提交。
     * TOO_FREQUENT: 同一 IP 在限频窗口内重复提交
     * TOO_MANY_PENDING: 同一 IP 已有超过允许数量的待处理申诉
     * ACCEPTED: 记录成功
     */
    public AppealSubmitResult submit(String ip, String contact, String reason) {
        AppealRecord record = null;
        String code;
        synchronized (submitLock) {
            List<AppealRecord> records = load();
            long pendingForIp = records.stream()
                    .filter(r -> "PENDING".equals(r.status) && ip != null && ip.equals(r.ip))
                    .count();
            int maxPending = appealMaxPendingPerIp > 0 ? appealMaxPendingPerIp : 3;
            if (pendingForIp >= maxPending) {
                return new AppealSubmitResult(null, "TOO_MANY_PENDING");
            }
            long now = System.currentTimeMillis();
            Long last = lastAcceptedAt.get(ip);
            long interval = appealMinIntervalMs > 0 ? appealMinIntervalMs : 60_000L;
            if (last != null && now - last < interval) {
                return new AppealSubmitResult(null, "TOO_FREQUENT");
            }
            record = new AppealRecord();
            record.id = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            record.ip = ip;
            record.contact = safe(contact, 64);
            record.reason = safe(reason, 240);
            record.status = "PENDING";
            record.createdAt = nowText();
            records.add(0, record);
            save(records);
            lastAcceptedAt.put(ip, now);
            if (lastAcceptedAt.size() > 10000) {
                lastAcceptedAt.clear();
            }
            code = "ACCEPTED";
        }
        if ("ACCEPTED".equals(code) && shouldNotify(ip)) {
            sendAdminEmail(record);
            sendReceiptEmail(record);
        }
        return new AppealSubmitResult(record, code);
    }

    /** 兼容旧调用：受限返回时 record 为 null。 */
    public AppealRecord recordAndNotify(String ip, String contact, String reason) {
        return submit(ip, contact, reason).record;
    }

    public List<AppealRecord> list() {
        return load();
    }

    /**
     * @param decision processed / rejected
     */
    public AppealRecord resolve(String id, String decision, String note) {
        String normalized = decision == null ? "" : decision.trim().toLowerCase();
        if (!"processed".equals(normalized) && !"rejected".equals(normalized)) {
            return null;
        }
        String status = "processed".equals(normalized) ? "PROCESSED" : "REJECTED";
        AppealRecord target = null;
        List<AppealRecord> records = load();
        for (AppealRecord record : records) {
            if (record.id != null && record.id.equals(id) && "PENDING".equals(record.status)) {
                record.status = status;
                record.resolutionNote = safe(note, 240);
                record.resolvedAt = nowText();
                target = record;
                break;
            }
        }
        if (target != null) {
            save(records);
            boolean notified = sendDecisionEmail(target, status);
            target.notified = notified;
            target.notificationNote = notified
                    ? "处理结果已发送至申诉人邮箱"
                    : (isEmail(target.contact) ? "邮件发送失败，请检查邮件服务配置" : "申诉人未提供有效邮箱，无法发送结果通知");
            // IronWall v1.27.8: 申诉通过（processed）立即解除站内封禁/陷阱，并联动 fail2ban 解封
            if ("processed".equals(normalized)) {
                target.unbanNote = releaseBlockedIp(target);
            }
            save(records);
        }
        return target;
    }

    /**
     * IronWall v1.27.8: 申诉通过后立即解封：
     * 站内封禁 + 陷阱吞没 + 命中网段 + fail2ban（ironwall / ironwall-portscan）联动。
     */
    private String releaseBlockedIp(AppealRecord record) {
        String ip = record.ip;
        if (ip == null || ip.isBlank()) {
            return "申诉记录缺少来源 IP，未执行解封";
        }
        StringBuilder note = new StringBuilder();
        try {
            attackGuardService.unblock(ip);
            trapService.release(ip);
            String segment = matchingSegment(ip);
            if (segment != null) {
                attackGuardService.unblockSegment(segment);
                note.append("已立即解除该 IP 站内封禁与网段 ").append(segment).append(" 封禁");
            } else {
                note.append("已立即解除该 IP 站内封禁");
            }
            log.info("[IronWall] appeal approved, bans released: ip={}", ip);
        } catch (Exception e) {
            log.warn("[IronWall] appeal station-side unban failed: ip={} err={}", ip, e.getMessage());
            note.append("站内解封异常：").append(e.getMessage());
        }
        String f2b = runFail2banUnban(ip);
        if (f2b != null && !f2b.isBlank()) {
            note.append("；").append(f2b);
        }
        return note.toString();
    }

    private String matchingSegment(String ip) {
        for (AttackGuardService.SegmentInfo seg : attackGuardService.getBlockedSegments()) {
            if (seg.segment != null && seg.segment.contains("/")) {
                String prefix = seg.segment.substring(0, seg.segment.indexOf('/'));
                int lastDot = prefix.lastIndexOf('.');
                if (lastDot > 0 && ip.startsWith(prefix.substring(0, lastDot) + ".")) {
                    return seg.segment;
                }
            }
        }
        return null;
    }

    private String runFail2banUnban(String ip) {
        if (!fail2banUnbanEnabled || !isIpv4(ip)) {
            return null;
        }
        String[] jails = {"ironwall", "ironwall-portscan"};
        int ok = 0;
        for (String jail : jails) {
            try {
                ProcessBuilder pb = new ProcessBuilder("fail2ban-client", "set", jail, "unbanip", ip);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                try (java.io.InputStream in = p.getInputStream()) {
                    byte[] buf = new byte[1024];
                    while (in.read(buf) != -1) {
                        // 排空输出，防止阻塞
                    }
                }
                if (!p.waitFor(8, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    log.warn("[IronWall] appeal fail2ban unban timeout: jail={} ip={}", jail, ip);
                    continue;
                }
                int code = p.exitValue();
                log.info("[IronWall] appeal fail2ban unban: jail={} ip={} exit={}", jail, ip, code);
                if (code == 0) {
                    ok++;
                }
            } catch (Exception e) {
                log.warn("[IronWall] appeal fail2ban unban failed: jail={} ip={} err={}", jail, ip, e.getMessage());
            }
        }
        return ok > 0
                ? "fail2ban 联动解封已执行"
                : "fail2ban 未安装或联动失败，可手动执行 fail2ban-client set ironwall unbanip " + ip;
    }

    private boolean isIpv4(String ip) {
        if (ip == null) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int v = Integer.parseInt(part);
                if (v < 0 || v > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private AppealRecord record(String ip, String contact, String reason) {
        AppealRecord record = new AppealRecord();
        record.id = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        record.ip = ip;
        record.contact = safe(contact, 64);
        record.reason = safe(reason, 240);
        record.status = "PENDING";
        record.createdAt = nowText();

        List<AppealRecord> records = load();
        records.add(0, record);
        save(records);
        return record;
    }

    private boolean shouldNotify(String ip) {
        long now = System.currentTimeMillis();
        Long last = notifiedAt.putIfAbsent(ip, now);
        if (last == null) {
            return true;
        }
        if (now - last < NOTIFY_INTERVAL_MS) {
            return false;
        }
        return notifiedAt.replace(ip, last, now);
    }

    private void sendAdminEmail(AppealRecord record) {
        String recipients = adminEmail == null ? "" : adminEmail.trim();
        if (recipients.isEmpty()) {
            recipients = mailUsername == null ? "" : mailUsername.trim();
        }
        if (recipients.isEmpty()) {
            log.warn("[IronWall] appeal email skipped: no recipient configured (app.admin.email / spring.mail.username)");
            return;
        }
        try {
            String subject = "[IronWall] 封禁申诉 - IP " + record.ip;
            String text = "收到一条封禁申诉，请人工复核。";
            for (String to : recipients.split(",")) {
                if (to != null && !to.isBlank()) {
                    emailService.sendHtml(to.trim(), subject, buildAdminHtml(record), text);
                }
            }
            log.info("[IronWall] appeal admin email sent: id={} ip={} recipients={}", record.id, record.ip, recipients);
        } catch (Exception e) {
            log.error("[IronWall] appeal admin email send failed: id={} error={}", record.id, e.getMessage());
        }
    }

    private void sendReceiptEmail(AppealRecord record) {
        if (!isEmail(record.contact)) {
            return;
        }
        try {
            String subject = "[IronWall] 您的申诉已收到";
            String text = "您的封禁申诉已提交，我们将尽快人工复核。";
            emailService.sendHtml(record.contact.trim(), subject, buildReceiptHtml(record), text);
            log.info("[IronWall] appeal receipt sent: id={} ip={}", record.id, record.ip);
        } catch (Exception e) {
            log.warn("[IronWall] appeal receipt send failed: id={} error={}", record.id, e.getMessage());
        }
    }

    private boolean sendDecisionEmail(AppealRecord record, String status) {
        if (!isEmail(record.contact)) {
            return false;
        }
        String decisionText = "PROCESSED".equals(status) ? "已处理" : "已驳回";
        String text = "您的封禁申诉已有处理结果：" + decisionText + "。";
        try {
            emailService.sendHtml(record.contact.trim(),
                    "[IronWall] 申诉处理结果 - " + decisionText,
                    buildDecisionHtml(record, decisionText),
                    text);
            log.info("[IronWall] appeal decision email sent: id={} ip={} contact={} status={}",
                    record.id, record.ip, record.contact, status);
            return true;
        } catch (Exception e) {
            log.warn("[IronWall] appeal decision email send failed: id={} error={}", record.id, e.getMessage());
            return false;
        }
    }

    private String buildAdminHtml(AppealRecord record) {
        String contact = record.contact == null || record.contact.isBlank() ? "（未填写）" : record.contact;
        String reason = record.reason == null || record.reason.isBlank() ? "（未填写）" : record.reason;
        return htmlShell("#4f46e5", "IronWall 封禁申诉",
                "<p>收到一条封禁申诉，请人工复核。</p>"
                + "<p>申诉编号：" + escapeHtml(record.id) + "</p>"
                + "<p>来源 IP：" + escapeHtml(record.ip) + "</p>"
                + "<p>提交时间：" + escapeHtml(record.createdAt) + "</p>"
                + "<p>联系方式：" + escapeHtml(contact) + "</p>"
                + "<p>申诉说明：" + escapeHtml(reason) + "</p>");
    }

    private String buildReceiptHtml(AppealRecord record) {
        String contact = record.contact == null || record.contact.isBlank() ? "（未填写）" : record.contact;
        return htmlShell("#16a34a", "IronWall 申诉回执",
                "<p>您的封禁申诉已提交，我们将尽快人工复核。</p>"
                + "<p>申诉编号：" + escapeHtml(record.id) + "</p>"
                + "<p>来源 IP：" + escapeHtml(record.ip) + "</p>"
                + "<p>提交时间：" + escapeHtml(record.createdAt) + "</p>"
                + "<p>联系方式：" + escapeHtml(contact) + "</p>");
    }

    private String buildDecisionHtml(AppealRecord record, String decisionText) {
        String resolution = record.resolutionNote == null || record.resolutionNote.isBlank()
                ? "（管理员未填写备注）"
                : record.resolutionNote;
        String unbanLine = "PROCESSED".equals(record.status)
                ? "<p>该来源的访问限制已立即解除，请刷新页面后重试。</p>"
                : "";
        return htmlShell("#7c3aed", "IronWall 申诉处理结果",
                "<p>您的封禁申诉已有处理结果：<strong>" + escapeHtml(decisionText) + "</strong></p>"
                + "<p>申诉编号：" + escapeHtml(record.id) + "</p>"
                + "<p>来源 IP：" + escapeHtml(record.ip) + "</p>"
                + "<p>处理备注：" + escapeHtml(resolution) + "</p>"
                + unbanLine);
    }

    private String htmlShell(String color, String title, String body) {
        return "<div style=\"font-family:Arial,'Microsoft YaHei',sans-serif;max-width:560px;margin:0 auto;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;\">"
                + "<div style=\"background:" + color + ";padding:18px 24px;color:#ffffff;font-size:18px;font-weight:700;\">" + escapeHtml(title) + "</div>"
                + "<div style=\"padding:24px;color:#374151;font-size:14px;line-height:1.7;\">" + body + "</div>"
                + "<div style=\"padding:12px 24px;background:#f9fafb;color:#9ca3af;font-size:12px;\">请勿直接回复本邮件。</div>"
                + "</div>";
    }

    private List<AppealRecord> load() {
        if (!Files.exists(storePath)) {
            return new ArrayList<>();
        }
        try {
            List<AppealRecord> records = objectMapper.readValue(Files.readAllBytes(storePath), new TypeReference<List<AppealRecord>>() {});
            return records == null ? new ArrayList<>() : records;
        } catch (IOException e) {
            log.error("[IronWall] appeal store read failed: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private void save(List<AppealRecord> records) {
        try {
            Path parent = storePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = storePath.resolveSibling(storePath.getFileName() + ".tmp");
            Files.write(tmp, objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(records));
            try {
                Files.move(tmp, storePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, storePath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            log.error("[IronWall] appeal store write failed: {}", e.getMessage());
        }
    }

    private boolean isEmail(String value) {
        return value != null && EMAIL_PATTERN.matcher(value.trim()).matches();
    }

    private String safe(String value, int max) {
        if (value == null) {
            return "";
        }
        // IronWall v1.28.9: 输入层剥离 HTML 标签与控制字符，杜绝申诉字段存储型 XSS
        String v = SecurityUtils.stripHtmlTags(value.trim()).replaceAll("[\\x00-\\x1f\\x7f]", "");
        return v.length() > max ? v.substring(0, max) : v;
    }

    private String nowText() {
        return LocalDateTime.now(ZoneId.of("Asia/Shanghai")).format(TIME_FORMAT);
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    public static class AppealSubmitResult {
        public final AppealRecord record;
        public final String code;

        public AppealSubmitResult(AppealRecord record, String code) {
            this.record = record;
            this.code = code;
        }
    }

    public static class AppealRecord {
        public String id;
        public String ip;
        public String contact;
        public String reason;
        public String status;
        public String createdAt;
        public String resolvedAt;
        public String resolutionNote;
        // IronWall v1.26.1: 处理结果是否成功邮件通知申诉人（无邮箱/发送失败时为 false）
        public Boolean notified;
        public String notificationNote;
        // IronWall v1.27.8: 申诉通过后立即解封的执行结果说明
        public String unbanNote;
    }
}
