package com.jdy.cloud.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.27.0: 用户意见反馈。
 * 反馈不走封禁申诉队列：记录落盘到 JSON 文件留档，同时直接发送邮件给官方管理员邮箱
 * （app.admin.email，未配置时回退 spring.mail.username）。每 IP 默认 10 分钟限频。
 */
@Slf4j
@Service
public class FeedbackService {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final EmailService emailService;
    private final ObjectMapper objectMapper;
    private final Path storePath;
    private final boolean enabled;
    private final long minIntervalMs;
    private final String adminEmail;
    private final String mailUsername;
    private final Map<String, Long> lastSubmitAt = new ConcurrentHashMap<>();
    private final Object submitLock = new Object();

    public FeedbackService(EmailService emailService,
                           ObjectMapper objectMapper,
                           @Value("${app.feedback.store:./logs/feedback-records.json}") String storePath,
                           @Value("${app.feedback.enabled:true}") boolean enabled,
                           @Value("${app.feedback.min-interval-ms:600000}") long minIntervalMs,
                           @Value("${app.admin.email:}") String adminEmail,
                           @Value("${spring.mail.username:}") String mailUsername) {
        this.emailService = emailService;
        this.objectMapper = objectMapper;
        this.storePath = Paths.get(storePath).toAbsolutePath().normalize();
        this.enabled = enabled;
        this.minIntervalMs = minIntervalMs;
        this.adminEmail = adminEmail;
        this.mailUsername = mailUsername;
    }

    public static class FeedbackRecord {
        public String id;
        public String ip;
        public String contact;
        public String content;
        public String createdAt;
        public String status;
        public String notifiedAt;
    }

    /** 返回 OK / INVALID / TOO_FREQUENT / DISABLED。 */
    public String submit(String ip, String contact, String content) {
        if (!enabled) {
            return "DISABLED";
        }
        String safeContact = safe(contact, 64);
        String safeContent = safe(content, 1000);
        if (safeContent.trim().length() < 5) {
            return "INVALID";
        }
        long now = System.currentTimeMillis();
        Long last = lastSubmitAt.putIfAbsent(ip, now);
        if (last != null && now - last < Math.max(1000L, minIntervalMs)) {
            return "TOO_FREQUENT";
        }
        lastSubmitAt.put(ip, now);

        FeedbackRecord record = new FeedbackRecord();
        record.id = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        record.ip = ip == null ? "" : ip;
        record.contact = safeContact;
        record.content = safeContent;
        record.createdAt = TIME.format(LocalDateTime.now());
        record.status = "RECEIVED";
        synchronized (submitLock) {
            List<FeedbackRecord> records = load();
            records.add(0, record);
            save(records);
        }
        sendAdminEmail(record);
        return "OK";
    }

    private void sendAdminEmail(FeedbackRecord record) {
        String recipients = adminEmail == null ? "" : adminEmail.trim();
        if (recipients.isEmpty()) {
            recipients = mailUsername == null ? "" : mailUsername.trim();
        }
        if (recipients.isEmpty()) {
            log.warn("[IronWall] feedback email skipped: no recipient configured (app.admin.email / spring.mail.username)");
            return;
        }
        String subject = "【经典云网盘官方】新的用户意见反馈（编号 " + record.id + "）";
        String textFallback = "收到一条用户意见反馈。\n"
                + "编号：" + record.id + "\n"
                + "时间：" + record.createdAt + "\n"
                + "来源 IP：" + (record.ip.isEmpty() ? "-" : record.ip) + "\n"
                + "联系方式：" + (record.contact.isEmpty() ? "未提供" : record.contact) + "\n\n"
                + "反馈内容：\n" + record.content;
        String html = buildFeedbackHtml(record);
        try {
            for (String to : recipients.split(",")) {
                if (to != null && !to.isBlank()) {
                    emailService.sendHtml(to.trim(), subject, html, textFallback);
                }
            }
            record.notifiedAt = TIME.format(LocalDateTime.now());
            record.status = "NOTIFIED";
            synchronized (submitLock) {
                List<FeedbackRecord> records = load();
                for (FeedbackRecord r : records) {
                    if (record.id.equals(r.id)) {
                        r.status = record.status;
                        r.notifiedAt = record.notifiedAt;
                    }
                }
                save(records);
            }
            log.info("[IronWall] feedback email sent: id={} ip={}", record.id, record.ip);
        } catch (Exception e) {
            log.error("[IronWall] feedback email send failed: id={} error={}", record.id, e.getMessage());
        }
    }

    private String buildFeedbackHtml(FeedbackRecord record) {
        String contact = record.contact.isEmpty() ? "未提供" : escapeHtml(record.contact);
        String ip = record.ip.isEmpty() ? "-" : escapeHtml(record.ip);
        String content = escapeHtml(record.content).replace("\n", "<br/>");
        return "<div style=\"margin:0;padding:0;background:#eef2f9;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#eef2f9;padding:28px 12px;\">"
                + "<tr><td align=\"center\">"
                + "<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:600px;width:100%;border-radius:16px;overflow:hidden;box-shadow:0 8px 24px rgba(37,99,235,0.12);\">"
                + "<tr><td style=\"background:linear-gradient(120deg,#6366f1,#2563eb);padding:28px 32px;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>"
                + "<td style=\"width:48px;\"><div style=\"width:44px;height:44px;background:rgba(255,255,255,0.18);border:1px solid rgba(255,255,255,0.4);border-radius:12px;text-align:center;line-height:44px;font-size:22px;color:#ffffff;font-weight:700;\">云</div></td>"
                + "<td style=\"padding-left:14px;\"><p style=\"margin:0;color:#ffffff;font-size:18px;font-weight:700;letter-spacing:1px;\">经典云网盘官方</p><p style=\"margin:6px 0 0;color:#dbe4ff;font-size:13px;\">用户意见反馈通知</p></td>"
                + "<td align=\"right\" valign=\"top\"><span style=\"display:inline-block;background:rgba(255,255,255,0.16);border:1px solid rgba(255,255,255,0.35);color:#ffffff;font-size:12px;padding:5px 14px;border-radius:999px;\">新反馈</span></td>"
                + "</tr></table></td></tr>"
                + "<tr><td style=\"background:#ffffff;padding:26px 32px 6px;\">"
                + infoRow("编号", escapeHtml(record.id))
                + infoRow("时间", escapeHtml(record.createdAt))
                + infoRow("来源 IP", ip)
                + infoRow("联系方式", contact)
                + "<div style=\"margin-top:14px;background:#f5f7ff;border:1px solid #e3e8ff;border-left:4px solid #6366f1;border-radius:10px;padding:16px 18px;\">"
                + "<p style=\"margin:0 0 8px;color:#6366f1;font-size:13px;font-weight:700;\">反馈内容</p>"
                + "<p style=\"margin:0;color:#334155;font-size:14px;line-height:1.8;word-break:break-word;\">" + content + "</p>"
                + "</div>"
                + "<p style=\"margin:14px 0 0;color:#8a94a6;font-size:12px;\">可在管理后台查看完整反馈记录。</p>"
                + "</td></tr>"
                + "<tr><td style=\"background:#f8fafc;border-top:1px solid #eef2f7;padding:16px 32px;text-align:center;\">"
                + "<p style=\"margin:0;color:#9aa5b1;font-size:11px;line-height:1.7;\">本邮件由经典云网盘意见反馈系统自动发送<br/>请勿直接回复此邮件</p>"
                + "</td></tr>"
                + "</table>"
                + "</td></tr></table>"
                + "</div>";
    }

    private String infoRow(String label, String value) {
        return "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>"
                + "<td style=\"padding:7px 0;width:96px;color:#8a94a6;font-size:13px;\">" + label + "</td>"
                + "<td style=\"padding:7px 0;color:#1f2937;font-size:14px;font-weight:500;word-break:break-all;\">" + value + "</td>"
                + "</tr></table>";
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private List<FeedbackRecord> load() {
        try {
            if (Files.isRegularFile(storePath)) {
                List<FeedbackRecord> list = objectMapper.readValue(Files.readAllBytes(storePath), new TypeReference<>() {});
                return list == null ? new ArrayList<>() : list;
            }
        } catch (Exception e) {
            log.warn("[IronWall] feedback store read failed: {}", e.getMessage());
        }
        return new ArrayList<>();
    }

    private void save(List<FeedbackRecord> records) {
        try {
            if (!Files.exists(storePath.getParent())) {
                Files.createDirectories(storePath.getParent());
            }
            Files.write(storePath, objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(records));
        } catch (Exception e) {
            log.error("[IronWall] feedback store write failed: {}", e.getMessage());
        }
    }

    private String safe(String value, int max) {
        if (value == null) {
            return "";
        }
        String v = value.trim().replaceAll("[\\x00-\\x1f\\x7f]", "");
        return v.length() > max ? v.substring(0, max) : v;
    }
}
