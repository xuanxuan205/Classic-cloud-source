package com.jdy.cloud.service;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.repository.SystemConfigRepository;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Service
public class VerificationCodeService {

    private final JavaMailSender defaultMailSender;
    private final SystemConfigRepository systemConfigRepository;
    private final Map<String, CodeEntry> codeStore = new ConcurrentHashMap<>();

    // IronWall IW-08: IP-based send-code rate limit (per hour)
    private final Map<String, IpSendRecord> ipSendLog = new ConcurrentHashMap<>();
    private static final int MAX_SENDS_PER_IP_PER_HOUR = 5;

    // IronWall v1.40.0: 每邮箱每小时发送上限（防单邮箱被恶意轰炸，与 IP 限频正交）
    private final Map<String, EmailHourWindow> emailHourLog = new ConcurrentHashMap<>();
    private static final int MAX_SENDS_PER_EMAIL_PER_HOUR = 5;

    // IronWall IW-03: Max verification attempts per code
    private static final int MAX_VERIFY_ATTEMPTS = 5;

    // IronWall v1.2: Tombstone - invalidated codes stay recorded so
    // subsequent attempts get "已失效" instead of falling back to "验证码错误"
    private final Map<String, Long> invalidatedCodes = new ConcurrentHashMap<>();
    private static final long TOMBSTONE_TTL_MS = 10 * 60 * 1000;

    @Value("${app.security.code-send-interval:60}")
    private int sendIntervalSeconds;

    @Value("${spring.mail.username:}")
    private String defaultMailUsername;

    public VerificationCodeService(JavaMailSender defaultMailSender,
                                    SystemConfigRepository systemConfigRepository) {
        this.defaultMailSender = defaultMailSender;
        this.systemConfigRepository = systemConfigRepository;
    }

    private static class MailSenderConfig {
        JavaMailSender sender;
        String fromAddress;
    }

    private MailSenderConfig getMailSender() {
        String dbHost = getConfig("smtp_host");
        String dbPort = getConfig("smtp_port");
        String dbUsername = getConfig("smtp_username");
        String dbPassword = getConfig("smtp_password");

        if (dbHost != null && !dbHost.isBlank()
                && dbUsername != null && !dbUsername.isBlank()
                && dbPassword != null && !dbPassword.isBlank()) {
            log.info("Using SMTP config from database: host={}, port={}, user={}", dbHost, dbPort, dbUsername);
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setHost(dbHost);
            sender.setPort(Integer.parseInt(dbPort != null && !dbPort.isBlank() ? dbPort : "587"));
            sender.setUsername(dbUsername);
            sender.setPassword(dbPassword);
            Properties props = sender.getJavaMailProperties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
            props.put("mail.smtp.from", dbUsername);
            MailSenderConfig cfg = new MailSenderConfig();
            cfg.sender = sender;
            cfg.fromAddress = dbUsername;
            return cfg;
        }

        log.info("Using default SMTP config (spring.mail.username={})", defaultMailUsername);
        MailSenderConfig cfg = new MailSenderConfig();
        cfg.sender = defaultMailSender;
        cfg.fromAddress = defaultMailUsername;
        return cfg;
    }

    private String getConfig(String key) {
        try {
            return systemConfigRepository.findByConfigKey(key)
                    .map(c -> c.getConfigValue())
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    public void sendCode(String email, String clientIp) {
        // IW-08: Check IP-based rate limit
        checkIpSendLimit(clientIp);
        // IronWall v1.40.0: Check email-based rate limit
        checkEmailHourLimit(email);

        CodeEntry existing = codeStore.get(email);
        if (existing != null && existing.createdAt.plusSeconds(sendIntervalSeconds).isAfter(LocalDateTime.now())) {
            throw new BusinessException(ErrorCode.CODE_TOO_FREQUENT);
        }

        String code = String.format("%06d", new Random().nextInt(999999));
        codeStore.put(email, new CodeEntry(code, LocalDateTime.now()));
        invalidatedCodes.remove(email);
        // IW-08: Record IP send
        ipSendLog.computeIfAbsent(clientIp, k -> new IpSendRecord()).record();
        emailHourLog.computeIfAbsent(email, k -> new EmailHourWindow()).record();

        log.info("Sending verification code to: {}", email);
        try {
            MailSenderConfig cfg = getMailSender();
            MimeMessage mimeMessage = cfg.sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(cfg.fromAddress, "经典云网盘官方");
            helper.setTo(email);
            helper.setSubject("【经典云网盘】注册验证码");
            helper.setText(buildTextEmail(code), buildHtmlEmail(code));
            cfg.sender.send(mimeMessage);
            log.info("Verification code sent successfully to: {}", email);
        } catch (BusinessException e) {
            codeStore.remove(email);
            throw e;
        } catch (Exception e) {
            // IronWall v1.28.9: 邮件投递失败不抛 500，避免攻击者用“发送失败”信号枚举注册邮箱。
            // 已注册/未注册/投递失败三种情况对外响应完全一致，仅记录服务端日志供运维排查。
            codeStore.remove(email);
            log.error("Failed to send email to {}: {}", email, e.getMessage(), e);
        }
    }

    /** IronWall v1.40.0: 单邮箱每小时最多 5 封验证码。 */
    private void checkEmailHourLimit(String email) {
        long now = System.currentTimeMillis();
        EmailHourWindow window = emailHourLog.get(email);
        if (window == null) {
            return;
        }
        synchronized (window) {
            if (now - window.windowStart >= 3600_000L) {
                window.windowStart = now;
                window.count = 0;
            }
            if (window.count >= MAX_SENDS_PER_EMAIL_PER_HOUR) {
                throw new BusinessException(ErrorCode.CODE_TOO_FREQUENT);
            }
        }
    }

    private static class EmailHourWindow {
        long windowStart = System.currentTimeMillis();
        int count = 0;

        void record() {
            count++;
        }
    }

    private String buildTextEmail(String code) {
        return "尊敬的先生/女士，\n"
                + "您正在注册经典云网盘账号，验证码为：\n"
                + code + "\n\n"
                + "温馨提示：\n"
                + "• 验证码有效期为10分钟\n"
                + "• 请勿将验证码告知他人\n"
                + "• 如非本人操作，请忽略此邮件\n\n"
                + "如果这不是您的操作，请忽略此邮件。\n"
                + "此邮件由系统自动发送，请勿回复。\n\n"
                + "© 2026 经典云网盘 Classic Cloud. All rights reserved.";
    }

    private String buildHtmlEmail(String code) {
        return """
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#eef2f9;font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',Arial,sans-serif;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#eef2f9;padding:28px 12px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%%;border-radius:16px;overflow:hidden;box-shadow:0 8px 24px rgba(37,99,235,0.12);">
  <tr><td style="background:linear-gradient(120deg,#6366f1,#2563eb);padding:28px 32px;">
    <table width="100%%" cellpadding="0" cellspacing="0"><tr>
      <td style="width:48px;"><div style="width:44px;height:44px;background:rgba(255,255,255,0.18);border:1px solid rgba(255,255,255,0.4);border-radius:12px;text-align:center;line-height:44px;font-size:22px;color:#ffffff;font-weight:700;">云</div></td>
      <td style="padding-left:14px;"><p style="margin:0;color:#ffffff;font-size:18px;font-weight:700;letter-spacing:1px;">经典云网盘官方</p><p style="margin:6px 0 0;color:#dbe4ff;font-size:13px;">注册验证码</p></td>
      <td align="right" valign="top"><span style="display:inline-block;background:rgba(255,255,255,0.16);border:1px solid rgba(255,255,255,0.35);color:#ffffff;font-size:12px;padding:5px 14px;border-radius:999px;">安全验证</span></td>
    </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;padding:28px 32px;">
    <p style="margin:0;color:#1f2937;font-size:15px;font-weight:600;">尊敬的先生/女士，</p>
    <p style="margin:10px 0 0;color:#4b5563;font-size:14px;line-height:1.7;">您正在注册经典云网盘账号，验证码为：</p>
    <table width="100%%" cellpadding="0" cellspacing="0" style="margin-top:18px;">
      <tr><td style="background:#f5f7ff;border:1px solid #e3e8ff;border-radius:12px;padding:20px;text-align:center;">
        <span style="font-family:'Courier New',monospace;font-size:34px;font-weight:700;color:#4f46e5;letter-spacing:10px;">%s</span>
      </td></tr>
    </table>
    <p style="margin:20px 0 10px;color:#1f2937;font-size:14px;font-weight:600;">温馨提示：</p>
    <table width="100%%" cellpadding="0" cellspacing="0">
      <tr><td style="padding:5px 0;color:#6b7280;font-size:13px;">• 验证码有效期为10分钟</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280;font-size:13px;">• 请勿将验证码告知他人</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280;font-size:13px;">• 如非本人操作，请忽略此邮件</td></tr>
    </table>
    <p style="margin:16px 0 0;color:#9ca3af;font-size:12px;line-height:1.7;">如果这不是您的操作，请忽略此邮件。<br/>此邮件由系统自动发送，请勿回复。</p>
  </td></tr>
  <tr><td style="background:#f8fafc;border-top:1px solid #eef2f7;padding:16px 32px;text-align:center;">
    <p style="margin:0;color:#9aa5b1;font-size:11px;">© 2026 经典云网盘 Classic Cloud. All rights reserved.</p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>""".formatted(code);
    }

    // IronWall v1.2: 验证码防护 - 失效后彻底拒绝，绝不回落
    public void verify(String email, String code) {
        // 检查tombstone：已失效验证码直接拒绝
        Long tombstoneAt = invalidatedCodes.get(email);
        if (tombstoneAt != null) {
            if (System.currentTimeMillis() - tombstoneAt < TOMBSTONE_TTL_MS) {
                throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "验证码已失效，请重新获取");
            } else {
                invalidatedCodes.remove(email);
            }
        }

        CodeEntry entry = codeStore.get(email);
        if (entry == null) {
            throw new BusinessException(ErrorCode.CODE_ERROR);
        }
        // 优先检查过期（不再回退为CODE_ERROR）
        if (entry.createdAt.plusMinutes(10).isBefore(LocalDateTime.now())) {
            codeStore.remove(email);
            invalidatedCodes.put(email, System.currentTimeMillis());
            throw new BusinessException(ErrorCode.CODE_EXPIRED);
        }
        // 检查尝试次数
        if (entry.attempts.incrementAndGet() > MAX_VERIFY_ATTEMPTS) {
            codeStore.remove(email);
            invalidatedCodes.put(email, System.currentTimeMillis());
            throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "验证码尝试次数过多，已失效，请重新获取");
        }
        // 检查验证码是否正确
        if (!entry.code.equals(code)) {
            throw new BusinessException(ErrorCode.CODE_ERROR);
        }
        // 验证通过，立即移除（防止重放）
        codeStore.remove(email);
    }

    // IW-03: Code entry with attempt tracking
    private static class CodeEntry {
        final String code;
        final LocalDateTime createdAt;
        final AtomicInteger attempts = new AtomicInteger(0);

        CodeEntry(String code, LocalDateTime createdAt) {
            this.code = code;
            this.createdAt = createdAt;
        }
    }

    // IW-08: IP send tracking
    private static class IpSendRecord {
        long windowStart = System.currentTimeMillis();
        int count = 0;

        synchronized void record() {
            long now = System.currentTimeMillis();
            if (now - windowStart > 3600_000) {
                windowStart = now;
                count = 0;
            }
            count++;
        }

        synchronized boolean isOverLimit(int max) {
            long now = System.currentTimeMillis();
            if (now - windowStart > 3600_000) return false;
            return count >= max;
        }
    }

    private void checkIpSendLimit(String ip) {
        IpSendRecord rec = ipSendLog.get(ip);
        if (rec != null && rec.isOverLimit(MAX_SENDS_PER_IP_PER_HOUR)) {
            throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(),
                "该IP发送验证码过于频繁，请1小时后再试");
        }
    }
}
