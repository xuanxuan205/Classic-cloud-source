package com.jdy.cloud.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * IronWall v1.27.2: 发件人必须与 SMTP 授权账号一致（QQ 邮箱 501 校验），
 * 显示名默认「经典云网盘官方」；纯文本与 HTML 两种发送方式统一支持个性化发件人。
 */
@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;

    @Value("${spring.mail.from:}")
    private String defaultFrom;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${spring.mail.personal:经典云网盘官方}")
    private String personalName;

    private String fromAddress() {
        if (defaultFrom != null && !defaultFrom.isBlank()) {
            return defaultFrom.trim();
        }
        if (mailUsername != null && !mailUsername.isBlank()) {
            return mailUsername.trim();
        }
        return null;
    }

    private void applyFrom(MimeMessageHelper helper) throws MessagingException {
        String from = fromAddress();
        if (from == null) {
            return;
        }
        try {
            if (personalName != null && !personalName.isBlank()) {
                helper.setFrom(from, personalName.trim());
            } else {
                helper.setFrom(from);
            }
        } catch (java.io.UnsupportedEncodingException e) {
            helper.setFrom(from);
        }
    }

    public void send(String to, String subject, String text) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            applyFrom(helper);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, false);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("email send failed", e);
        }
    }

    public void sendHtml(String to, String subject, String html, String textFallback) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            applyFrom(helper);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(textFallback, html);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("HTML email send failed", e);
        }
    }
}
