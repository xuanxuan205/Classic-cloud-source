package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.38.0: 告警联动通知服务（Webhook / 邮件 / 面板快照）。
 *
 * 封禁、网段封禁、挑战滥用、跨IP聚合等事件统一经此推送；5 分钟同源节流防风暴；
 * 内存环形缓冲最近 200 条供铁壁控制台展示；Webhook 3 秒连接超时异步发送；
 * 邮件仅在配置了 spring.mail 与 app.admin.email 时启用。所有通道异常静默降级，
 * 绝不影响拦截主链。
 */
@Slf4j
@Service
public class AlertNotifierService {

    private static final int MAX_RECENT = 200;
    private static final long THROTTLE_MS = 5 * 60_000L;

    @Value("${app.security.alerts.enabled:true}")
    private boolean enabled;

    @Value("${app.security.alerts.webhook-url:}")
    private String webhookUrl;

    @Value("${app.security.alerts.email-enabled:true}")
    private boolean emailEnabled;

    @Value("${app.admin.email:}")
    private String adminEmail;

    private final JavaMailSender mailSender;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final Map<String, Long> lastNotified = new ConcurrentHashMap<>();
    private final ArrayDeque<AlertRecord> recent = new ArrayDeque<>();
    private long totalCount;

    public AlertNotifierService(@Autowired(required = false) JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public static final class AlertRecord {
        public final long time;
        public final String type;
        public final String ip;
        public final String detail;
        AlertRecord(long time, String type, String ip, String detail) {
            this.time = time;
            this.type = type;
            this.ip = ip;
            this.detail = detail;
        }
    }

    /** 通知入口：节流 -> 入环形缓冲 -> Webhook/邮件异步推送。任何异常不影响调用方。 */
    public void notify(String type, String ip, String detail) {
        if (!enabled) {
            return;
        }
        try {
            String src = (ip == null ? "system" : ip) + "|" + (type == null ? "unknown" : type);
            long now = System.currentTimeMillis();
            Long last = lastNotified.get(src);
            if (last != null && now - last < THROTTLE_MS) {
                return;
            }
            lastNotified.put(src, now);
            String safeDetail = detail == null ? "" : (detail.length() > 300 ? detail.substring(0, 300) : detail);
            synchronized (recent) {
                if (recent.size() >= MAX_RECENT) {
                    recent.removeFirst();
                }
                recent.addLast(new AlertRecord(now, type, ip, safeDetail));
                totalCount++;
            }
            pushWebhookAsync(type, ip, safeDetail);
            sendEmailAsync(type, ip, safeDetail);
        } catch (Exception e) {
            log.warn("[IronWall] alert notify failed: {}", e.getMessage());
        }
    }

    public List<Map<String, Object>> recent(int limit) {
        int n = Math.max(0, Math.min(limit, MAX_RECENT));
        List<Map<String, Object>> list = new ArrayList<>();
        synchronized (recent) {
            for (AlertRecord r : recent) {
                if (list.size() >= n) {
                    break;
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("time", r.time);
                m.put("type", r.type);
                m.put("ip", r.ip);
                m.put("detail", r.detail);
                list.add(m);
            }
        }
        return list;
    }

    public Map<String, Object> snapshot() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", enabled);
        m.put("webhook_configured", webhookUrl != null && !webhookUrl.isBlank());
        m.put("email_configured", mailSender != null && adminEmail != null && !adminEmail.isBlank());
        m.put("total", totalCount);
        m.put("recent", recent(20));
        return m;
    }

    private void pushWebhookAsync(String type, String ip, String detail) {
        if (webhookUrl == null || webhookUrl.isBlank()) {
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("engine", AttackGuardService.ENGINE_FULL_NAME);
        body.put("type", type == null ? "unknown" : type);
        body.put("ip", ip == null ? "" : ip);
        body.put("detail", detail);
        body.put("time", System.currentTimeMillis());
        CompletableFuture.runAsync(() -> {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(webhookUrl.trim()))
                        .timeout(Duration.ofSeconds(5))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                        .build();
                httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            } catch (Exception e) {
                log.warn("[IronWall] alert webhook push failed: {}", e.getMessage());
            }
        });
    }

    private void sendEmailAsync(String type, String ip, String detail) {
        if (!emailEnabled || mailSender == null || adminEmail == null || adminEmail.isBlank()) {
            return;
        }
        CompletableFuture.runAsync(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(adminEmail.trim());
                message.setSubject("[铁壁告警] " + (type == null ? "unknown" : type));
                message.setText("来源IP: " + (ip == null ? "-" : ip) + "\n详情: " + detail);
                mailSender.send(message);
            } catch (Exception e) {
                log.warn("[IronWall] alert email failed: {}", e.getMessage());
            }
        });
    }
}
