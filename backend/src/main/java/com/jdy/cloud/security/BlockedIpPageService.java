package com.jdy.cloud.security;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.service.ThreatIntelService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * IronWall v1.17.4: 封禁专属警示页渲染（合法威慑，非攻击）。
 * 被自动封禁的 IP 只能访问该页面：展示安全引擎触发状态、威慑引擎内容记录
 * （脱敏攻击流水）与"不要越界，否则报警处理"警示（不暴露画像/记分/解封时间戳）。
 * 所有攻击载荷输出前 HTML 转义，杜绝反射型 XSS。
 */
@Slf4j
@Service
public class BlockedIpPageService {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final AttackGuardService attackGuardService;
    private final AttackLogRepository attackLogRepository;
    private final TrapService trapService;
    private final DecoyPortTrapService decoyPortTrapService;
    private final ThreatIntelService threatIntelService;

    // IronWall v1.25.0: 陷阱区人机验证逃生口——入陷阱满该分钟后才可自助验证退出
    @Value("${app.security.defense-engine.trap.escape-minutes:10}")
    private long trapEscapeMinutes;

    public BlockedIpPageService(AttackGuardService attackGuardService, AttackLogRepository attackLogRepository,
                               TrapService trapService, DecoyPortTrapService decoyPortTrapService,
                               ThreatIntelService threatIntelService) {
        this.attackGuardService = attackGuardService;
        this.attackLogRepository = attackLogRepository;
        this.trapService = trapService;
        this.decoyPortTrapService = decoyPortTrapService;
        this.threatIntelService = threatIntelService;
    }

    public String render(String ip) {
        return render(ip, null);
    }

    /** IronWall v1.24.0: reason 用于展示人机验证失败原因（answer_wrong/expired/locked）。 */
    public String render(String ip, String reason) {
        boolean ipBlocked = attackGuardService.isBlocked(ip);
        boolean segmentBlocked = attackGuardService.isBlockedSegment(ip);

        // IronWall v1.19: 不再下发画像/记分/解封时间戳等内部字段
        String segmentName = null;
        if (segmentBlocked) {
            for (AttackGuardService.SegmentInfo s : attackGuardService.getBlockedSegments()) {
                if (ip != null && s.segment != null && s.segment.contains("/")) {
                    // 前缀匹配 /24：203.0.113.x 命中 203.0.113.0/24
                    String prefix = s.segment.substring(0, s.segment.indexOf('/'));
                    int lastDot = prefix.lastIndexOf('.');
                    if (lastDot > 0 && ip.startsWith(prefix.substring(0, lastDot) + ".")) {
                        segmentName = s.segment;
                        break;
                    }
                }
            }
            if (segmentName == null) {
                segmentName = segmentOf(ip);
            }
        }

        List<AttackLog> recent = new ArrayList<>();
        try {
            List<AttackLog> logs = attackLogRepository.findTop100ByIpOrderByCreatedAtDesc(ip);
            if (logs != null) recent.addAll(logs.subList(0, Math.min(10, logs.size())));
        } catch (Exception e) {
            log.warn("[IronWall] blocked page evidence load failed: {}", e.getMessage());
        }

        // IronWall v1.21: 黑洞陷阱状态（只进不出）
        TrapService.TrapEntry trap = trapService.entryOf(ip);
        boolean trapped = trap != null;
        // IronWall v1.26.1: 封禁页只呈现通用状态，不泄露网段/陷阱/层级等内部防御机制
        String statusText = (ipBlocked || segmentBlocked) ? "已封禁" : trapped ? "访问受限" : "监控中";

        // IronWall v1.25.0: IP 封禁可自助验证；陷阱区满逃生等待期后提供人机验证逃生口；网段封禁不提供
        boolean trapEscapeReady = false;
        if (trapped) {
            long escapeMs = trapEscapeMinutes > 0 ? trapEscapeMinutes * 60_000L : 0L;
            trapEscapeReady = System.currentTimeMillis() - trap.enteredAt >= escapeMs;
        }
        boolean challengeEligible = (ipBlocked || (trapped && trapEscapeReady)) && !segmentBlocked
                && attackGuardService.isChallengeEnabled();
        String challengeToken = null;
        String challengeQuestion = null;
        if (challengeEligible) {
            String issued = attackGuardService.issueChallenge(ip);
            if (issued != null && issued.contains("|")) {
                challengeToken = issued.substring(0, issued.indexOf('|'));
                challengeQuestion = issued.substring(issued.indexOf('|') + 1);
            }
        }
        String challengeMessage = challengeMessage(reason);
        long remainSeconds = remainingBlockSeconds(ip, ipBlocked, segmentBlocked);
        String countdownText = countdownText(ipBlocked, segmentBlocked, trapped, trapEscapeReady, remainSeconds);
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">")
          .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
          .append("<meta name=\"robots\" content=\"noindex,nofollow\">")
          .append("<title>访问受限 · 安全封禁警示页</title>")
          .append("<style>")
          .append("*{margin:0;padding:0;box-sizing:border-box}")
          .append("body{background:#0a0d12;color:#e2e8f0;font-family:'Segoe UI','Microsoft YaHei',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}")
          .append(".card{width:100%;max-width:720px;background:#11151d;border:1px solid #272e3b;border-radius:20px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.55)}")
          .append(".head{background:linear-gradient(135deg,#7f1d1d,#450a0a);padding:28px 32px;display:flex;align-items:center;gap:16px}")
          .append(".shield{width:52px;height:52px;border-radius:14px;background:rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;font-size:30px}")
          .append(".head h1{font-size:20px;font-weight:700;color:#fff}")
          .append(".head p{font-size:13px;color:#fca5a5;margin-top:4px}")
          .append(".body{padding:28px 32px}")
          .append(".banner{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);border-radius:12px;padding:14px 18px;font-size:14px;color:#fecaca;line-height:1.7;margin-bottom:22px}")
          .append(".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:22px}")
          .append(".box{background:#0d1117;border:1px solid #1f2733;border-radius:12px;padding:14px 16px}")
          .append(".box .k{font-size:11px;color:#64748b;margin-bottom:6px}")
          .append(".box .v{font-size:17px;font-weight:700;color:#fff;word-break:break-all}")
          .append(".box .v.red{color:#f87171}.box .v.green{color:#34d399}")
          .append(".foot{padding:16px 32px;border-top:1px solid #1f2733;font-size:12px;color:#475569;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}")
          .append("@media(max-width:560px){.head{padding:20px}.body{padding:18px}.foot{padding:14px 18px}}")
          .append("</style></head><body><div class=\"card\">")
          .append("<div class=\"head\"><div class=\"shield\">\uD83D\uDEE1\uFE0F</div><div><h1>访问受限</h1>")
          .append("<p>安全访问控制已触发</p></div></div>")
          .append("<div class=\"body\">")
          .append("<div class=\"banner\">\u26A0\uFE0F <b>访问已被拦截：</b>该来源的访问行为已触发安全策略，当前仅可访问本警示页。")
          .append("请立即停止异常行为；相关访问行为已被记录，继续尝试将升级处置。</div>")
          .append("<div class=\"grid\">")
          .append(box("来源 IP", esc(ip), "v"))
          .append(box("来源位置", esc(geoDisplayOf(ip)), ""))
            .append(box("处置状态", esc(statusText), "v red"))
            .append(box("处置说明", "由系统自动判定，停止异常行为后自动解除", "v green"))
            .append(box("处置原因", esc(reasonDisplay(recent)), ""))
            .append("<div class=\"box\"><div class=\"k\">预计解除倒计时</div><div class=\"v green\" id=\"cd\">").append(esc(countdownText)).append("</div></div>")
            .append("</div>");
        if (challengeEligible && challengeToken != null) {
            sb.append("<div style=\"margin:22px 0;padding:20px 22px;border:1px solid #3b82f6;border-radius:14px;background:rgba(59,130,246,.08)\">")
              .append("<h2 style=\"font-size:16px;color:#93c5fd;margin-bottom:8px\">\uD83D\uDD11 人机验证 · 误封自助解除</h2>")
              .append("<p style=\"font-size:13px;color:#cbd5e1;line-height:1.7;margin-bottom:14px\">如果您是正常用户，请完成下方验证，通过后恢复访问；异常访问者请停止尝试。</p>")
              .append(challengeMessage != null ? "<p style=\"font-size:13px;color:#fca5a5;margin-bottom:12px\">" + challengeMessage + "</p>" : "")
              .append("<form method=\"post\" action=\"").append(BlockedIpPageFilter.VERIFY_PATH).append("\" style=\"display:flex;flex-wrap:wrap;gap:10px;align-items:center\">")
              .append("<input type=\"hidden\" name=\"token\" value=\"").append(esc(challengeToken)).append("\"/>")
              .append("<span style=\"font-size:15px;color:#e2e8f0;font-weight:700;letter-spacing:1px\">").append(esc(challengeQuestion)).append("</span>")
              .append("<input type=\"text\" name=\"answer\" inputmode=\"numeric\" autocomplete=\"off\" maxlength=\"4\" required placeholder=\"输入计算结果\" style=\"flex:1;min-width:160px;padding:10px 14px;border-radius:10px;border:1px solid #334155;background:#0f141c;color:#e2e8f0;font-size:15px\"/>")
              .append("<button type=\"submit\" style=\"padding:10px 20px;border:none;border-radius:10px;background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff;font-size:14px;font-weight:700;cursor:pointer\">验证并恢复访问</button>")
              .append("</form></div>");
        }
        sb.append("<div style=\"margin:22px 0;padding:20px 22px;border:1px solid #334155;border-radius:14px;background:rgba(15,23,42,.6)\">")
          .append("<h2 style=\"font-size:15px;color:#cbd5e1;margin-bottom:6px\">\uD83D\uDCAC 人工申诉通道 · 共享 IP / NAT 误伤</h2>")
          .append("<p style=\"font-size:12px;color:#64748b;line-height:1.7;margin-bottom:12px\">如您确认是正常用户，但受运营商共享 IP 影响被误封，可提交申诉；人工复核后会尽快处理。异常访问者无需提交。</p>")
          .append("<form id=\"appealForm\" style=\"display:grid;gap:10px\">")
          .append("<input name=\"contact\" maxlength=\"64\" placeholder=\"联系方式（邮箱/电话，可选）\" style=\"padding:10px 12px;border-radius:10px;border:1px solid #334155;background:#0f141c;color:#e2e8f0;font-size:13px\"/>")
          .append("<textarea name=\"reason\" maxlength=\"240\" rows=\"3\" placeholder=\"请简要说明访问目的或误伤情况\" style=\"padding:10px 12px;border-radius:10px;border:1px solid #334155;background:#0f141c;color:#e2e8f0;font-size:13px;resize:vertical\"></textarea>")
          .append("<div style=\"display:flex;align-items:center;gap:12px\"><button type=\"submit\" style=\"padding:10px 18px;border:none;border-radius:10px;background:#334155;color:#e2e8f0;font-size:13px;font-weight:700;cursor:pointer\">提交申诉</button><span id=\"appealMsg\" style=\"font-size:12px;color:#34d399\"></span></div>")
          .append("</form></div>");
        sb.append("<p style=\"font-size:12px;color:#64748b;line-height:1.7\">访问行为及相关网络信息已记录，必要时将依法提供给网络安全机构。</p>")
          .append("</div>")
          .append("<div class=\"foot\"><span>安全访问控制</span><span>自动生成</span></div>")
          .append("<script type=\"text/javascript\">")
          .append("var af=document.getElementById('appealForm');af.addEventListener('submit',function(e){e.preventDefault();var fd=new FormData(af);var body='contact='+encodeURIComponent(fd.get('contact')||'')+'&reason='+encodeURIComponent(fd.get('reason')||'');fetch('").append(BlockedIpPageFilter.APPEAL_PATH).append("',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).then(function(r){return r.json()}).then(function(d){var m=document.getElementById('appealMsg');m.textContent=d&&d.message?d.message:'已提交'}).catch(function(){var m=document.getElementById('appealMsg');m.textContent='提交失败，请稍后重试'});});")
          .append("</script>")
          .append("</div></body></html>");
        return sb.toString();
    }

    /**
     * IronWall v1.47.9: 稳定处置原因码——只暴露处置类别，
     * 不泄露具体攻击类型/记分/阈值/解封时间戳等内部机制。
     */
    private String reasonDisplay(List<AttackLog> recent) {
        for (AttackLog log : recent) {
            if (log == null || log.getAttackType() == null) {
                continue;
            }
            String type = log.getAttackType();
            if (type.contains("注入") || type.contains("XSS") || type.contains("穿越")
                    || type.contains("命令") || type.contains("SSRF")) {
                return "IW-INJECTION（载荷注入类）";
            }
            if (type.contains("扫描") || type.contains("爬虫")) {
                return "IW-CRAWLER（扫描/爬虫类）";
            }
        }
        return "IW-POLICY（访问策略类）";
    }

    private long remainingBlockSeconds(String ip, boolean ipBlocked, boolean segmentBlocked) {
        long now = System.currentTimeMillis();
        long maxMs = 0L;
        if (ipBlocked) {
            for (AttackGuardService.BlockInfo b : attackGuardService.getBlockedIps()) {
                if (ip != null && ip.equals(b.ip)) {
                    maxMs = Math.max(maxMs, Math.max(0L, b.blockedUntil - now));
                }
            }
        }
        if (segmentBlocked) {
            for (AttackGuardService.SegmentInfo seg : attackGuardService.getBlockedSegments()) {
                if (segmentMatches(ip, seg.segment)) {
                    maxMs = Math.max(maxMs, Math.max(0L, seg.blockedUntil - now));
                }
            }
        }
        return maxMs / 1000L;
    }

    private boolean segmentMatches(String ip, String segment) {
        if (ip == null || segment == null || !segment.contains("/")) return false;
        String prefix = segment.substring(0, segment.indexOf('/'));
        int lastDot = prefix.lastIndexOf('.');
        return lastDot > 0 && ip.startsWith(prefix.substring(0, lastDot) + ".");
    }

    private String countdownText(boolean ipBlocked, boolean segmentBlocked, boolean trapped,
                                 boolean trapEscapeReady, long remainSeconds) {
        if (trapped && !trapEscapeReady) return "等待安全策略周期后验证";
        if (!ipBlocked && trapped && trapEscapeReady) return "完成人机验证后解除";
        // IronWall v1.36.0: 不再下发精确解封时间戳，改为模糊档位——
        // 攻击者无法据倒计时反推封禁时长与计分阈值（泄露面收敛）。
        if (remainSeconds <= 0) return "自动解除中，请刷新页面";
        if (remainSeconds < 3600) return "1 小时内自动解除";
        if (remainSeconds < 86400) return "24 小时内自动解除";
        if (remainSeconds < 7 * 86400L) return "数日内自动解除";
        return "按安全策略周期自动解除";
    }

    /** IronWall v1.24.0: 人机验证失败原因文案（不泄露内部状态）。 */
    private String challengeMessage(String reason) {
        if (reason == null) return null;
        switch (reason) {
            case "answer_wrong": return "\u26A0\uFE0F 验证结果不正确，请重新输入（多次失败将升级处置）。";
            case "expired": return "\u23F0 验证已过期，请重新提交。";
            case "locked": return "\uD83D\uDD12 验证失败次数过多，已升级为服务器级封禁。请立即停止攻击行为。";
            default: return null;
        }
    }

    /** IronWall v1.25.0: 人机验证资格——IP 级站内封禁，或入陷阱满等待期的 IP；网段封禁永不提供。 */
    public boolean isChallengeEligible(String ip) {
        boolean ipBlocked = attackGuardService.isBlocked(ip);
        boolean segmentBlocked = attackGuardService.isBlockedSegment(ip);
        TrapService.TrapEntry trap = trapService.entryOf(ip);
        boolean trapped = trap != null;
        if (segmentBlocked || !attackGuardService.isChallengeEnabled()) return false;
        if (!ipBlocked && !trapped) return false;
        if (trapped) {
            long escapeMs = trapEscapeMinutes > 0 ? trapEscapeMinutes * 60_000L : 0L;
            if (System.currentTimeMillis() - trap.enteredAt < escapeMs) return false;
        }
        return true;
    }

    /** IronWall v1.25.0: 当前是否处于引擎锁定状态（IP 封禁 / 网段封禁 / 陷阱吞没）。 */
    public boolean isActiveLockdown(String ip) {
        return attackGuardService.isBlocked(ip) || attackGuardService.isBlockedSegment(ip)
                || trapService.isTrapped(ip);
    }

    /** IronWall v1.25.0: 人机验证通过后联动释放陷阱（再犯会立即重新入阱并升级）。 */
    public void releaseTrap(String ip) {
        trapService.release(ip);
    }

    // IronWall v1.19: 载荷脱敏——过滤可执行片段、截断 20 字符，隐藏完整参数值
    private String maskPayload(String payload) {
        if (payload == null) return "-";
        String cleaned = payload.replaceAll("(?is)<(script|iframe|svg|style|object|embed)\\b[^>]*>.*?</\\1>", "")
                .replaceAll("<[^>]{0,120}>", "").replaceAll("[\\x00-\\x1f\\x7f]", "");
        String truncated = cleaned.length() > 20 ? cleaned.substring(0, 20) + "..." : cleaned;
        return truncated.isEmpty() ? "已脱敏" : truncated;
    }

    /** IronWall v1.28.5: 专属页展示来源位置（城市/ISP 级，不泄露经纬度与引擎内部机制）。 */
    private String geoDisplayOf(String ip) {
        try {
            Map<String, Object> geo = threatIntelService.lookupGeo(ip);
            if (geo != null && geo.get("display") != null) {
                return String.valueOf(geo.get("display"));
            }
        } catch (Exception ignored) {
            // 情报查询失败不阻断页面渲染
        }
        return "自动识别中，网络信息已记录";
    }

    private String box(String k, String v, String cls) {
        return "<div class=\"box\"><div class=\"k\">" + esc(k) + "</div><div class=\"" + cls + "\">" + v + "</div></div>";
    }

    private String segmentOf(String ip) {
        if (ip == null) return null;
        int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) + ".0/24" : null;
    }

    private String esc(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
