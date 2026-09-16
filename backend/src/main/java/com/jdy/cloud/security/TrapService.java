package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.28.8 七层黑洞陷阱服务（合法威慑，非攻击）。
 *
 * 每一层防护都埋设一个「只进不出」的陷阱：攻击者一旦触网（重复攻击载荷 / 蜜罐触碰 /
 * 挑战伪造 / 持续限流对抗 / 令牌版本攻击），该 IP 立即被投入陷阱状态：
 * 陷阱期内除封禁警示页外的一切请求都被吞没（429 + 延时 + 无任何业务数据）；
 * 同时按高权重记分直接升级 IP 封禁；
 * 即使管理员解封 IP，陷阱仍在有效期内持续生效——只有入口，没有出口。
 *
 * 白名单与登录态永不入陷阱（保护公网 NAT 出口下正常用户）；任何异常 fail-open。
 */
@Slf4j
@Service
public class TrapService {

    public static final String TRAP_HEADER = "X-IronWall-Trapped";

    @Value("${app.security.defense-engine.trap.enabled:true}")
    private boolean enabled;

    @Value("${app.security.defense-engine.trap.minutes:30}")
    private long trapMinutes;

    private final AttackGuardService attackGuardService;
    private final RequestTrustResolver trustResolver;
    private final Map<String, TrapEntry> traps = new ConcurrentHashMap<>();

    public TrapService(AttackGuardService attackGuardService, RequestTrustResolver trustResolver) {
        this.attackGuardService = attackGuardService;
        this.trustResolver = trustResolver;
    }

    public static final class TrapEntry {
        public final int layer;
        public final String reason;
        public final long enteredAt;
        public final long expiresAt;
        TrapEntry(int layer, String reason, long enteredAt, long expiresAt) {
            this.layer = layer;
            this.reason = reason;
            this.enteredAt = enteredAt;
            this.expiresAt = expiresAt;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 将 IP 投入陷阱（幂等：重复进入只更新层级，不重复封禁）。
     * @param trustedSession 登录态/白名单永不入陷阱，避免误伤 NAT 出口
     */
    public void trap(String ip, int layer, String reason, String path, String userAgent, String method, boolean trustedSession) {
        if (!enabled || ip == null || trustedSession) {
            return;
        }
        // IronWall v1.21.1: 管理员/运维白名单 IP 永不入陷阱，防止把自己锁在门外
        if (trustResolver.isWhitelisted(ip)) {
            log.warn("[IronWall] trap skipped for whitelisted ip={}", ip);
            return;
        }
        long now = System.currentTimeMillis();
        long minutes = trapMinutes > 0 ? trapMinutes : 30;
        TrapEntry existing = traps.get(ip);
        if (existing != null && existing.expiresAt > now) {
            if (existing.layer < layer) {
                traps.put(ip, new TrapEntry(layer, reason, existing.enteredAt, existing.expiresAt));
            }
            return;
        }
        traps.put(ip, new TrapEntry(layer, reason, now, now + minutes * 60_000L));
        // 陷阱 = 高危 20 分直接升级封禁，让威慑链与陷阱同时生效（常量化）
        try {
            AttackGuardService.AttackRecord record = attackGuardService.recordWeighted(
                    ip, AttackGuardService.TYPE_TRAP, "七层黑洞陷阱·第" + layer + "层: " + reason,
                    path == null ? "trap" : path, userAgent, method, false, AttackGuardService.SCORE_SEVERE);
            log.warn("[IronWall] trap triggered: ip={} layer={} reason={} score={} action={}",
                    ip, layer, reason, record != null ? record.score : 0, record != null ? record.action : "UNKNOWN");
        } catch (Exception e) {
            log.error("[IronWall] trap score failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.28.1: 周期性清理已过期的陷阱条目，防止长时间运行后陷阱表无界增长。
     */
    @Scheduled(fixedDelay = 600_000L, initialDelay = 600_000L)
    public void sweepExpiredTraps() {
        long now = System.currentTimeMillis();
        traps.entrySet().removeIf(e -> e.getValue().expiresAt <= now);
    }
    public boolean isTrapped(String ip) {
        if (!enabled || ip == null) return false;
        TrapEntry entry = traps.get(ip);
        if (entry == null) return false;
        if (entry.expiresAt > System.currentTimeMillis()) return true;
        traps.remove(ip);
        return false;
    }

    public TrapEntry entryOf(String ip) {
        if (ip == null) return null;
        TrapEntry entry = traps.get(ip);
        if (entry != null && entry.expiresAt <= System.currentTimeMillis()) {
            traps.remove(ip);
            return null;
        }
        return entry;
    }

    /** 管理员解封时联动释放陷阱。 */
    public void release(String ip) {
        if (ip != null) {
            traps.remove(ip);
            log.info("[IronWall] trap released: ip={}", ip);
        }
    }

    public long activeCount() {
        long now = System.currentTimeMillis();
        traps.entrySet().removeIf(e -> e.getValue().expiresAt <= now);
        return traps.size();
    }

    public List<Map<String, Object>> snapshot() {
        long now = System.currentTimeMillis();
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map.Entry<String, TrapEntry> e : traps.entrySet()) {
            TrapEntry entry = e.getValue();
            if (entry.expiresAt <= now) {
                traps.remove(e.getKey());
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", e.getKey());
            m.put("layer", entry.layer);
            m.put("reason", entry.reason);
            m.put("entered_at", entry.enteredAt);
            m.put("expires_at", entry.expiresAt);
            list.add(m);
        }
        return list;
    }
}
