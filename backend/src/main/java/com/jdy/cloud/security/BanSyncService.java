package com.jdy.cloud.security;

import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.repository.AttackLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * IronWall v1.38.0: 分布式封禁联动——attack_logs 事件总线对账。
 *
 * 每 30 秒拉取最近 50 条「封禁同步事件」，跳过自实例写入的事件，
 * 把其他实例的 BLOCKED/UNBLOCKED 合并进本地封禁状态（幂等，取较晚到期）。
 * 单机部署时为零开销自环；多实例共享同一 MySQL 即自动收敛封禁名单。
 * 任何异常 fail-open，绝不影响攻击拦截主链。
 */
@Slf4j
@Service
public class BanSyncService {

    @Value("${app.security.attack-guard.ban-sync.enabled:true}")
    private boolean enabled;

    private final AttackLogRepository attackLogRepository;
    private final AttackGuardService attackGuardService;

    public BanSyncService(AttackLogRepository attackLogRepository, AttackGuardService attackGuardService) {
        this.attackLogRepository = attackLogRepository;
        this.attackGuardService = attackGuardService;
    }

    @Scheduled(fixedDelayString = "${app.security.attack-guard.ban-sync.interval-ms:30000}",
            initialDelay = 10_000L)
    public void poll() {
        if (!enabled) {
            return;
        }
        try {
            List<AttackLog> events = attackLogRepository.findTop50ByAttackTypeOrderByIdDesc(AttackGuardService.TYPE_SYNC);
            if (events == null || events.isEmpty()) {
                return;
            }
            // IronWall v1.38.1: 倒序回放（旧->新），确保更新的 UNBLOCKED 覆盖更早的 BLOCKED，避免重启后被历史封禁事件复封。
            for (int i = events.size() - 1; i >= 0; i--) {
                AttackLog event = events.get(i);
                if (attackGuardService.isSelfInstance(event.getUserAgent())) {
                    continue;
                }
                String ip = event.getIp();
                if (ip == null || ip.isBlank()) {
                    continue;
                }
                if ("UNBLOCKED".equals(event.getAction())) {
                    attackGuardService.applyRemoteUnblock(ip);
                } else if ("BLOCKED".equals(event.getAction())) {
                    attackGuardService.applyRemoteBan(ip, parseExpiry(event.getPayload()));
                }
            }
        } catch (Exception e) {
            log.warn("[IronWall] ban sync poll failed: {}", e.getMessage());
        }
    }

    private long parseExpiry(String payload) {
        if (payload == null || payload.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(payload.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
